#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "structs.h"

#define PROXY_PORT 2020
#define PROXY_CONN 20
#define PROXY_MAX_MSGLEN 10*1024
#define TITLE_DELIM " "

struct http_msg *child_msg;

int parse_title(char *msgbuff) {
    char *title_end = strrchr(msgbuff, '\n');
    if (title_end == NULL) {
        return -1; 
    }

    const int title_len = title_end - msgbuff;
    char title[title_len]; 
    strncpy(title, msgbuff, title_len);

    char *title_sub; 
    int index; 
    for (index = 0, title_sub = strtok(title, TITLE_DELIM); 
            title_sub != NULL; 
            title_sub = strtok(NULL, TITLE_DELIM), index++) {
        
        char *destarr = (char *) calloc(1, strlen(title_sub)+1); 
        if (destarr == NULL) {
            goto error_title_props;
        }

        if (index == 0) {
            child_msg->method = destarr;
            strcpy(child_msg->method, title_sub);
        }
        else if (index == 1) {
            child_msg->uri = destarr;
            strcpy(child_msg->uri, title_sub);
        }
        else if (index == 2) {
            child_msg->ver = destarr; 
            strcpy(child_msg->ver, title_sub);
        }
        else {
            goto error_title_props; 
        }
    }

    return 0;

error_title_props:
    for (int i = 0; i <= index; i++) {
        free(child_msg+i);
    }

    return -1;
}

void handle_request(int sockfd) {
    int ret;
    int id = getpid();
    char msgbuff[PROXY_MAX_MSGLEN]; 
    memset(msgbuff, 0, sizeof(msgbuff));
    
    ret = recv(sockfd, msgbuff, sizeof(msgbuff), 0);
    if (ret < 0) {
        fprintf(stderr, "[CHILD %d] Failed to receive data from client\n", id);
        goto end_sock; 
    }

    fprintf(stdout, "[CHILD %d] Received data from client: %s\n", id, msgbuff);

    // prepare structs 
    child_msg = (struct http_msg *) calloc(1, sizeof(struct http_msg));
    if (child_msg == NULL) {
        fprintf(stderr, "[CHILD %d] Failed to allocate memory for client structs\n", id);
        goto end_sock; 
    }

    // start parsing 
    ret = parse_title(msgbuff); 
    if (ret < 0) {
        fprintf(stderr, "[CHILD %d] Failed to parse the title of the request\n", id);
        goto end_structs; 
    }

end_structs: 
    free(child_msg);

end_sock:
    close(sockfd);
}

int main(int argc, char *argv[]) {
	int server_socket; 
	int ret; 

	ret = server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	
	if (ret < 0) {
		fprintf(stderr, "Failed to create a socket to listen on\n");
		return EXIT_FAILURE;
	}

	struct sockaddr_in serv_addr; 
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PROXY_PORT);

	ret = bind(server_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (ret < 0) {
		fprintf(stderr, "Failed to bind to port %d\n", PROXY_PORT);
		return EXIT_FAILURE;
	}

	ret = listen(server_socket, PROXY_CONN); 
	if (ret < 0) {
		fprintf(stderr, "Failed to listen on port %d\n", PROXY_PORT);
		return EXIT_FAILURE;
	}

	fprintf(stdout, "Listening on port %d\n", PROXY_PORT);

	for (;;) {
		struct sockaddr_in client_addr; 
		socklen_t client_addrlen = sizeof(client_addr);	
		int client_socket; 

		ret = client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_addrlen);
		if (ret < 0) {
			fprintf(stderr, "Failed to establish socket connection with client\n");	
			return EXIT_FAILURE;
		}

        ret = fork();
        switch (ret) {
        case -1: 
            fprintf(stderr, "[CLIENT SOCKET %d] Failed to fork child process to handle the request\n", client_socket);
            return EXIT_FAILURE; 
            break; 
        case 0: 
            handle_request(client_socket);
            break;
        default: 
            fprintf(stdout, "[PROGRAM] Successfully forked a new child process with PID %d\n", ret);
            break;
        }
	}

	return EXIT_SUCCESS;
}
