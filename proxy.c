#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <regex.h>
#include "structs.h"

#define PROXY_PORT 2020
#define PROXY_CONN 20
#define PROXY_MAX_MSGLEN 10*1024
#define TITLE_DELIM " "

#define REGEX_MATCHN 4
#define REGEX_TITLE "^([A-Z]+)[ ]+([a-zA-Z0-9\\:\\/\\_\\-\\.\\,]+)[ ]+([a-zA-Z0-9\\_\\-\\.\\,\\/]+)[ ]*[$\n\r]"
#define REGEX_HEADER "^(.*)[$\\n\\r]"

struct http_msg *child_msg;
regex_t preg; 
regmatch_t pmatch[REGEX_MATCHN];

void *extractsub(const char *msg, regmatch_t match) {
    int buflen = match.rm_eo - match.rm_so;
    void *buf = (void *) calloc(1, buflen);
    if (buf == NULL) 
        goto _return;

    sprintf(buf, "%.*s", buflen, &msg[match.rm_so]); 

_return:
    return buf;
}

int parse_header(char *msgbuff) {
    return 0;
}

int parse_title(char *msgbuff) {
    int ret; 

    ret = regcomp(&preg, REGEX_TITLE, REG_EXTENDED);
    if (ret != 0)
        goto _err;

    ret = regexec(&preg, msgbuff, REGEX_MATCHN, pmatch, 0);
    if (ret != 0)
        goto _err;

    child_msg->method = extractsub(msgbuff, pmatch[1]);
    if (child_msg->method == NULL) 
        goto _err;

    child_msg->uri = extractsub(msgbuff, pmatch[2]);
    if (child_msg->uri == NULL) 
        goto _err;

    child_msg->ver = extractsub(msgbuff, pmatch[3]); 
    if (child_msg->ver == NULL)
        goto _err;

    goto _ok;

_err: 
    regfree(&preg);
    return -1; 

_ok:
    regfree(&preg);
    return 0;

}

int par_line = 0; 

int parse_line(char *line, int line_count) {
    int ret = 0; 

    if (line_count == 0) {
        ret = parse_title(line);
    } else {
        ret = parse_header(line);
    }

    return ret;
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

    for (char *ln = strtok(msgbuff, "\n"); ln != NULL; ln = strtok(NULL, "\n"), par_line++) {
        parse_line(ln, par_line);
    }
    
    // start parsing 
    /*ret = parse_title(msgbuff); 
    if (ret < 0) {
        fprintf(stderr, "[CHILD %d] Failed to parse the title of the request\n", id);
        goto end_structs; 
    }*/


//end_structs: 
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
