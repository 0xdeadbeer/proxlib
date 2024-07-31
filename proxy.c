#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <regex.h>
#include "structs.h"

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
    int ret; 

    ret = regcomp(&preg, REGEX_HEADER, REG_EXTENDED);
    if (ret != 0) 
        goto _err; 

    ret = regexec(&preg, msgbuff, REGEX_MATCHN, pmatch, 0); 
    if (ret != 0) 
        goto _err; 

    char *key = extractsub(msgbuff, pmatch[1]);
    if (key == NULL) 
        goto _err; 

    char *value = extractsub(msgbuff, pmatch[2]);
    if (value == NULL) 
        goto _err;

    struct header new_header = {
        .key = key,
        .value = value
    };

    int last_index = child_msg->header_num;

    child_msg->header_num++;
    child_msg->headers = (void *) realloc(child_msg->headers,
            child_msg->header_num*sizeof(struct header));

    child_msg->headers[last_index] = new_header;

    regfree(&preg);
    return 0;

_err: 
    regfree(&preg);
    return -1; 
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

    regfree(&preg);
    return 0;

_err: 
    regfree(&preg);
    return -1; 

}

int parse_line(char *line, int line_count) {
    int ret = 0; 

    if (line_count == 0) {
        ret = parse_title(line);
    } else {
        ret = parse_header(line);
    }

    return ret;
}

int test(char *line, int num) {
    fprintf(stdout, "line %s and num %d\n", line, num);
    return 0;
}

int par_line = 0; 

void handle_request(int sockfd) {
    int ret;
    int id = getpid();

    char *msgbuff = (char *) calloc(1, PROXY_MAX_MSGLEN);
    if (msgbuff == NULL) {
        fprintf(stderr, "Not enough dynamic memory\n");
        goto end_sock;
    }
    
    ret = recv(sockfd, msgbuff, PROXY_MAX_MSGLEN, 0);
    if (ret < 0) {
        fprintf(stderr, "[CHILD %d] Failed to receive data from client\n", id);
        goto end_sock; 
    }

    fprintf(stdout, "[CHILD %d] Received data from client: %s\n", id, msgbuff);

    // prepare structs 
    child_msg = (struct http_msg *) calloc(1, sizeof(struct http_msg));
    if (child_msg == NULL) {
        fprintf(stderr, "[CHILD %d] Failed to allocate memory for client"
                        "structs\n", id);
        goto end_sock; 
    }

    char *ln = strdup(msgbuff); 
    if (!ln) {
        fprintf(stdout, "Not enough dynamic memory\n");
        goto end_sock; 
    }

    ln = strtok(ln, "\n");

    while (ln) {
        parse_line(ln, par_line);
        par_line++; 
        ln = strtok(NULL, "\n"); 
    }

    fprintf(stdout, "I am done here.... zzzz \n");

    for (;;);

//end_structs: 
    //free(child_msg);

end_sock:
    close(sockfd);
}

void dohelp() {
    printf(
        "+====================+\n"
        "|   HTTP/1.0 PROXY   |\n"
        "+=====@0xdeadbeer====+\n"
        "usage:\n"
        " ./proxy [mode]\n"
        "mode:\n"
        " * server -> start listening as proxy\n"
        " * client -> send test requests to server\n"
    );
}

int doserver(void) {
    int ret, server_socket; 

    ret = server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
        fprintf(stderr, "Failed to create a socket to listen on\n");
		return -1;
	}

	struct sockaddr_in serv_addr; 

	memset(&serv_addr, 0, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PROXY_PORT);

    ret = bind(server_socket, (struct sockaddr *) &serv_addr,
            sizeof(serv_addr));
	if (ret < 0) {
		fprintf(stderr, "Failed to bind to port %d\n", PROXY_PORT);
		return -1;
	}

	ret = listen(server_socket, PROXY_CONN); 
	if (ret < 0) {
        fprintf(stderr, "Failed to listen on port %d\n", PROXY_PORT);
		return -1;
	}

	fprintf(stdout, "Listening on port %d\n", PROXY_PORT);

	for (;;) {
		struct sockaddr_in client_addr; 
        socklen_t client_addrlen = sizeof(client_addr);	
		int client_socket; 

        ret = client_socket = accept(server_socket, (struct sockaddr *)
                &client_addr, &client_addrlen);
		if (ret < 0) {
            fprintf(stderr, "Failed to establish socket connection with"
                            "client\n");	
			return -1;
		}

        ret = fork();
        switch (ret) {
        case -1: 
            fprintf(stderr, "[CLIENT SOCKET %d] Failed to fork child process to"
                            "handle the request\n", client_socket);
            return -1; 
            break; 
        case 0: 
            handle_request(client_socket);
            break;
        default: 
            fprintf(stdout, "[PROGRAM] Successfully forked a new child process"
                            "with PID %d\n", ret);
            break;
        }
	}

	return 0;
}

int doclient(void) {
    int ret = 0;
    int client_socket; 
	struct sockaddr_in serv_addr;

    ret = client_socket = socket(AF_INET, SOCK_STREAM, 0); 
	if(ret < 0)
	{
        fprintf(stderr, "Failed creating socket\n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PROXY_PORT);

    ret = inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
	if(ret <= 0)
	{
        fprintf(stderr, "Inet_pton error\n");
		return -1;
	}

    ret = connect(client_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if(ret < 0)
	{
        fprintf(stderr, "Failed connecting to remote server\n");
		return -1;
	}

    int bytes = 0; 
    do {
        bytes += send(client_socket, CLIENT_MESSAGE, sizeof(CLIENT_MESSAGE), 0);
    } while (bytes != sizeof(CLIENT_MESSAGE));

    fprintf(stdout, "Sent %d bytes to server\n", bytes);

    return 0;
}

int main(int argc, char *argv[]) {
	int ret; 
    if (argc != 2) {
        dohelp();
        return 0;
    }

    const char *mode = argv[1]; 
    ret = strcmp(mode, SERVER_MODE);
    if (ret == 0)
        return doserver();

    ret = strcmp(mode, CLIENT_MODE); 
    if (ret == 0)
        return doclient();

    fprintf(stderr, "Unknown proxy mode\n");
}
