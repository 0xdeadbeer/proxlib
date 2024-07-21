#include "proxy_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define PROXY_PORT 80
#define PROXY_CONN 20

int main(int argc, char *argv[]) {
	int server_socket; 
	int new_fd;
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

		fprintf(stdout, "[CLIENT %d] Successfully connected\n", client_socket);
	}

	printf("New connection with fd -> %d\n", new_fd);

	return EXIT_SUCCESS;
}
