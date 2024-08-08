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

int debug = 1; 
struct request *clt_data;
regex_t preg; 
regmatch_t pmatch[REGEX_MATCHN];

int statem; 

int clt_sock = -1;
int srv_sock = -1;
char *clt_msg = NULL;
int clt_msg_len = 0; 
char *srv_msg = NULL;
int srv_msg_len = 0;

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
        goto _ok; 

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

    int last_index = clt_data->header_num;

    clt_data->header_num++;
    clt_data->headers = (void *) realloc(clt_data->headers,
            clt_data->header_num*sizeof(struct header));

    clt_data->headers[last_index] = new_header;

_ok:
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

    clt_data->method = extractsub(msgbuff, pmatch[1]);
    if (clt_data->method == NULL) 
        goto _err;

    clt_data->uri = extractsub(msgbuff, pmatch[2]);
    if (clt_data->uri == NULL) 
        goto _err;

    clt_data->ver = extractsub(msgbuff, pmatch[3]); 
    if (clt_data->ver == NULL)
        goto _err;

    regfree(&preg);
    return 0;

_err: 
    regfree(&preg);
    return -1; 

}

void free_title() {
    free(clt_data->method);
    free(clt_data->uri);
    free(clt_data->ver);
}

void free_headers() {
    for (int i = 0; i < clt_data->header_num; i++) {
        struct header *header = &clt_data->headers[i];
        free(header->key);
        free(header->value);
    }
    free(clt_data->headers);
}

void free_message() {
    free_title();
    free_headers();
    free(clt_data);
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

char *getheader(char *key) {
    char *ret = NULL; 
    for (int i = 0; i < clt_data->header_num; i++) {
        struct header *hdr = &clt_data->headers[i];
        if (strcmp(hdr->key, key)) 
            continue; 

        ret = hdr->value; 
    }

    return ret; 
}

void do_err(void) {
    int statem_code = statem & (~STATEM_ERR);
    fprintf(stderr, "[%d,%d,%d] Errored out!\n", statem, statem_code, STATEM_ERR);
}

int do_fwd_clt(void) {
    int bytes = 0; 
    int ret = 0; 
    do {
        ret = send(clt_sock, srv_msg+bytes, srv_msg_len-bytes, 0);
        if (ret < 0) 
            return -1; 
        
        bytes += ret;
    } while (bytes < srv_msg_len);

    return 0;
}

// TODO: add parsing ability
int do_prs_srv(void) {
    int ret = 0; 
    return ret; 
}

int do_rcv_srv(void) {
    int bytes = 0;
    int ret = 0; 
    do {
        ret = recv(srv_sock, srv_msg+bytes, PROXY_MAX_MSGLEN-bytes, 0);
        if (ret < 0) 
            return -1;
        if (!ret) 
            break;

        bytes += ret;
    } while (bytes < sizeof(PROXY_MAX_MSGLEN));

    srv_msg_len = bytes;

    if (debug) {
        fprintf(stdout, "[%d] Received server message: %s\n", statem, srv_msg);
    }

    return 0; 
}

int do_con_srv(void) {
    int ret;
    char *host = getheader("Host");
    if (!host)
        return -1;
    
    struct addrinfo hints; 
    struct addrinfo *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(host, "80", &hints, &res);
    if (ret < 0) 
        return -1;

    ret = srv_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ret < 0)
        return -1;

    ret = connect(srv_sock, res->ai_addr, res->ai_addrlen);
    if (ret < 0)
        return -1;

    return 0;
}

int do_fwd_srv(void) {
    int bytes = 0;
    int ret = 0;
    do {
        ret = send(srv_sock, clt_msg+bytes, clt_msg_len-bytes, 0);
        if (ret < 0) 
            return -1; 

        bytes += ret; 
    } while (bytes < clt_msg_len);

    return 0;
}

int do_prs_clt(void) {
    int ret;
    int ln_cnt = 0;

    char *ln = strdup(clt_msg);
    if (!ln)
        return -1;

    ln = strtok(ln, "\n");
    while (ln) {
        ret = parse_line(ln, ln_cnt);
        if (ret < 0)
            return -1;

        ln_cnt++;
        ln = strtok(NULL, "\n");
    }

    return 0; 
}

int do_rcv_clt(void) {
    int bytes = 0; 
    int ret = 0;
    do {
        ret = recv(clt_sock, clt_msg+bytes, PROXY_MAX_MSGLEN-bytes, 0);
        if (ret < 0) 
            return -1;
        if (!ret) 
            break;

        bytes += ret;
    } while (bytes < sizeof(PROXY_MAX_MSGLEN));

    clt_msg_len = bytes;

    if (debug) {
        fprintf(stdout, "[%d] Received client message: %s\n", statem, clt_msg);
    }

    return 0; 
}

int do_alloc(void) {
    clt_msg = (char *) calloc(1, PROXY_MAX_MSGLEN);
    if (!clt_msg)
        return -1;

    srv_msg = (char *) calloc(1, PROXY_MAX_MSGLEN);
    if (!srv_msg) 
        return -1;

    clt_data = (struct request *) calloc(1, sizeof(struct request));
    if (!clt_data) 
        return -1;

    return 0;
}

void do_clear(void) {
    memset(clt_msg, 0, PROXY_MAX_MSGLEN);
    memset(srv_msg, 0, PROXY_MAX_MSGLEN);
    memset(clt_data, 0, sizeof(struct request));

    clt_msg_len = 0;
    srv_msg_len = 0;
} 

void dostatem() {
    int ret = do_alloc(); 
    if (ret < 0) {
        do_err();
        return;
    }
        
    for (int counter = 0; counter < MAX_BOUND; counter++) {
        switch (statem & (~STATEM_ERR)) {
        case STATEM_RCV_CLT:
            ret = do_rcv_clt();
            break;
        case STATEM_PRS_CLT: 
            ret = do_prs_clt();
            break; 
        case STATEM_CON_SRV: 
            ret = do_con_srv();
            break;
        case STATEM_FWD_SRV: 
            ret = do_fwd_srv();
            break; 
        case STATEM_RCV_SRV: 
            ret = do_rcv_srv();
            break;
        case STATEM_PRS_SRV: 
            ret = do_prs_srv();
            break; 
        case STATEM_FWD_CLT:
            ret = do_fwd_clt();
            break;
        default: 
            ret = -1; 
            break; 
        }

        if (ret < 0) 
            statem |= STATEM_ERR;

        if (statem & STATEM_ERR) {
            do_err();
            break;
        }

        if (statem & STATEM_FWD_CLT) {
            statem = STATEM_RCV_CLT;
            do_clear();
            continue;
        }

        statem <<= 1;
    }

    free_message();
    free(clt_msg);
    free(srv_msg);
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

    int on = 1; 
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0) {
        fprintf(stderr, "Failed flagging server socket as reusable\n");
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
            fprintf(stderr, "[CLIENT SOCKET %d] Failed to fork child process"
                            "to handle the request\n", client_socket);
            return -1; 
            break; 
        case 0: 
            clt_sock = client_socket;
            statem = STATEM_RCV_CLT;
            dostatem();
            return 0;
            break;
        default: 
            fprintf(stdout, "[PROGRAM] Successfully forked a new child process"
                            " with PID %d\n", ret);
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

    ret = connect(client_socket, (struct sockaddr *) &serv_addr,
            sizeof(serv_addr));
	if(ret < 0)
	{
        fprintf(stderr, "Failed connecting to remote server\n");
		return -1;
	}

    int bytes = 0; 
    do {
        bytes += send(client_socket, CLIENT_MESSAGE, 
                sizeof(CLIENT_MESSAGE), 0);
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
