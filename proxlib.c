#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "proxlib.h"
#include "parslib/parslib.h"

int on = 1; 
int debug = 3;
int statem; 

#define SEGMENT_LEN 512
#define MAX_BUFF_LEN 128 * 1024
int _read_line(int fd, char **outbuff) {
    char tmp_buff[SEGMENT_LEN]; 
    int tmp_buff_len = 0; 
    char *output_buff = NULL;
    int output_buff_len = 0;
    char *ptr = NULL;
    int whead_pos = 0;
    char *whead = NULL;
    int diff = 0;
    int ret = 0;
    int end = 0;

    while (!end) {
        ret = recv(fd, tmp_buff, SEGMENT_LEN, MSG_PEEK);
        if (ret <= 0) {
            break;
        }

        ptr = strstr(tmp_buff, "\r\n");  
        if (ptr >= tmp_buff+SEGMENT_LEN) {
            diff = ret; 
        } else {
            diff = ptr - tmp_buff + 2;
            end = 1;
        }

        tmp_buff_len = diff;
        whead_pos = output_buff_len;
        output_buff_len += tmp_buff_len;

        if (tmp_buff_len > MAX_BUFF_LEN) {
            return -1;
        }

        output_buff = (char *) realloc(output_buff, output_buff_len);
        if (!output_buff) {
            return -1;
        }

        whead = output_buff+whead_pos;
        ret = recv(fd, whead, diff, 0);
        if (ret <= 0) {
            break;
        }
    }

    *outbuff = output_buff;
    return output_buff_len;
}

/* easy wrapper for _read_line(int fd, void **outbuff) */ 
int read_line(int fd, 
              int *line_len, char **line, 
              int *msgbuff_len, char **msgbuff) {
    int ret = 0; 

    ret = *line_len = _read_line(fd, line);
    if (ret < 0) {
        return -1;
    }

    *msgbuff = (char *) realloc(*msgbuff, *msgbuff_len+*line_len);
    if (!*msgbuff) {
        free(*line);
        return -1;
    }

    memcpy(*msgbuff+*msgbuff_len, *line, *line_len);

    *msgbuff_len += *line_len;
    ((char *) *line)[(*line_len)-2] = '\0';
    *line_len -= 2;

    return 0;
}

int parse_line(char *line, int line_count) {
    int ret = 0; 

    return ret;
}

void do_err(void) {
    int statem_code = statem & (~STATEM_ERR);
    fprintf(stderr, "[%d,%d,%d] Errored out!\n", statem, statem_code,
            STATEM_ERR);
}

int do_fwd_clt(struct conn *conn) {
    int bytes = 0;
    int ret = 0;
    while (bytes < conn->srvbuff_len) {
        ret = write(conn->cltfd, conn->srvbuff+bytes, conn->srvbuff_len-bytes);
        if (ret < 0)
            return -1;

        bytes += ret;
    }

    return 0;
}

int do_rcv_srv(struct conn *conn) {
    int ret = 0;
    char *line = NULL; 
    char *msgbuff = NULL;
    int line_len = 0; 
    int msgbuff_len = 0;

    // response line 
    ret = read_line(conn->srvfd, &line_len, &line, &msgbuff_len, &msgbuff);
    if (ret < 0) {
        fprintf(stderr, "Failed receiving response line from upstream\n");
        return -1;
    }

    if (debug == 1) {
        fprintf(stdout, "debug - [upstream] received line: %s\n", line);
    }

    ret = parestitl(line, line_len, &(conn->srvres.titl));    
    if (ret < 0) {
        fprintf(stderr, "Failed parsing response line\n");
        return -1;
    }

    if (debug == 1) {
        fprintf(stdout, "debug - [upstream] parsed response line\n");
    }

    free(line);

    // headers
    int next_header = 1; 
    while (next_header) {
        ret = read_line(conn->srvfd, &line_len, &line, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            fprintf(stderr, "Failed receiving header line\n");
            return -1;
        }

        if (line_len == 0) {
            if (debug == 1) {
                fprintf(stdout, "debug - [upstream] reached end of headers\n");
            }
            next_header = 0;
            continue;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - [upstream] received line: %s\n", line);
        }

        ret = parshfield(line, line_len, conn->srvres.hentries);
        if (ret < 0) {
            fprintf(stderr, "Failed parsing header field\n");
            return -1;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - parsed header field\n");
        }

        free(line);
    }

    // body
body:
    struct httpares *res = &conn->srvres;
    struct point *content_length_entry = &res->hentries[header_content_length];
    if (content_length_entry->er == NULL) {
        fprintf(stderr, "[upstream] no content length header\n");
        return -1;
    }

    int content_length = 0;
    ret = stoin(content_length_entry->er, content_length_entry->len, &content_length);
    if (ret < 0) {
        fprintf(stderr, "[upstream] failed parsing content length header\n");
        return -1;
    }

    line_len = content_length;
    line = (char *) calloc(1, line_len);
    if (!line) {
        fprintf(stderr, "[upstream] not enough dynamic memory\n");
        return -1;
    }

    int bytes = 0;
    do {
        ret = recv(conn->srvfd, line+bytes, line_len-bytes, MSG_WAITALL);
        if (ret < 0) {
            fprintf(stderr, "[upstream] failed reading body from response\n");
            return -1;
        }
        bytes += ret;
    } while (bytes < line_len);

    msgbuff = (char *) realloc(msgbuff, msgbuff_len+line_len);
    if (!msgbuff) {
        fprintf(stderr, "[upstream] not enough dynamic memory\n");
        return -1;
    }

    memcpy(msgbuff+msgbuff_len, line, line_len);
    msgbuff_len += line_len;

    if (debug <= 2) {
        fprintf(stdout, "------------------------------\n");
        fprintf(stdout, "debug - [upstream] received body %d: %.*s\n", line_len, line_len, line);
        fprintf(stdout, "------------------------------\n");
    }

    if (debug <= 2) {
        fprintf(stdout, "printing parsed response\n");
        printfpares(&conn->srvres);
    }

    conn->srvbuff = msgbuff;
    conn->srvbuff_len = msgbuff_len;

    return 0; 
}

int do_con_srv(struct conn *conn) {
    int ret = 0;
    struct httpareq *req = &conn->cltreq;
    struct point *host = &req->hentries[header_host];
    if (host->er == NULL) {
        if (debug <= 2) {
            fprintf(stderr, "debug - request does not have HOST header\n");
        }
        goto _exit;
    }

    struct hostinfo *info = (struct hostinfo *) calloc(1, sizeof(struct hostinfo));
    if (!info) {
        goto _exit;
    }

    ret = pahostinfo(host->er, host->len, info);
    if (ret < 0) {
        if (debug <= 2) {
            fprintf(stderr, "Failed parsing upstream host header\n");
        }
        goto _exit_hostinfo;
    }

    if (debug <= 2) {
        fprintf(stdout, "Establishing connection with upstream: %.*s : %.*s\n", info->hostname_len, info->hostname, info->service_len, info->service);
    }

    struct addrinfo hints; 
    struct addrinfo *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(info->hostname, info->service, &hints, &res);
    if (ret < 0) {
        goto _exit_hostinfo;
    }

    ret = conn->srvfd = socket(res->ai_family, res->ai_socktype,
            res->ai_protocol);
    if (ret < 0) {
        goto _exit_getaddrinfo;
    }

    ret = connect(conn->srvfd, res->ai_addr, res->ai_addrlen);
    if (ret < 0) {
        goto _exit_getaddrinfo;
    }

_exit_getaddrinfo:
    freeaddrinfo(res);
_exit_hostinfo:
    free(info->hostname);
    free(info->service);
    free(info);
_exit:
    return ret;
}

int do_fwd_srv(struct conn *conn) {
    int bytes = 0;
    int ret = 0;
    while (bytes < conn->cltbuff_len) {
        ret = write(conn->srvfd, conn->cltbuff+bytes, conn->cltbuff_len-bytes);
        if (ret < 0)
            return -1;

        bytes += ret;
    }

    return 0;
}

int do_rcv_clt(struct conn *conn) {
    int ret = 0;
    char *line = NULL; 
    char *msgbuff = NULL;
    int line_len = 0; 
    int msgbuff_len = 0;

    // request line 
    ret = read_line(conn->cltfd, &line_len, &line, &msgbuff_len, &msgbuff);
    if (ret < 0) {
        fprintf(stderr, "Failed receiving request line\n");
        return -1;
    }

    if (debug == 1) {
        fprintf(stdout, "debug - received line: %s\n", line);
    }

    ret = pareqtitl(line, line_len, &(conn->cltreq.titl));    
    if (ret < 0) {
        fprintf(stderr, "Failed parsing request line\n");
        return -1;
    }

    if (debug == 1) {
        fprintf(stdout, "debug - parsed request line\n");
    }

    free(line);

    // headers
    int next_header = 1; 
    while (next_header) {
        ret = read_line(conn->cltfd, &line_len, &line, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            fprintf(stderr, "Failed receiving header line\n");
            return -1;
        }

        if (line_len == 0) {
            if (debug == 1) {
                fprintf(stdout, "debug - reached end of headers\n");
            }
            next_header = 0;
            continue;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - received line: %s\n", line);
        }

        ret = parshfield(line, line_len, conn->cltreq.hentries);
        if (ret < 0) {
            fprintf(stderr, "Failed parsing header field\n");
            return -1;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - parsed header field\n");
        }

        free(line);
    }

    // body
    // TODO

    if (debug <= 2) {
        fprintf(stdout, "printing parsed request\n");
        printfpareq(&conn->cltreq);
    }

    conn->cltbuff = msgbuff;
    conn->cltbuff_len = msgbuff_len;

    return 0; 
}

void do_clear(struct conn *conn) {
    statem = STATEM_RCV_CLT;
    frepareq(&conn->cltreq);
    frepares(&conn->srvres);
    free(conn->cltbuff);
    free(conn->srvbuff);
} 

void do_statem(struct conn *conn) {
    int ret = 0;

    for (int counter = 0; counter < MAX_BOUND; counter++) {
        switch (statem & (~STATEM_ERR)) {
        case STATEM_RCV_CLT:
            ret = do_rcv_clt(conn);
            break;
        case STATEM_CON_SRV:
            ret = do_con_srv(conn);
            break;
        case STATEM_FWD_SRV: 
            ret = do_fwd_srv(conn);
            break;
        case STATEM_RCV_SRV: 
            ret = do_rcv_srv(conn);
            break;
        case STATEM_FWD_CLT: 
            ret = do_fwd_clt(conn);
            break;
        }

        if (ret < 0) 
            statem |= STATEM_ERR;

        if (statem & STATEM_ERR) {
            do_err();
            break;
        }

        if (statem & STATEM_FWD_CLT) {
            do_clear(conn);
            continue;
        }

        statem <<= 1;
    }
}

int do_srv(void) {
    int ret, proxy_sock; 
	struct sockaddr_in serv_addr; 

    ret = proxy_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
        fprintf(stderr, "Failed to create a socket to listen on\n");
		return -1;
	}

    ret = setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret < 0) {
        fprintf(stderr, "Failed flagging server socket as reusable\n");
        return -1;
    }

	memset(&serv_addr, 0, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PROXY_PORT);

    ret = bind(proxy_sock, (struct sockaddr *) &serv_addr,
            sizeof(serv_addr));
	if (ret < 0) {
        fprintf(stderr, "Failed to bind to port %d\n", PROXY_PORT);
		return -1;
	}

	ret = listen(proxy_sock, PROXY_CONN); 
	if (ret < 0) {
        fprintf(stderr, "Failed to listen on port %d\n", PROXY_PORT);
		return -1;
	}

	fprintf(stdout, "Listening on port %d\n", PROXY_PORT);

	for (;;) {
		struct sockaddr_in new_clt_addr; 
        socklen_t new_clt_addr_len= sizeof(new_clt_addr);
		int new_clt_sock; 

        ret = new_clt_sock = accept(proxy_sock, (struct sockaddr *)
                &new_clt_addr, &new_clt_addr_len);
		if (ret < 0) {
            fprintf(stderr, "Failed to establish socket connection with"
                            "client\n");	
			return -1;
		}

        ret = fork();
        if (ret < 0) {
            fprintf(stderr, "[CLIENT SOCKET %d] Failed to fork child process"
                            "to handle the request\n", new_clt_sock);
            return -1; 
        } 

        if (ret > 0) {
            fprintf(stdout, "[PROGRAM] Successfully forked a new child process"
                            " with PID %d\n", ret);
            continue;
        }

        // child 
        struct conn *conn = (struct conn *) calloc(1, sizeof(struct conn));
        if (!conn) {
            fprintf(stderr, "Not enough dynamic memory to establish connection\n");
            return -1;
        }

        conn->cltfd = new_clt_sock;
        statem = STATEM_RCV_CLT;
        do_statem(conn);
        free(conn);

        if (debug == 1) {
            fprintf(stdout, "Finished proxying client\n");
        }

        return 0;
	}

	return 0;
}

int main(int argc, char *argv[]) {
    int ret = initres();
    if (ret < 0) {
        fprintf(stderr, "Failed generating trees\n");
        return -1;
    } 

    return do_srv();

    fretres();
}
