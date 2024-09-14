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
int debug = 1;
int statem = 0; 
int err = 0;

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

int pull_content_length(int fd, int len, int *msgbuff_len, char **msgbuff) {
    int ret = 0; 
    int line_len = len;
    char *line = (char *) calloc(1, line_len);
    if (!line) {
        return err_mem;
    }

    int bytes = 0;
    do {
        ret = recv(fd, line+bytes, line_len-bytes, MSG_WAITALL);
        if (ret < 0) {
            return err_recv;
        }
        bytes += ret;
    } while (bytes < line_len);

    *msgbuff = (char *) realloc(*msgbuff, *msgbuff_len+line_len);
    if (!*msgbuff) {
        return err_mem;
    }

    memcpy(*msgbuff+*msgbuff_len, line, line_len);
    *msgbuff_len += line_len;

    return 0;
}

int pull_chunked_encoding(int fd, int *msgbuff_len, char **msgbuff) {
	int ret = 0; 
	char *line = NULL;
	int line_len = 0; 

	while (1) {
		ret = read_line(fd, &line_len, &line, msgbuff_len, msgbuff);
		if (ret < 0) {
			fprintf(stderr, "Failed receiving chunked body from upstream\n");
			return -1;
		}

		line_len = strtol(line, (char **) 0, 16); 
		if (!line_len) {
			break;
		}

		line_len += 2;

		free(line);

		line = (char *) calloc(1, line_len);
		if (!line) {
			fprintf(stderr, "Not enough dynamic memory\n");
			return -1;
		}

		int bytes = 0; 
		do {
			ret = recv(fd, line+bytes, line_len-bytes, MSG_WAITALL); 
			if (ret < 0) {
				fprintf(stderr, "Failed reading respones body from server\n");
				return -1;
			}
			bytes += ret;
		} while (bytes < line_len); 

		*msgbuff = (char *) realloc(*msgbuff, *msgbuff_len+line_len);
		if (!msgbuff) {
			fprintf(stderr, "Not enough dynamic memory\n");
			return -1;
		}

		memcpy(*msgbuff+*msgbuff_len, line, line_len);
		*msgbuff_len += line_len;
		if (debug == 1) {
			fprintf(stdout, "debug - [upstream] received chunk:%d\n", line_len);
		}
		free(line);
	}
    return 0;

}

void do_err(void) {
    fprintf(stderr, "[%s] failed with error code %d=%s\n", 
            states_str[statem], err, errs_str[err]);
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
        return err_recv;
    }

    if (debug == 1) {
        fprintf(stdout, "debug - [upstream] received line: %s\n", line);
    }

    ret = parestitl(line, line_len, &(conn->srvres.titl));    
    if (ret < 0) {
        return err_parstitle;
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
            return err_recv;
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
            return err_parsheader;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - parsed header field\n");
        }

        free(line);
    }

    // body
    struct httpares *res = &conn->srvres;
    struct point *content_length_entry = &res->hentries[header_content_length];
    struct point *transfer_encoding_entry = &res->hentries[header_transfer_encoding];
    if (content_length_entry->er) {
        int content_length = 0;
 
        ret = stoin(content_length_entry->er, content_length_entry->len, &content_length);
        if (ret < 0) {
            return err_pars;
        }

        ret = pull_content_length(conn->srvfd, content_length, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            return err_recv;
        }
        fprintf(stdout, "Successfully received normal body from server\n");
    } else if (transfer_encoding_entry->er && strcmp(transfer_encoding_entry->er, "chunked") == 0) {
	    ret = pull_chunked_encoding(conn->srvfd, &msgbuff_len, &msgbuff);
	    if (ret < 0) {
            return err_recv;
	    }
	    fprintf(stdout, "Successfully received chunked body from server\n");
    } else {
        return err_support;
    }

    fprintf(stdout, "srvbuff:%p+srvbuff_len:%d\n", conn->srvbuff, conn->srvbuff_len);
    conn->srvbuff = msgbuff;
    conn->srvbuff_len = msgbuff_len;

    return 0; 
}

int do_con_srv(struct conn *conn) {
    int ret = 0;
    struct httpareq *req = &conn->cltreq;
    struct point *host = &req->hentries[header_host];
    if (host->er == NULL) {
        return err_pars;
    }

    struct hostinfo *info = (struct hostinfo *) calloc(1, sizeof(struct hostinfo));
    if (!info) {
        return err_mem;
    }

    ret = pahostinfo(host->er, host->len, info);
    if (ret < 0) {
        return err_pars;
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
        free(info->hostname);
        free(info->service);
        free(info);
        return err_pars;
    }

    ret = conn->srvfd = socket(res->ai_family, res->ai_socktype,
            res->ai_protocol);
    if (ret < 0) {
        freeaddrinfo(res);
        free(info->hostname);
        free(info->service);
        free(info);
        return err_pars;
    }

    ret = connect(conn->srvfd, res->ai_addr, res->ai_addrlen);
    if (ret < 0) {
        freeaddrinfo(res);
        free(info->hostname);
        free(info->service);
        free(info);
        return err_pars;
    }

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
    fprintf(stdout, "debug - listening for new lines from client\n");
    ret = read_line(conn->cltfd, &line_len, &line, &msgbuff_len, &msgbuff);
    if (ret < 0) {
        return err_recv;
    }

    if (debug == 1) {
        fprintf(stdout, "debug - received line of %d bytes from client\n", line_len);
    }

    ret = pareqtitl(line, line_len, &(conn->cltreq.titl));    
    if (ret < 0) {
        return err_parstitle;
    }

    if (debug == 1) {
        fprintf(stdout, "[do_rcv_clt] parsed request line\n");
    }

    free(line);

    // headers
    int next_header = 1; 
    while (next_header) {
        ret = read_line(conn->cltfd, &line_len, &line, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            return err_recv;
        }

        if (line_len == 0) {
            if (debug == 1) {
                fprintf(stdout, "[do_rcv_clt] reached end of headers for the client\n");
            }
            next_header = 0;
            continue;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - received line: %s\n", line);
        }

        ret = parshfield(line, line_len, conn->cltreq.hentries);
        if (ret < 0) {
            return err_parsheader;
        }

        if (debug == 1) {
            fprintf(stdout, "debug - parsed header field\n");
        }

        free(line);
    }

    // body
    struct httpareq *req = &conn->cltreq;
    struct point *content_length_entry = &req->hentries[header_content_length];
    struct point *transfer_encoding_entry = &req->hentries[header_transfer_encoding];
    if (content_length_entry->er) {
        int content_length = 0;

        ret = stoin(content_length_entry->er, content_length_entry->len, &content_length);
        if (ret < 0) {
            return err_pars;
        }

        ret = pull_content_length(conn->srvfd, content_length, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            return err_recv;
        }

        fprintf(stdout, "Successfully received normal body from server\n");
    } else if (transfer_encoding_entry->er && strcmp(transfer_encoding_entry->er, "chunked") == 0) {
	    ret = pull_chunked_encoding(conn->srvfd, &msgbuff_len, &msgbuff);
	    if (ret < 0) {
            return err_recv;
	    }
	    fprintf(stdout, "Successfully received chunked body from server\n");
    } 
    
    conn->cltbuff = msgbuff;
    conn->cltbuff_len = msgbuff_len;

    return 0; 
}

void do_clear(struct conn *conn) {
    statem = state_rcv_clt;
    frepareq(&conn->cltreq);
    frepares(&conn->srvres);
    free(conn->cltbuff);
    free(conn->srvbuff);
} 

void do_statem(struct conn *conn) {
    int ret = 0;

    for (int counter = 0; counter < MAX_BOUND; counter++) {
        switch (statem) {
        case state_rcv_clt:
            ret = do_rcv_clt(conn);
            break;
        case state_con_srv:
            ret = do_con_srv(conn);
            break;
        case state_fwd_srv: 
            ret = do_fwd_srv(conn);
            break;
        case state_rcv_srv: 
            ret = do_rcv_srv(conn);
            break;
        case state_fwd_clt: 
            ret = do_fwd_clt(conn);
            break;
        }

        if (ret > 0) {
            err = ret;
        }

        if (err) {
            do_err();
            break;
        }

        if (statem == state_fwd_clt) {
            do_clear(conn);
            continue;
        }

        statem++;
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
        statem = state_rcv_clt;
        do_statem(conn);
        free(conn);

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
