#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
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
        return ERR_MEM;
    }

    int bytes = 0;
    do {
        ret = recv(fd, line+bytes, line_len-bytes, MSG_WAITALL);
        if (ret < 0) {
            return ERR_MEM;
        }
        bytes += ret;
    } while (bytes < line_len);

    *msgbuff = (char *) realloc(*msgbuff, *msgbuff_len+line_len);
    if (!*msgbuff) {
        return ERR_MEM;
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
		free(line);
	}
    return 0;

}

void do_err(void) {
    fprintf(stderr, "failed with error code %d\n", err);
}

int do_con_srv(struct conn *conn) {
    statem = state_con_srv;

    int ret = 0;
    struct httpareq *req = &conn->cltreq;
    struct point *host = &req->hentries[header_host];
    if (host->er == NULL) {
        return ERR_PARS;
    }

    struct hostinfo *info = 
        (struct hostinfo *) calloc(1, sizeof(struct hostinfo));
    if (!info) {
        return ERR_MEM;
    }

    ret = pahostinfo(host->er, host->len, info);
    if (ret < 0) {
        return ERR_PARS;
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
        return ERR_PARS;
    }

    ret = conn->srvfd = socket(res->ai_family, res->ai_socktype,
            res->ai_protocol);
    if (ret < 0) {
        freeaddrinfo(res);
        free(info->hostname);
        free(info->service);
        free(info);
        return ERR_PARS;
    }

    ret = connect(conn->srvfd, res->ai_addr, res->ai_addrlen);
    if (ret < 0) {
        freeaddrinfo(res);
        free(info->hostname);
        free(info->service);
        free(info);
        return ERR_PARS;
    }

    return ret;
}

int do_rcv_clt(struct conn *conn) {
    statem = state_rcv_clt;

    int ret = 0;
    char *line = NULL; 
    char *msgbuff = NULL;
    int line_len = 0; 
    int msgbuff_len = 0;

    // request line 
    ret = read_line(conn->cltfd, &line_len, &line, &msgbuff_len, &msgbuff);
    if (ret < 0) {
        return ERR_RECV;
    }

    ret = pareqtitl(line, line_len, &(conn->cltreq.titl));    
    if (ret < 0) {
        return ERR_PARSTITLE;
    }

    free(line);

    // headers
    int next_header = 1; 
    while (next_header) {
        ret = read_line(conn->cltfd, &line_len, &line, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            return ERR_RECV;
        }

        if (line_len == 0) {
            next_header = 0;
            continue;
        }

        ret = parshfield(line, line_len, conn->cltreq.hentries);
        if (ret < 0) {
            return ERR_PARSHEADER;
        }

        free(line);
    }

    // body
    struct httpareq *req = &conn->cltreq;
    struct point *content_length_entry = &req->hentries[header_content_length];
    struct point *transfer_encoding_entry =
        &req->hentries[header_transfer_encoding];
    if (content_length_entry->er) {
        int content_length = 0;

        ret = stoin(content_length_entry->er, 
                content_length_entry->len, &content_length);
        if (ret < 0) {
            return ERR_PARS;
        }

        ret = pull_content_length(conn->srvfd, 
                content_length, &msgbuff_len, &msgbuff);
        if (ret < 0) {
            return ERR_RECV;
        }
    } else if (transfer_encoding_entry->er &&
            strcmp(transfer_encoding_entry->er, "chunked") == 0) {
	    ret = pull_chunked_encoding(conn->srvfd, &msgbuff_len, &msgbuff);
	    if (ret < 0) {
            return ERR_RECV;
	    }
    } 
    
    conn->cltbuff = msgbuff;
    conn->cltbuff_len = msgbuff_len;

    return 0; 
}

int read_buffer(int fd, char **buff, int *len) {
    char *tmp = (char *) malloc(RELAY_BUFFER_SIZE);
    if (!tmp) {
        return ERR_MEM;
    }

    memset(tmp, 0, RELAY_BUFFER_SIZE);
    int bytes = recv(fd, tmp, RELAY_BUFFER_SIZE, 0);
    if (bytes <= 0) {
        free(tmp);
        return ERR_RECV;
    }

    *buff = realloc(*buff, *len+bytes);
    if (!*buff) {
        free(tmp);
        return ERR_MEM;
    }

    memcpy(*buff+*len, tmp, bytes);
    *len += bytes;

    return 0;
}

int write_buffer(int fd, char **buff, int *len) {
    if (*len <= 0) {
        *len = 0;
        return 0;
    }

    int writen = send(fd, *buff, *len, 0); 
    if (writen < 0) {
        return ERR_SEND;
    }

    char *trunc = (char *) malloc(*len-writen);
    if (!trunc) {
        return ERR_MEM;
    }

    memcpy(trunc, *buff+writen, *len-writen);
    
    char *tofree = *buff; // FIXME: any better solution? 
    *buff = trunc;
    *len -= writen;
    free(tofree);

    return 0;
}

void do_statem(struct conn *conn) {
    int ret = 0; 

    ret = do_rcv_clt(conn); 
    if (ret < 0) {
        err = ret;
        do_err();
    }

    ret = do_con_srv(conn);
    if (ret < 0) {
        err = ret;
        do_err();
    }

    // TODO: add stanard checks for detecting real TLS connections
    //       and prevent fake/forged ones.
    if (conn->cltreq.titl.method == method_connect) {
        int size = snprintf(NULL, 0, "%.*s 200 Connection established\r\n"
                                     "Proxy-agent: proxlib\r\n"
                                     "\r\n", 
                                     conn->cltreq.titl.ver.len, conn->cltreq.titl.ver.er
                );
        size += 1;
        char *msg = (char *) malloc(size);
        memset(msg, 0, size);
        snprintf(msg, size, "%.*s 200 Connection established\r\n"
                                     "Proxy-agent: proxlib\r\n"
                                     "\r\n", 
                                     conn->cltreq.titl.ver.len, conn->cltreq.titl.ver.er
                );
        
        ret = write_buffer(conn->cltfd, &msg, &size);
        if (ret < 0) {
            fprintf(stderr, "Failed writing to client: %s\n", strerror(errno));
            return;
        }

        free(msg);
        free(conn->cltbuff);
        conn->cltbuff = 0; 
        conn->cltbuff_len = 0;
    }

    // relay the data between the two sockets until the end of time
    ssize_t bytes_received;
	struct pollfd fds[2];
    for (;;) {
	    memset(fds, 0, 2*sizeof(struct pollfd));
        fds[0].fd = conn->cltfd;
        fds[1].fd = conn->srvfd;

        fds[0].events |= POLLHUP;
        fds[1].events |= POLLHUP;

        if (conn->srvbuff_len > 0) {
            fds[0].events |= POLLOUT;
        }
        if (conn->cltbuff_len > 0) {
            fds[1].events |= POLLOUT;
        }
        if (!conn->srvbuff_len) {
            fds[1].events |= POLLIN;
        }
        if (!conn->cltbuff_len) {
            fds[0].events |= POLLIN;
        }

        ret = poll(fds, 2, 1000);

        if (fds[1].revents & POLLOUT) {
            ret = write_buffer(conn->srvfd, 
                    &conn->cltbuff, &conn->cltbuff_len);
        }
        if (ret < 0) {
            break;
        }

        if (fds[1].revents & POLLIN) {
            ret = read_buffer(conn->srvfd, 
                    &conn->srvbuff, &conn->srvbuff_len);
        }
        if (ret < 0) {
            break;
        }

        if (fds[0].revents & POLLIN) {
            ret = read_buffer(conn->cltfd, 
                    &conn->cltbuff, &conn->cltbuff_len);
        }
        if (ret < 0) {
            break;
        }

        if (fds[0].revents & POLLOUT) {
            ret = write_buffer(conn->cltfd, 
                    &conn->srvbuff, &conn->srvbuff_len);
        }
        if (ret < 0) {
            break;
        }

        if (fds[0].revents & POLLHUP) {
            break;
        }
        if (fds[1].revents & POLLHUP) {
            break;
        }
        if (ret < 0) {
            break;
        }
    }

    if (conn->cltbuff_len > 0) {
        write_buffer(conn->srvfd, &conn->cltbuff, &conn->cltbuff_len);
    }
    if (conn->srvbuff_len > 0) {
        write_buffer(conn->cltfd, &conn->srvbuff, &conn->srvbuff_len);
    }

    close(conn->cltfd);
    close(conn->srvfd);
    exit(0); // child die
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

	for (;;) {
		fprintf(stdout, "listening for sockets\n");
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
		fprintf(stdout, "accepted new client socket\n");

        ret = fork();
        if (ret < 0) {
            fprintf(stderr, "[CLIENT SOCKET %d] Failed to fork child process"
                            "to handle the request\n", new_clt_sock);
            return -1; 
        } 

        if (ret > 0) {
            fprintf(stdout, "+new request process:%d(pid)\n", ret);
            continue;
        }

        // request process
        struct conn *conn = (struct conn *) calloc(1, sizeof(struct conn));
        if (!conn) {
            fprintf(stderr, "Not enough dynamic memory "
                    "to establish connection\n");
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

    ret = do_srv();
    if (ret < 0) {
        return -1;
    }

    fretres();
}
