#ifndef STRUCTS_H
#define STRUCTS_H

#define MAX_BOUND 10000

#define SERVER_MODE "server"
#define CLIENT_MODE "client"

#define PROXY_PORT 2020
#define PROXY_CONN 20
#define PROXY_MAX_MSGLEN 10000*1024

#define REGEX_MATCHN 4
#define REGEX_TITLE "^([A-Z]+)[ ]+([a-zA-Z0-9\\:/_.,-]+)"\
                    "[ ]+([a-zA-Z0-9_.,/-]+)[\n\r]*$"
#define REGEX_HEADER "^([a-zA-Z0-9_-]*):[ \t]+([^\r\n]*)"

#define CLIENT_MESSAGE "GET http://archive.0xdeadbeer.org/ HTTP/1.0\r\n\r\n"\
                       "Host: archive.0xdeadbeer.org\r\n"\

#define STATEM_RCV_CLT 0b00000001
#define STATEM_PRS_CLT 0b00000010
#define STATEM_CON_SRV 0b00000100
#define STATEM_FWD_SRV 0b00001000
#define STATEM_RCV_SRV 0b00010000
#define STATEM_PRS_SRV 0b00100000
#define STATEM_FWD_CLT 0b01000000
#define STATEM_ERR     0b10000000

struct header {
    char *key; 
    char *value; 
};

struct request {
    char *method; 
    char *uri; 
    char *ver; 
    int header_num;
    struct header *headers;
};

#endif
