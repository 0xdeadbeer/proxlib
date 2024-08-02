#ifndef STRUCTS_H
#define STRUCTS_H

#define SERVER_MODE "server"
#define CLIENT_MODE "client"

#define PROXY_PORT 2020
#define PROXY_CONN 20
#define PROXY_MAX_MSGLEN 1000*1024

#define REGEX_MATCHN 4
#define REGEX_TITLE "^([A-Z]+)[ ]+([a-zA-Z0-9\\:/_.,-]+)"\
                    "[ ]+([a-zA-Z0-9_.,/-]+)[\n\r]*$"
#define REGEX_HEADER "^([a-zA-Z0-9_-]*):[ \t]+([^\r\n]*)"

#define CLIENT_MESSAGE "GET http://google.com/auth HTTP/1.0\n"\
                       "\n"\
                       "Host: google.com\n"\
                       "Authorization: Bearer ffja2439gjawgjgojserg\n"

struct header {
    char *key; 
    char *value; 
};

struct http_msg {
    char *method; 
    char *uri; 
    char *ver; 
    int header_num;
    struct header *headers;
};

#endif 
