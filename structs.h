#ifndef STRUCTS_H
#define STRUCTS_H

struct header {
    char *key; 
    char *value; 
};

struct http_msg {
    char *method; 
    char *uri; 
    char *ver; 
    struct header *headers;
    void *body;
};

#endif 
