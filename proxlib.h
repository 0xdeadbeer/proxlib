#ifndef STRUCTS_H
#define STRUCTS_H

#include "parslib/parslib.h"

#ifndef MAX_BOUND
#define MAX_BOUND 100000000000
#endif

#define PROXY_PORT 2020
#define PROXY_CONN 20
#define RELAY_BUFFER_SIZE 1024*2
#define RELAY_POLL_TIMEOUT 1000

enum states {
    state_rcv_clt = 0,
    state_con_srv,
    state_fwd_srv,
    state_rcv_srv,
    state_fwd_clt,
    state_ok
};

#define ERR_GENERIC     -1 
#define ERR_MEM         -2
#define ERR_RECV        -3
#define ERR_SEND        -4
#define ERR_PARS        -5
#define ERR_PARSTITLE   -6
#define ERR_PARSHEADER  -7
#define ERR_SUPPORT     -8
#define ERR_TIMEOUT     -9

char *states_str[] = {
    "state_rcv_clt",
    "state_con_srv",
    "state_fwd_srv",
    "state_rcv_srv",
    "state_fwd_clt",
    "state_ok"
};

struct conn {
    int cltfd; 
    int srvfd; 

    char *cltbuff;
    char *srvbuff;

    int cltbuff_len;
    int srvbuff_len;

    struct httpareq cltreq;
    struct httpares srvres; 
};

#endif
