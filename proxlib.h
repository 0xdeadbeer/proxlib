#ifndef STRUCTS_H
#define STRUCTS_H

#include "parslib/parslib.h"

#ifndef MAX_BOUND
#define MAX_BOUND 100000000000
#endif

#define PROXY_PORT 2020
#define PROXY_CONN 20

enum states {
    state_rcv_clt = 0,
    state_con_srv,
    state_fwd_srv,
    state_rcv_srv,
    state_fwd_clt
};

enum errs {
    err_generic = 1,
    err_mem,
    err_recv,
    err_pars,
    err_parstitle,
    err_parsheader,
    err_support
};

char *states_str[] = {
    "state_rcv_clt",
    "state_con_srv",
    "state_fwd_srv",
    "state_rcv_srv",
    "state_fwd_clt"
};

char *errs_str[] = {
    "err_generic",
    "err_mem",
    "err_recv",
    "err_pars",
    "err_parstitle",
    "err_parsheader",
    "err_support"
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
