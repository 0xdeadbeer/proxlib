#ifndef STRUCTS_H
#define STRUCTS_H

#include "parslib/parslib.h"

#ifndef MAX_BOUND
#define MAX_BOUND 10000
#endif

#define PROXY_PORT 2020
#define PROXY_CONN 20

#define STATEM_RCV_CLT 0b00000001
#define STATEM_CON_SRV 0b00000010
#define STATEM_FWD_SRV 0b00000100
#define STATEM_RCV_SRV 0b00001000
#define STATEM_FWD_CLT 0b00010000
#define STATEM_ERR     0b00100000

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
