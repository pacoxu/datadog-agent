#ifndef __PROTOCOL_CLASSIFICATION_DEFS_H
#define __PROTOCOL_CLASSIFICATION_DEFS_H

#include <linux/types.h>

#define HTTP2_MARKER_SIZE 24

typedef enum __attribute__ ((packed)) {
    PROTOCOL_UNKNOWN = 0,
    PROTOCOL_HTTP = 1,
    PROTOCOL_HTTP2 = 2,
    //  Add new protocols before that line.
    MAX_PROTOCOLS,
    __MAX_UINT16 = 65536,
} protocol_t;

typedef struct {
    __u32 tcp_seq;
    protocol_t protocol;
} connection_state_t;

#endif
