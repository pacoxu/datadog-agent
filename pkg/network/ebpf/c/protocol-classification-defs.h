#ifndef __PROTOCOL_CLASSIFICATION_DEFS_H
#define __PROTOCOL_CLASSIFICATION_DEFS_H

#include <linux/types.h>

#define HTTP2_MARKER_SIZE 24

// The enum below represents all different protocols we know to classify.
// We set the size of the enum to be 16 bits, but adding max value (max uint16 which is 65535) and
// `__attribute__ ((packed))` to tell the compiler to use as minimum bits as needed. Due to our max
// value we will use 16 bits for the enum.
typedef enum {
    PROTOCOL_UNKNOWN = 0,
    PROTOCOL_HTTP,
    PROTOCOL_HTTP2,
    //  Add new protocols before that line.
    MAX_PROTOCOLS,
    __MAX_UINT16 = 65535,
} __attribute__ ((packed)) protocol_t;

#endif
