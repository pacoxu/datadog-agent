#ifndef __PROTOCOL_CLASSIFICATION_HELPERS_H
#define __PROTOCOL_CLASSIFICATION_HELPERS_H

#include <linux/types.h>

#include "tracer.h"
#include "protocol-classification-defs.h"

static __always_inline bool is_http2(const char* buf, __u32 buf_size) {
    if (buf_size < HTTP2_MARKER_SIZE) {
        return false;
    }

    if (buf == NULL) {
        return false;
    }

    uint8_t http2_prefix[] = {0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a};
    for (int i = 0; i < HTTP2_MARKER_SIZE; i++) {
        if (buf[i] != http2_prefix[i]) {
            return false;
        }
    }

    return true;
}

static __always_inline bool is_http(const char *buf, __u32 size) {
    if ((buf[0] == 'H') && (buf[1] == 'T') && (buf[2] == 'T') && (buf[3] == 'P')) {
        return true;
    } else if ((buf[0] == 'G') && (buf[1] == 'E') && (buf[2] == 'T') && (buf[3]  == ' ') && (buf[4] == '/')) {
        return true;
    } else if ((buf[0] == 'P') && (buf[1] == 'O') && (buf[2] == 'S') && (buf[3] == 'T') && (buf[4]  == ' ') && (buf[5] == '/')) {
        return true;
    } else if ((buf[0] == 'P') && (buf[1] == 'U') && (buf[2] == 'T') && (buf[3]  == ' ') && (buf[4] == '/')) {
        return true;
    } else if ((buf[0] == 'D') && (buf[1] == 'E') && (buf[2] == 'L') && (buf[3] == 'E') && (buf[4] == 'T') && (buf[5] == 'E') && (buf[6]  == ' ') && (buf[7] == '/')) {
        return true;
    } else if ((buf[0] == 'H') && (buf[1] == 'E') && (buf[2] == 'A') && (buf[3] == 'D') && (buf[4]  == ' ') && (buf[5] == '/')) {
        return true;
    } else if ((buf[0] == 'O') && (buf[1] == 'P') && (buf[2] == 'T') && (buf[3] == 'I') && (buf[4] == 'O') && (buf[5] == 'N') && (buf[6] == 'S') && (buf[7]  == ' ') && ((buf[8] == '/') || (buf[8] == '*'))) {
        return true;
    } else if ((buf[0] == 'P') && (buf[1] == 'A') && (buf[2] == 'T') && (buf[3] == 'C') && (buf[4] == 'H') && (buf[5]  == ' ') && (buf[6] == '/')) {
        return true;
    }

    return false;
}

static __always_inline void infer_protocol(protocol_t *protocol, const char *buf, __u32 size) {
    if (*protocol != PROTOCOL_UNKNOWN) {
        return;
    } else if (is_http(buf, size)) {
        log_debug("[protocol_classifier] hey - http\n");
        *protocol = PROTOCOL_HTTP;
    } else if (is_http2(buf, size)) {
        *protocol = PROTOCOL_HTTP2;
    }
}

static __always_inline bool has_sequence_seen_before(connection_state_t *connection_state, skb_info_t *skb_info) {
    if (!skb_info || !skb_info->tcp_seq) {
        return false;
    }

    // check if we've seen this TCP segment before. this can happen in the
    // context of localhost traffic where the same TCP segment can be seen
    // multiple times coming in and out from different interfaces
    if (connection_state->tcp_seq == skb_info->tcp_seq) {
        return true;
    }

    connection_state->tcp_seq = skb_info->tcp_seq;
    return false;
}

static __always_inline bool should_process_packet(struct __sk_buff *skb, skb_info_t *skb_info, conn_tuple_t *tup) {
    // we're only interested in TCP traffic
    if (!(tup->metadata&CONN_TYPE_TCP)) {
        return false;
    }

    // if payload data is empty we only
    // process it if the packet represents a TCP termination
    // TODO: guy, improve the following condition. If the payload is not empty, yet we should not parse it (encrypted, unidentified protocol) if that's TCP termination
    bool empty_payload = skb_info->data_off == skb->len;
    if (empty_payload && !(skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST))) {
        return false;
    }

    return true;
}
#endif
