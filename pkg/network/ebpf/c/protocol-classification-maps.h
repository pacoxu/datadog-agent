#ifndef __PROTOCOL_CLASSIFICATION_MAPS_H
#define __PROTOCOL_CLASSIFICATION_MAPS_H

#include "protocol-classification-defs.h"
#include "bpf_helpers.h"
#include "map-defs.h"

BPF_LRU_MAP(connection_states, conn_tuple_t, connection_state_t, 1024)

/* Map used to store the sub program actually used by the socket filter.
 * This is done to avoid memory limitation when attaching a filter to
 * a socket.
 * See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Program-size-limit-for-socket-filters */
BPF_PROG_ARRAY(protocols_progs, MAX_PROTOCOLS)

#endif
