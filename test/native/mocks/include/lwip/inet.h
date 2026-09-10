// Host-native mock of lwip/inet.h
#ifndef MOCK_LWIP_INET_H
#define MOCK_LWIP_INET_H

#include "lwip/ip_addr.h"

#ifndef INADDR_ANY
#define INADDR_ANY IPADDR_ANY
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK IPADDR_LOOPBACK
#endif
#ifndef INADDR_BROADCAST
#define INADDR_BROADCAST IPADDR_BROADCAST
#endif
#ifndef INADDR_NONE
#define INADDR_NONE IPADDR_NONE
#endif

// The mock keeps addresses in host byte order throughout, so these are no-ops.
#define lwip_htons(x) (x)
#define lwip_ntohs(x) (x)
#define lwip_htonl(x) (x)
#define lwip_ntohl(x) (x)

#endif
