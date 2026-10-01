// Host-native mock of lwip/opt.h
#ifndef MOCK_LWIP_OPT_H
#define MOCK_LWIP_OPT_H

#include "lwip/arch.h"

#define LWIP_IPV4               1
#define LWIP_IPV6               1
#define TCP_MSS                 1436
#define TCP_SND_BUF             (4 * TCP_MSS)
#define LWIP_TCPIP_CORE_LOCKING 1

#endif
