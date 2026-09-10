// Host-native mock of lwip/ip4_addr.h
#ifndef MOCK_LWIP_IP4_ADDR_H
#define MOCK_LWIP_IP4_ADDR_H

#include "lwip/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ip4_addr {
  u32_t addr;  // network byte order on target; host order here (see README)
};
typedef struct ip4_addr ip4_addr_t;

#define IPADDR_ANY ((u32_t)0x00000000UL)
#define IPADDR_LOOPBACK ((u32_t)0x7f000001UL)
#define IPADDR_BROADCAST ((u32_t)0xffffffffUL)
#define IPADDR_NONE ((u32_t)0xffffffffUL)

#define ip4_addr_set_zero(ipaddr) ((ipaddr)->addr = 0)
#define ip4_addr_isany_val(ipaddr) ((ipaddr).addr == IPADDR_ANY)
#define ip4_addr_get_u32(src_ipaddr) ((src_ipaddr)->addr)
#define ip4_addr_set_u32(dest_ipaddr, src_u32) ((dest_ipaddr)->addr = (src_u32))

char *ip4addr_ntoa(const ip4_addr_t *addr);

#ifdef __cplusplus
}
#endif

#endif
