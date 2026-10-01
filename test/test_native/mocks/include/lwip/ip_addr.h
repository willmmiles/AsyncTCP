// Host-native mock of lwip/ip_addr.h.
// As in lwIP built with both IPv4 and IPv6, ip_addr_t is a tagged union of the
// two families.
#ifndef MOCK_LWIP_IP_ADDR_H
#define MOCK_LWIP_IP_ADDR_H

#include "lwip/arch.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

enum lwip_ip_addr_type {
  IPADDR_TYPE_V4 = 0U,
  IPADDR_TYPE_V6 = 6U,
  IPADDR_TYPE_ANY = 46U
};

typedef struct ip_addr {
  union {
    ip6_addr_t ip6;
    ip4_addr_t ip4;
  } u_addr;
  u8_t type;
} ip_addr_t;

#define IP_SET_TYPE_VAL(ipaddr, iptype) ((ipaddr).type = (iptype))
#define IP_SET_TYPE(ipaddr, iptype)       \
  do {                                    \
    if ((ipaddr) != NULL) {               \
      IP_SET_TYPE_VAL(*(ipaddr), iptype); \
    }                                     \
  } while (0)

#define ip_2_ip4(ipaddr)            (&((ipaddr)->u_addr.ip4))
#define ip_addr_get_ip4_u32(ipaddr) ((ipaddr)->u_addr.ip4.addr)
#define ip_addr_set_ip4_u32(ipaddr, val)       \
  do {                                         \
    if (ipaddr) {                              \
      ip4_addr_set_u32(ip_2_ip4(ipaddr), val); \
      IP_SET_TYPE(ipaddr, IPADDR_TYPE_V4);     \
    }                                          \
  } while (0)
#define ip_addr_set_ip4_u32_val(ipaddr, val)    \
  do {                                          \
    ip4_addr_set_u32(ip_2_ip4(&(ipaddr)), val); \
    IP_SET_TYPE_VAL(ipaddr, IPADDR_TYPE_V4);    \
  } while (0)

#define IPADDR4_INIT(u32val) \
  { {{{u32val, 0, 0, 0}}}, IPADDR_TYPE_V4 }
#define IPADDR6_INIT(a, b, c, d) \
  { {{{a, b, c, d}}}, IPADDR_TYPE_V6 }

#ifdef __cplusplus
}
#endif

#endif
