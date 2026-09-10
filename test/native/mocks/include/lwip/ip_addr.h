// Host-native mock of lwip/ip_addr.h.
// Models the LWIP_IPV4 && LWIP_IPV6 layout, which is what AsyncTCP assumes
// (it touches `addr.type` and `addr.u_addr.ip4.addr`).
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

#define IP_IS_V4_VAL(ipaddr) ((ipaddr).type == IPADDR_TYPE_V4)
#define IP_IS_V6_VAL(ipaddr) ((ipaddr).type == IPADDR_TYPE_V6)
#define IP_IS_V4(ipaddr) (((ipaddr) == NULL) || IP_IS_V4_VAL(*(ipaddr)))
#define IP_IS_V6(ipaddr) (((ipaddr) != NULL) && IP_IS_V6_VAL(*(ipaddr)))
#define IP_SET_TYPE_VAL(ipaddr, iptype) ((ipaddr).type = (iptype))
#define IP_SET_TYPE(ipaddr, iptype)   \
  do {                                \
    if ((ipaddr) != NULL) {           \
      IP_SET_TYPE_VAL(*(ipaddr), iptype); \
    }                                 \
  } while (0)
#define IP_GET_TYPE(ipaddr) ((ipaddr)->type)

#define ip_2_ip4(ipaddr) (&((ipaddr)->u_addr.ip4))
#define ip_2_ip6(ipaddr) (&((ipaddr)->u_addr.ip6))
#define ip_addr_get_ip4_u32(ipaddr) ((ipaddr)->u_addr.ip4.addr)

#define ip_addr_set_zero(ipaddr)              \
  do {                                        \
    (ipaddr)->u_addr.ip6.addr[0] = 0;         \
    (ipaddr)->u_addr.ip6.addr[1] = 0;         \
    (ipaddr)->u_addr.ip6.addr[2] = 0;         \
    (ipaddr)->u_addr.ip6.addr[3] = 0;         \
    (ipaddr)->u_addr.ip6.zone = 0;            \
    (ipaddr)->type = IPADDR_TYPE_V4;          \
  } while (0)

#define ip_addr_isany_val(ipaddr) \
  (((ipaddr).type == IPADDR_TYPE_V4) ? ((ipaddr).u_addr.ip4.addr == 0) : 0)
#define ip_addr_isany(ipaddr) (((ipaddr) == NULL) || ip_addr_isany_val(*(ipaddr)))

#define IPADDR4_INIT(u32val) \
  { {{{u32val, 0, 0, 0}, 0}}, IPADDR_TYPE_V4 }
#define IPADDR6_INIT(a, b, c, d) \
  { {{{a, b, c, d}, 0}}, IPADDR_TYPE_V6 }
#define IPADDR6_INIT_HOST(a, b, c, d) IPADDR6_INIT(a, b, c, d)
#define IPADDR_ANY_TYPE_INIT \
  { {{{0, 0, 0, 0}, 0}}, IPADDR_TYPE_ANY }

extern const ip_addr_t ip_addr_any_type;
#define IP_ANY_TYPE (&ip_addr_any_type)

char *ipaddr_ntoa(const ip_addr_t *addr);

#ifdef __cplusplus
}
#endif

#endif
