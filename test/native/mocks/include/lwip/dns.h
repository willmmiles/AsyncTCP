// Host-native mock of lwip/dns.h
#ifndef MOCK_LWIP_DNS_H
#define MOCK_LWIP_DNS_H

#include "lwip/arch.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dns_found_callback)(const char *name, const ip_addr_t *ipaddr, void *callback_arg);

#define LWIP_DNS_ADDRTYPE_IPV4 0
#define LWIP_DNS_ADDRTYPE_IPV6 1
#define LWIP_DNS_ADDRTYPE_IPV4_IPV6 2
#define LWIP_DNS_ADDRTYPE_IPV6_IPV4 3
#define LWIP_DNS_ADDRTYPE_DEFAULT LWIP_DNS_ADDRTYPE_IPV4_IPV6

err_t dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *callback_arg);
err_t dns_gethostbyname_addrtype(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *callback_arg, u8_t dns_addrtype);

#ifdef __cplusplus
}
#endif

#endif
