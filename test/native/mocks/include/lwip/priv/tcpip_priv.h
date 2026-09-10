// Host-native mock of lwip/priv/tcpip_priv.h.
//
// We always model the CONFIG_LWIP_TCPIP_CORE_LOCKING flavour of tcpip_api_call:
// it simply invokes the callback on the calling thread. That makes the whole
// library deterministic and single-threaded under test.
#ifndef MOCK_LWIP_TCPIP_PRIV_H
#define MOCK_LWIP_TCPIP_PRIV_H

#include "lwip/err.h"
#include "lwip/tcpip.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcpip_api_call_data {
  u8_t dummy;
};

typedef err_t (*tcpip_api_call_fn)(struct tcpip_api_call_data *call);

err_t tcpip_api_call(tcpip_api_call_fn fn, struct tcpip_api_call_data *call);

#ifdef __cplusplus
}
#endif

#endif
