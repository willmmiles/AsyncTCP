// Host-native mock of lwip/tcpip.h
#ifndef MOCK_LWIP_TCPIP_H
#define MOCK_LWIP_TCPIP_H

#include "lwip/err.h"
#include "lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_CORE_LOCK_QUERY_HOLDER 2

// The mock is single-threaded: the "TCPIP core lock" is a plain recursion
// counter so the library's lock/unlock bookkeeping still balances.
int sys_thread_tcpip(int type);
void mock_lock_tcpip_core(void);
void mock_unlock_tcpip_core(void);

#define LOCK_TCPIP_CORE() mock_lock_tcpip_core()
#define UNLOCK_TCPIP_CORE() mock_unlock_tcpip_core()

#ifdef __cplusplus
}
#endif

#endif
