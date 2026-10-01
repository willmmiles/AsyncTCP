// Test-facing control surface for the mock lwIP stack.
//
// This header is for tests only -- the library never sees it.
#ifndef ASYNCTCP_MOCK_LWIP_H
#define ASYNCTCP_MOCK_LWIP_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "lwip/dns.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
}

namespace mocklwip {

// ---------------------------------------------------------------------------
// Call recording
// ---------------------------------------------------------------------------
struct Call {
  std::string fn;   // "tcp_close", "tcp_recved", ...
  const void *pcb;  // pcb the call targeted, or nullptr
  long a;           // first scalar argument (len, port, backlog, err, ...)
  long b;           // second scalar argument (apiflags, ...)
};

size_t count(const char *fn);
size_t count(const char *fn, const void *pcb);
// Nth (0-based) recorded call to <fn>, or nullptr.
const Call *nth(const char *fn, size_t n);
// Total bytes handed to tcp_recved() for <pcb>: how much window was reopened.
size_t recved(const tcp_pcb *pcb);

// ---------------------------------------------------------------------------
// Resource accounting
// ---------------------------------------------------------------------------
void reset();  // free everything and clear the log; call between tests

size_t live_pcbs();
std::vector<tcp_pcb *> pcbs();
bool is_live(const tcp_pcb *pcb);
// The pcb handed to the most recent tcp_connect(), or nullptr. It may since have been
// freed, so check is_live() before dereferencing.
tcp_pcb *dialled_pcb();
size_t live_pbufs();

// Everything a pcb was handed to tcp_write(), in order.
std::string written(const tcp_pcb *pcb);

// Empties <pcb>'s send buffer and resizes it, with the queue limit lwIP would derive
// for that TCP_SND_BUF.  Above 65535 only with LWIP_WND_SCALE.
void set_send_buffer(tcp_pcb *pcb, uint32_t size);

// How many times the TCPIP core lock is held.  0 whenever no api call is running.
int core_lock_depth();

// ---------------------------------------------------------------------------
// Failure injection. All are reset by reset().
// ---------------------------------------------------------------------------
struct Faults {
  err_t write_result = 0;   // ERR_OK; set ERR_MEM to fail tcp_write
  err_t output_result = 0;  // ERR_OK
  err_t dns_result = 0;     // ERR_OK (immediate) or an error
  uint32_t dns_addr = 0;    // address returned for an immediate ERR_OK lookup
};
Faults &faults();

// ---------------------------------------------------------------------------
// Driving lwIP callbacks (i.e. playing the part of the lwIP thread).
//
// These call straight into the callbacks the library registered, exactly as
// lwIP would. Nothing is delivered to the application until you then call
// asynctcp_test_pump().
// ---------------------------------------------------------------------------

// Completes a connect: moves the pcb to ESTABLISHED (when err == ERR_OK) and
// invokes the tcp_connected_fn passed to tcp_connect().
err_t fire_connected(tcp_pcb *pcb, err_t err = 0);

// Fatal error. Models lwIP faithfully: the pcb is freed *and then* the error
// callback runs, so the pcb pointer is dangling by the time the library sees
// it. Any pointer you hold to `pcb` is invalid after this returns.
void fire_error(tcp_pcb *pcb, err_t err);

// Delivers <len> bytes to tcp_recv_fn. Allocates the pbuf for you.
err_t fire_recv(tcp_pcb *pcb, const void *data, size_t len, err_t err = 0);
// Remote FIN: tcp_recv_fn with a NULL pbuf.
err_t fire_fin(tcp_pcb *pcb, err_t err = 0);

err_t fire_sent(tcp_pcb *pcb, uint16_t len);

// Builds a fresh ESTABLISHED pcb and offers it to the listening pcb's
// tcp_accept_fn. Returns the new pcb (which may already have been freed by the
// library, so check is_live() before dereferencing).  As in lwIP, a return other than
// ERR_OK or ERR_ABRT aborts the new pcb.  The peer is 10.0.0.2:40000 unless given.  The
// local address is the listener's.
tcp_pcb *fire_accept(tcp_pcb *listen_pcb, err_t err = 0);
tcp_pcb *fire_accept(tcp_pcb *listen_pcb, const ip_addr_t &peer, uint16_t port, err_t err = 0);

// Non-zero if the library made an api call while standing on the LwIP thread, which on a
// real target would deadlock.
unsigned reentrant_api_calls();

// Calls into tcp_* or dns_* made neither on the LwIP thread nor under the TCPIP core
// lock, which on a real target race the LwIP thread.  The first one's name.
unsigned unlocked_calls();
const char *first_unlocked_call();

// Callbacks handed a pcb that returned ERR_ABRT without aborting it, or anything else
// after aborting it; lwIP would then leak the pcb or use it after free.  The first one.
unsigned callback_return_violations();
const char *first_callback_return_violation();

}  // namespace mocklwip

#endif
