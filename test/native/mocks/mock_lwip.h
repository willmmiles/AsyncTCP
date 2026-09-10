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
  std::string fn;    // "tcp_close", "tcp_recved", ...
  const void *pcb;   // pcb the call targeted, or nullptr
  long a;            // first scalar argument (len, port, backlog, err, ...)
  long b;            // second scalar argument (apiflags, ...)
  std::string text;  // hostname / payload / anything stringy
};

const std::vector<Call> &calls();
size_t count(const char *fn);
size_t count(const char *fn, const void *pcb);
// True if <fn> was called on <pcb> with first scalar argument == a.
bool saw(const char *fn, const void *pcb, long a);
// Nth (0-based) recorded call to <fn>, or nullptr.
const Call *nth(const char *fn, size_t n);
// Human-readable dump of the call log; handy when a CHECK fails.
std::string dump_calls();

// ---------------------------------------------------------------------------
// Resource accounting
// ---------------------------------------------------------------------------
void reset();  // free everything and clear the log; call between tests

size_t live_pcbs();
std::vector<tcp_pcb *> pcbs();
bool is_live(const tcp_pcb *pcb);
size_t live_pbufs();
// Ports currently held by a bound or listening pcb.
std::vector<uint16_t> bound_ports();
bool port_is_bound(uint16_t port);

// Everything a pcb was handed to tcp_write(), in order.
std::string written(const tcp_pcb *pcb);

// ---------------------------------------------------------------------------
// Failure injection. All are reset by reset().
// ---------------------------------------------------------------------------
struct Faults {
  int fail_tcp_new = 0;         // >0: that many tcp_new_ip_type() calls return NULL
  err_t connect_result = 0;     // ERR_OK; set e.g. ERR_RTE to fail tcp_connect
  err_t bind_result = 0;        // ERR_OK
  err_t write_result = 0;       // ERR_OK; set ERR_MEM to fail tcp_write
  err_t output_result = 0;      // ERR_OK
  err_t close_result = 0;       // ERR_OK; non-OK leaves the pcb allocated
  bool listen_returns_null = false;
  int fail_pbuf_alloc = 0;      // >0: that many pbuf_alloc() calls return NULL
  err_t dns_result = 0;         // ERR_OK (immediate), ERR_INPROGRESS, or an error
  uint32_t dns_addr = 0;        // address returned for an immediate ERR_OK lookup
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
// Delivers an already-built pbuf chain (ownership passes to the library).
err_t fire_recv_pbuf(tcp_pcb *pcb, pbuf *p, err_t err = 0);
// Remote FIN: tcp_recv_fn with a NULL pbuf.
err_t fire_fin(tcp_pcb *pcb, err_t err = 0);

err_t fire_sent(tcp_pcb *pcb, uint16_t len);
err_t fire_poll(tcp_pcb *pcb);

// Builds a fresh ESTABLISHED pcb and offers it to the listening pcb's
// tcp_accept_fn. Returns the new pcb (which may already have been freed by the
// library, so check is_live() before dereferencing).
tcp_pcb *fire_accept(tcp_pcb *listen_pcb, err_t err = 0);

// Convenience: build a pbuf holding <len> bytes of <data>.
pbuf *make_pbuf(const void *data, size_t len);

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------
// True while a dns_gethostbyname() that returned ERR_INPROGRESS is outstanding.
bool dns_pending();
std::string dns_pending_host();
// Fire the deferred callback with a resolved address.
void fire_dns(uint32_t addr);
// Fire the deferred callback with NULL (failure / timeout).
void fire_dns_failure();

}  // namespace mocklwip

#endif
