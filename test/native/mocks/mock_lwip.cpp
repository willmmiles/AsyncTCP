// Implementation of the mock lwIP stack.
//
// Behaviour is modelled on real lwIP wherever it matters for AsyncTCP:
//   * tcp_abort() frees the pcb and *then* runs the error callback
//   * tcp_close() frees the pcb only when it returns ERR_OK
//   * tcp_listen_with_backlog() frees the old pcb and returns a NEW one on
//     success, and returns NULL *without* freeing on failure
//   * a fatal error frees the pcb before the error callback sees it
// Those are exactly the edges AsyncTCP's lifetime handling gets wrong or right.

#include "mock_lwip.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

extern "C" {
#include "lwip/inet.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/tcpip.h"
}

namespace {

std::vector<mocklwip::Call> g_calls;
std::set<tcp_pcb *> g_pcbs;
std::set<pbuf *> g_pbufs;
std::map<const tcp_pcb *, std::string> g_written;
std::set<uint16_t> g_ports;
std::map<const tcp_pcb *, uint16_t> g_pcb_port;  // ports this pcb holds
mocklwip::Faults g_faults;
uint16_t g_next_ephemeral = 49152;
int g_core_lock_depth = 0;

struct PendingDns {
  bool active = false;
  std::string host;
  dns_found_callback cb = nullptr;
  void *arg = nullptr;
};
PendingDns g_dns;

void rec(const char *fn, const void *pcb = nullptr, long a = 0, long b = 0, const std::string &text = std::string()) {
  g_calls.push_back(mocklwip::Call{fn, pcb, a, b, text});
}

void release_port(const tcp_pcb *pcb) {
  auto it = g_pcb_port.find(pcb);
  if (it != g_pcb_port.end()) {
    g_ports.erase(it->second);
    g_pcb_port.erase(it);
  }
}

tcp_pcb *alloc_pcb() {
  tcp_pcb *pcb = new tcp_pcb();
  memset(pcb, 0, sizeof(*pcb));
  pcb->state = CLOSED;
  pcb->mss = TCP_MSS;
  pcb->snd_buf = TCP_SND_BUF;
  pcb->prio = TCP_PRIO_NORMAL;
  pcb->local_ip.type = IPADDR_TYPE_V4;
  pcb->remote_ip.type = IPADDR_TYPE_V4;
  g_pcbs.insert(pcb);
  return pcb;
}

void free_pcb(tcp_pcb *pcb) {
  if (!pcb) {
    return;
  }
  release_port(pcb);
  g_written.erase(pcb);
  g_pcbs.erase(pcb);
  delete pcb;
}

}  // namespace

// ===========================================================================
// lwIP globals
// ===========================================================================
extern "C" {
struct tcp_pcb *tcp_bound_pcbs = nullptr;
struct tcp_pcb *tcp_active_pcbs = nullptr;
struct tcp_pcb *tcp_tw_pcbs = nullptr;
const ip_addr_t ip_addr_any_type = {{{{0, 0, 0, 0}, 0}}, IPADDR_TYPE_ANY};
}

// ===========================================================================
// pbuf
// ===========================================================================
extern "C" struct pbuf *pbuf_alloc(pbuf_layer, u16_t length, pbuf_type) {
  if (g_faults.fail_pbuf_alloc > 0) {
    g_faults.fail_pbuf_alloc--;
    rec("pbuf_alloc", nullptr, length, 0, "FAIL");
    return nullptr;
  }
  pbuf *p = new pbuf();
  memset(p, 0, sizeof(*p));
  p->payload = length ? ::operator new(length) : nullptr;
  if (p->payload) {
    memset(p->payload, 0, length);
  }
  p->len = length;
  p->tot_len = length;
  p->ref = 1;
  p->type_internal = (u8_t)PBUF_RAM;
  g_pbufs.insert(p);
  rec("pbuf_alloc", nullptr, length);
  return p;
}

extern "C" void pbuf_realloc(struct pbuf *p, u16_t size) {
  if (p && size < p->len) {
    p->len = size;
    p->tot_len = size;
  }
}

extern "C" u8_t pbuf_free(struct pbuf *p) {
  u8_t freed = 0;
  while (p) {
    if (p->ref > 0) {
      p->ref--;
    }
    if (p->ref != 0) {
      break;
    }
    pbuf *next = p->next;
    if (p->payload) {
      ::operator delete(p->payload);
    }
    g_pbufs.erase(p);
    delete p;
    freed++;
    p = next;
  }
  return freed;
}

extern "C" void pbuf_ref(struct pbuf *p) {
  if (p) {
    p->ref++;
  }
}

extern "C" u16_t pbuf_clen(const struct pbuf *p) {
  u16_t n = 0;
  while (p) {
    n++;
    p = p->next;
  }
  return n;
}

extern "C" void pbuf_cat(struct pbuf *head, struct pbuf *tail) {
  if (!head || !tail) {
    return;
  }
  pbuf *p = head;
  while (p->next) {
    p->tot_len = (u16_t)(p->tot_len + tail->tot_len);
    p = p->next;
  }
  p->tot_len = (u16_t)(p->tot_len + tail->tot_len);
  p->next = tail;
}

extern "C" u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset) {
  u16_t copied = 0;
  u16_t left = len;
  for (const pbuf *q = p; q && left; q = q->next) {
    if (offset >= q->len) {
      offset = (u16_t)(offset - q->len);
      continue;
    }
    u16_t chunk = (u16_t)(q->len - offset);
    if (chunk > left) {
      chunk = left;
    }
    memcpy((char *)dataptr + copied, (const char *)q->payload + offset, chunk);
    copied = (u16_t)(copied + chunk);
    left = (u16_t)(left - chunk);
    offset = 0;
  }
  return copied;
}

// ===========================================================================
// tcp
// ===========================================================================
extern "C" struct tcp_pcb *tcp_new_ip_type(u8_t type) {
  if (g_faults.fail_tcp_new > 0) {
    g_faults.fail_tcp_new--;
    rec("tcp_new_ip_type", nullptr, type, 0, "FAIL");
    return nullptr;
  }
  tcp_pcb *pcb = alloc_pcb();
  pcb->local_ip.type = type;
  pcb->remote_ip.type = type;
  rec("tcp_new_ip_type", pcb, type);
  return pcb;
}

extern "C" struct tcp_pcb *tcp_new(void) {
  return tcp_new_ip_type(IPADDR_TYPE_V4);
}

extern "C" void tcp_arg(struct tcp_pcb *pcb, void *arg) {
  rec("tcp_arg", pcb, (long)(intptr_t)arg);
  if (pcb) {
    pcb->callback_arg = arg;
  }
}

extern "C" void tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv) {
  rec("tcp_recv", pcb, recv ? 1 : 0);
  if (pcb) {
    pcb->recv = recv;
  }
}

extern "C" void tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent) {
  rec("tcp_sent", pcb, sent ? 1 : 0);
  if (pcb) {
    pcb->sent = sent;
  }
}

extern "C" void tcp_err(struct tcp_pcb *pcb, tcp_err_fn err) {
  rec("tcp_err", pcb, err ? 1 : 0);
  if (pcb) {
    pcb->errf = err;
  }
}

extern "C" void tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept) {
  rec("tcp_accept", pcb, accept ? 1 : 0);
  if (pcb) {
    pcb->accept = accept;
  }
}

extern "C" void tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval) {
  rec("tcp_poll", pcb, poll ? 1 : 0, interval);
  if (pcb) {
    pcb->poll = poll;
    pcb->pollinterval = interval;
  }
}

extern "C" void tcp_setprio(struct tcp_pcb *pcb, u8_t prio) {
  rec("tcp_setprio", pcb, prio);
  if (pcb) {
    pcb->prio = prio;
  }
}

extern "C" err_t tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) {
  rec("tcp_bind", pcb, port, ipaddr ? (long)ipaddr->u_addr.ip4.addr : 0);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.bind_result != ERR_OK) {
    return g_faults.bind_result;
  }
  if (port == 0) {
    port = g_next_ephemeral++;
  }
  if (g_ports.count(port)) {
    return ERR_USE;
  }
  if (ipaddr) {
    pcb->local_ip = *ipaddr;
  }
  pcb->local_port = port;
  g_ports.insert(port);
  g_pcb_port[pcb] = port;
  return ERR_OK;
}

extern "C" struct tcp_pcb *tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err) {
  rec("tcp_listen_with_backlog", pcb, backlog);
  if (!pcb) {
    if (err) {
      *err = ERR_ARG;
    }
    return nullptr;
  }
  if (g_faults.listen_returns_null) {
    // Real lwIP leaves the caller's pcb alone when it cannot allocate the
    // listen pcb. Whoever called us still owns it.
    if (err) {
      *err = ERR_MEM;
    }
    return nullptr;
  }
  // Real lwIP swaps the pcb for a smaller listen pcb and frees the original.
  tcp_pcb *lpcb = alloc_pcb();
  lpcb->local_ip = pcb->local_ip;
  lpcb->local_port = pcb->local_port;
  lpcb->callback_arg = pcb->callback_arg;
  lpcb->state = LISTEN;
  lpcb->backlog = backlog;
  // Move the port reservation across before freeing the old pcb.
  auto it = g_pcb_port.find(pcb);
  if (it != g_pcb_port.end()) {
    g_pcb_port[lpcb] = it->second;
    g_pcb_port.erase(it);
  }
  g_written.erase(pcb);
  g_pcbs.erase(pcb);
  delete pcb;
  if (err) {
    *err = ERR_OK;
  }
  return lpcb;
}

extern "C" struct tcp_pcb *tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog) {
  return tcp_listen_with_backlog_and_err(pcb, backlog, nullptr);
}

extern "C" void tcp_backlog_delayed(struct tcp_pcb *pcb) {
  rec("tcp_backlog_delayed", pcb);
}

extern "C" void tcp_backlog_accepted(struct tcp_pcb *pcb) {
  rec("tcp_backlog_accepted", pcb);
}

extern "C" err_t tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port, tcp_connected_fn connected) {
  rec("tcp_connect", pcb, port, ipaddr ? (long)ipaddr->u_addr.ip4.addr : 0);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.connect_result != ERR_OK) {
    // lwIP does NOT free the pcb on a failed connect; the caller still owns it.
    return g_faults.connect_result;
  }
  if (ipaddr) {
    pcb->remote_ip = *ipaddr;
  }
  pcb->remote_port = port;
  pcb->connected = connected;
  pcb->state = SYN_SENT;
  if (pcb->local_port == 0) {
    uint16_t p = g_next_ephemeral++;
    pcb->local_port = p;
    g_ports.insert(p);
    g_pcb_port[pcb] = p;
  }
  return ERR_OK;
}

extern "C" err_t tcp_close(struct tcp_pcb *pcb) {
  rec("tcp_close", pcb, pcb ? (long)pcb->state : -1);
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.close_result != ERR_OK) {
    return g_faults.close_result;  // pcb stays allocated, as on the target
  }
  free_pcb(pcb);
  return ERR_OK;
}

extern "C" err_t tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx) {
  rec("tcp_shutdown", pcb, shut_rx, shut_tx);
  if (shut_rx && shut_tx) {
    return tcp_close(pcb);
  }
  return ERR_OK;
}

extern "C" void tcp_abort(struct tcp_pcb *pcb) {
  rec("tcp_abort", pcb, pcb ? (long)pcb->state : -1);
  if (!pcb) {
    return;
  }
  // lwIP frees the pcb and then reports ERR_ABRT through the error callback
  // (except for LISTEN pcbs, which have no error callback path).
  tcp_err_fn errf = (pcb->state == LISTEN) ? nullptr : pcb->errf;
  void *arg = pcb->callback_arg;
  free_pcb(pcb);
  if (errf) {
    errf(arg, ERR_ABRT);
  }
}

extern "C" err_t tcp_write(struct tcp_pcb *pcb, const void *dataptr, u16_t len, u8_t apiflags) {
  rec("tcp_write", pcb, len, apiflags, std::string((const char *)dataptr, dataptr ? len : 0));
  if (!pcb) {
    return ERR_ARG;
  }
  if (g_faults.write_result != ERR_OK) {
    return g_faults.write_result;
  }
  if (dataptr && len) {
    g_written[pcb].append((const char *)dataptr, len);
  }
  pcb->snd_buf = (u16_t)((pcb->snd_buf > len) ? (pcb->snd_buf - len) : 0);
  return ERR_OK;
}

extern "C" err_t tcp_output(struct tcp_pcb *pcb) {
  rec("tcp_output", pcb);
  if (!pcb) {
    return ERR_ARG;
  }
  return g_faults.output_result;
}

extern "C" void tcp_recved(struct tcp_pcb *pcb, u16_t len) {
  rec("tcp_recved", pcb, len);
  if (pcb) {
    pcb->snd_buf = (u16_t)((pcb->snd_buf + len > TCP_SND_BUF) ? TCP_SND_BUF : pcb->snd_buf + len);
  }
}

// ===========================================================================
// dns
// ===========================================================================
extern "C" err_t dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *callback_arg) {
  rec("dns_gethostbyname", nullptr, 0, 0, hostname ? hostname : "");
  if (g_faults.dns_result == ERR_OK) {
    if (addr) {
      memset(addr, 0, sizeof(*addr));
      addr->type = IPADDR_TYPE_V4;
      addr->u_addr.ip4.addr = g_faults.dns_addr;
    }
    return ERR_OK;
  }
  if (g_faults.dns_result == ERR_INPROGRESS) {
    g_dns.active = true;
    g_dns.host = hostname ? hostname : "";
    g_dns.cb = found;
    g_dns.arg = callback_arg;
    return ERR_INPROGRESS;
  }
  return g_faults.dns_result;
}

extern "C" err_t dns_gethostbyname_addrtype(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *callback_arg, u8_t) {
  return dns_gethostbyname(hostname, addr, found, callback_arg);
}

// ===========================================================================
// tcpip_api_call and the core lock
// ===========================================================================
extern "C" err_t tcpip_api_call(tcpip_api_call_fn fn, struct tcpip_api_call_data *call) {
  rec("tcpip_api_call");
  return fn(call);
}

extern "C" int sys_thread_tcpip(int) {
  // Report "we already hold the core lock" only when we actually do, so the
  // library's guard balances its own lock/unlock.
  return g_core_lock_depth > 0 ? 1 : 0;
}

extern "C" void mock_lock_tcpip_core(void) {
  g_core_lock_depth++;
}

extern "C" void mock_unlock_tcpip_core(void) {
  if (g_core_lock_depth > 0) {
    g_core_lock_depth--;
  }
}

// ===========================================================================
// misc
// ===========================================================================
extern "C" char *ip4addr_ntoa(const ip4_addr_t *addr) {
  static char buf[24];
  u32_t a = addr ? addr->addr : 0;
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (unsigned)((a >> 24) & 0xFF), (unsigned)((a >> 16) & 0xFF), (unsigned)((a >> 8) & 0xFF), (unsigned)(a & 0xFF));
  return buf;
}

extern "C" char *ipaddr_ntoa(const ip_addr_t *addr) {
  return ip4addr_ntoa(addr ? &addr->u_addr.ip4 : nullptr);
}

extern "C" char *ip6addr_ntoa(const ip6_addr_t *) {
  static char buf[8] = "::";
  return buf;
}

extern "C" const char *lwip_strerr(err_t err) {
  switch (err) {
    case ERR_OK: return "ERR_OK";
    case ERR_MEM: return "ERR_MEM";
    case ERR_RTE: return "ERR_RTE";
    case ERR_INPROGRESS: return "ERR_INPROGRESS";
    case ERR_USE: return "ERR_USE";
    case ERR_CONN: return "ERR_CONN";
    case ERR_ABRT: return "ERR_ABRT";
    case ERR_ARG: return "ERR_ARG";
    default: return "ERR_?";
  }
}

// ===========================================================================
// Test-facing API
// ===========================================================================
namespace mocklwip {

const std::vector<Call> &calls() {
  return g_calls;
}

size_t count(const char *fn) {
  size_t n = 0;
  for (const Call &c : g_calls) {
    if (c.fn == fn) {
      n++;
    }
  }
  return n;
}

size_t count(const char *fn, const void *pcb) {
  size_t n = 0;
  for (const Call &c : g_calls) {
    if (c.fn == fn && c.pcb == pcb) {
      n++;
    }
  }
  return n;
}

bool saw(const char *fn, const void *pcb, long a) {
  for (const Call &c : g_calls) {
    if (c.fn == fn && c.pcb == pcb && c.a == a) {
      return true;
    }
  }
  return false;
}

const Call *nth(const char *fn, size_t n) {
  for (const Call &c : g_calls) {
    if (c.fn == fn && n-- == 0) {
      return &c;
    }
  }
  return nullptr;
}

std::string dump_calls() {
  std::string out;
  char line[256];
  for (const Call &c : g_calls) {
    snprintf(line, sizeof(line), "  %-24s pcb=%p a=%ld b=%ld %s\n", c.fn.c_str(), c.pcb, c.a, c.b, c.text.c_str());
    out += line;
  }
  return out;
}

void reset() {
  g_calls.clear();
  for (pbuf *p : std::set<pbuf *>(g_pbufs)) {
    if (p->payload) {
      ::operator delete(p->payload);
    }
    delete p;
  }
  g_pbufs.clear();
  for (tcp_pcb *p : std::set<tcp_pcb *>(g_pcbs)) {
    delete p;
  }
  g_pcbs.clear();
  g_written.clear();
  g_ports.clear();
  g_pcb_port.clear();
  g_faults = Faults{};
  g_dns = PendingDns{};
  g_next_ephemeral = 49152;
  g_core_lock_depth = 0;
}

size_t live_pcbs() {
  return g_pcbs.size();
}

std::vector<tcp_pcb *> pcbs() {
  return std::vector<tcp_pcb *>(g_pcbs.begin(), g_pcbs.end());
}

bool is_live(const tcp_pcb *pcb) {
  return g_pcbs.count(const_cast<tcp_pcb *>(pcb)) != 0;
}

size_t live_pbufs() {
  return g_pbufs.size();
}

std::vector<uint16_t> bound_ports() {
  return std::vector<uint16_t>(g_ports.begin(), g_ports.end());
}

bool port_is_bound(uint16_t port) {
  return g_ports.count(port) != 0;
}

std::string written(const tcp_pcb *pcb) {
  auto it = g_written.find(pcb);
  return it == g_written.end() ? std::string() : it->second;
}

Faults &faults() {
  return g_faults;
}

pbuf *make_pbuf(const void *data, size_t len) {
  pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
  if (p && data && len) {
    memcpy(p->payload, data, len);
  }
  return p;
}

err_t fire_connected(tcp_pcb *pcb, err_t err) {
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  if (err == ERR_OK) {
    pcb->state = ESTABLISHED;
  }
  return pcb->connected ? pcb->connected(pcb->callback_arg, pcb, err) : ERR_OK;
}

void fire_error(tcp_pcb *pcb, err_t err) {
  if (!pcb || !is_live(pcb)) {
    return;
  }
  tcp_err_fn errf = pcb->errf;
  void *arg = pcb->callback_arg;
  // lwIP has already released the pcb by the time the callback runs.
  free_pcb(pcb);
  if (errf) {
    errf(arg, err);
  }
}

err_t fire_recv_pbuf(tcp_pcb *pcb, pbuf *p, err_t err) {
  if (!pcb || !is_live(pcb)) {
    if (p) {
      pbuf_free(p);
    }
    return ERR_ARG;
  }
  if (!pcb->recv) {
    if (p) {
      pbuf_free(p);
    }
    return ERR_OK;
  }
  return pcb->recv(pcb->callback_arg, pcb, p, err);
}

err_t fire_recv(tcp_pcb *pcb, const void *data, size_t len, err_t err) {
  return fire_recv_pbuf(pcb, make_pbuf(data, len), err);
}

err_t fire_fin(tcp_pcb *pcb, err_t err) {
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  if (pcb->state == ESTABLISHED) {
    pcb->state = CLOSE_WAIT;
  }
  return pcb->recv ? pcb->recv(pcb->callback_arg, pcb, nullptr, err) : ERR_OK;
}

err_t fire_sent(tcp_pcb *pcb, uint16_t len) {
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  pcb->snd_buf = (u16_t)((pcb->snd_buf + len > TCP_SND_BUF) ? TCP_SND_BUF : pcb->snd_buf + len);
  return pcb->sent ? pcb->sent(pcb->callback_arg, pcb, len) : ERR_OK;
}

err_t fire_poll(tcp_pcb *pcb) {
  if (!pcb || !is_live(pcb)) {
    return ERR_ARG;
  }
  return pcb->poll ? pcb->poll(pcb->callback_arg, pcb) : ERR_OK;
}

tcp_pcb *fire_accept(tcp_pcb *listen_pcb, err_t err) {
  if (!listen_pcb || !is_live(listen_pcb) || !listen_pcb->accept) {
    return nullptr;
  }
  tcp_pcb *newpcb = alloc_pcb();
  newpcb->state = ESTABLISHED;
  newpcb->local_ip = listen_pcb->local_ip;
  newpcb->local_port = listen_pcb->local_port;
  newpcb->remote_ip.type = IPADDR_TYPE_V4;
  newpcb->remote_ip.u_addr.ip4.addr = 0x0A000002;  // 10.0.0.2
  newpcb->remote_port = 40000;
  rec("accept_offered", newpcb, err);
  listen_pcb->accept(listen_pcb->callback_arg, newpcb, err);
  return newpcb;
}

bool dns_pending() {
  return g_dns.active;
}

std::string dns_pending_host() {
  return g_dns.host;
}

void fire_dns(uint32_t addr) {
  if (!g_dns.active) {
    return;
  }
  ip_addr_t a;
  memset(&a, 0, sizeof(a));
  a.type = IPADDR_TYPE_V4;
  a.u_addr.ip4.addr = addr;
  dns_found_callback cb = g_dns.cb;
  void *arg = g_dns.arg;
  g_dns.active = false;
  // g_dns.host stays alive: the library keeps the char* in its event and only
  // dereferences it while logging.
  if (cb) {
    cb(g_dns.host.c_str(), &a, arg);
  }
}

void fire_dns_failure() {
  if (!g_dns.active) {
    return;
  }
  dns_found_callback cb = g_dns.cb;
  void *arg = g_dns.arg;
  g_dns.active = false;
  if (cb) {
    cb(g_dns.host.c_str(), nullptr, arg);
  }
}

}  // namespace mocklwip
