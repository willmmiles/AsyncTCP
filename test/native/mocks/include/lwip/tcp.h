// Host-native mock of lwip/tcp.h.
//
// Only the parts AsyncTCP touches are modelled. The behavioural contract of the
// mocked functions is documented in test/native/mocks/mock_lwip.h.
#ifndef MOCK_LWIP_TCP_H
#define MOCK_LWIP_TCP_H

#include "lwip/arch.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/opt.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_pcb;

typedef err_t (*tcp_accept_fn)(void *arg, struct tcp_pcb *newpcb, err_t err);
typedef err_t (*tcp_recv_fn)(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
typedef err_t (*tcp_sent_fn)(void *arg, struct tcp_pcb *tpcb, u16_t len);
typedef err_t (*tcp_poll_fn)(void *arg, struct tcp_pcb *tpcb);
typedef void (*tcp_err_fn)(void *arg, err_t err);
typedef err_t (*tcp_connected_fn)(void *arg, struct tcp_pcb *tpcb, err_t err);

enum tcp_state {
  CLOSED = 0,
  LISTEN = 1,
  SYN_SENT = 2,
  SYN_RCVD = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1 = 5,
  FIN_WAIT_2 = 6,
  CLOSE_WAIT = 7,
  CLOSING = 8,
  LAST_ACK = 9,
  TIME_WAIT = 10
};

typedef u8_t tcpflags_t;
#define TF_ACK_DELAY 0x01U
#define TF_ACK_NOW 0x02U
#define TF_NODELAY 0x40U

// SOF_* socket options, as used by AsyncClient::setKeepAlive()
#define SOF_REUSEADDR 0x04U
#define SOF_KEEPALIVE 0x08U
#define SOF_BROADCAST 0x20U

struct tcp_pcb {
  ip_addr_t local_ip;
  ip_addr_t remote_ip;
  u8_t so_options;
  u8_t ttl;
  u8_t tos;

  enum tcp_state state;
  u8_t prio;
  void *callback_arg;

  u16_t local_port;
  u16_t remote_port;

  tcpflags_t flags;
  u16_t mss;
  u16_t snd_buf;
  u16_t snd_queuelen;

  u32_t keep_idle;
  u32_t keep_intvl;
  u32_t keep_cnt;

  u8_t backlog;
  u8_t polltmr;
  u8_t pollinterval;

  tcp_sent_fn sent;
  tcp_recv_fn recv;
  tcp_connected_fn connected;
  tcp_poll_fn poll;
  tcp_err_fn errf;
  tcp_accept_fn accept;

  struct tcp_pcb *next;
};

// Real lwIP exposes these lists; AsyncTCP inspects tcp_bound_pcbs on some branches.
extern struct tcp_pcb *tcp_bound_pcbs;
extern struct tcp_pcb *tcp_active_pcbs;
extern struct tcp_pcb *tcp_tw_pcbs;

struct tcp_pcb *tcp_new(void);
struct tcp_pcb *tcp_new_ip_type(u8_t type);

void tcp_arg(struct tcp_pcb *pcb, void *arg);
void tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv);
void tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent);
void tcp_err(struct tcp_pcb *pcb, tcp_err_fn err);
void tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept);
void tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval);

err_t tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port);
struct tcp_pcb *tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog);
struct tcp_pcb *tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err);
void tcp_backlog_delayed(struct tcp_pcb *pcb);
void tcp_backlog_accepted(struct tcp_pcb *pcb);

err_t tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port, tcp_connected_fn connected);
err_t tcp_close(struct tcp_pcb *pcb);
err_t tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx);
void tcp_abort(struct tcp_pcb *pcb);

err_t tcp_write(struct tcp_pcb *pcb, const void *dataptr, u16_t len, u8_t apiflags);
err_t tcp_output(struct tcp_pcb *pcb);
void tcp_recved(struct tcp_pcb *pcb, u16_t len);
void tcp_setprio(struct tcp_pcb *pcb, u8_t prio);

#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02

#define TCP_PRIO_MIN 1
#define TCP_PRIO_NORMAL 64
#define TCP_PRIO_MAX 127

#define TCP_DEFAULT_LISTEN_BACKLOG 0xff

// Real lwIP implements these as macros over pcb fields; keep that shape so tests
// can assert on the pcb directly.
#define tcp_sndbuf(pcb) ((pcb)->snd_buf)
#define tcp_sndqueuelen(pcb) ((pcb)->snd_queuelen)
#define tcp_mss(pcb) ((pcb)->mss)
#define tcp_nagle_disable(pcb) ((pcb)->flags = (tcpflags_t)((pcb)->flags | TF_NODELAY))
#define tcp_nagle_enable(pcb) ((pcb)->flags = (tcpflags_t)((pcb)->flags & (tcpflags_t)(~TF_NODELAY)))
#define tcp_nagle_disabled(pcb) (((pcb)->flags & TF_NODELAY) != 0)

#ifdef __cplusplus
}
#endif

#endif
