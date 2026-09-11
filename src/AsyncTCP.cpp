// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles

#include "AsyncTCP.h"
#include "AsyncTCPLogging.h"
#include "AsyncTCPSimpleIntrusiveList.h"

#include <memory>

/**
 * LibreTiny specific configurations
 */
#if defined(LIBRETINY)
#include <Arduino.h>
// LibreTiny does not support IDF - disable code that expects it to be available
#define ESP_IDF_VERSION_MAJOR (0)
// xTaskCreatePinnedToCore is not available, force single-core operation
#define CONFIG_FREERTOS_UNICORE 1
// ESP watchdog is not available
#undef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 0
#endif  // LIBRETINY

/**
 * Arduino specific configurations
 */
#if defined(ARDUINO) && !defined(LIBRETINY)
#include <Arduino.h>
#include <esp_idf_version.h>
#if (ESP_IDF_VERSION_MAJOR >= 5)
#include <NetworkInterface.h>
#endif  // ESP_IDF_VERSION_MAJOR
#endif  // ARDUINO

/**
 * ESP-IDF specific configurations
 */
#if !defined(LIBRETINY) && !defined(ARDUINO)
#include "esp_timer.h"
static unsigned long millis() {
  return (unsigned long)(esp_timer_get_time() / 1000ULL);
}
static unsigned long micros() {
  return static_cast<unsigned long>(esp_timer_get_time());
}
#endif  // !LIBRETINY && !ARDUINO

extern "C" {
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/inet.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
}

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#endif

// Required for:
// https://github.com/espressif/arduino-esp32/blob/3.0.3/libraries/Network/src/NetworkInterface.cpp#L37-L47

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_ESP_TASK_WDT_TIMEOUT_S) / 4)
#else
#define ASYNC_TCP_MAX_TASK_SLEEP portMAX_DELAY
#endif

#define async_tcp_log_elapsed(tag, statement)                          \
  {                                                                    \
    [[maybe_unused]]                                                   \
    const uint32_t s_time = micros();                                  \
    statement;                                                         \
    async_tcp_log_v("%s took %" PRIu32 " us", tag, micros() - s_time); \
  }

// https://github.com/espressif/arduino-esp32/issues/10526
namespace {
#ifdef CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
  bool do_lock;
  inline tcp_core_guard() : do_lock(!sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
    if (do_lock) {
      LOCK_TCPIP_CORE();
    }
  }
  inline ~tcp_core_guard() {
    if (do_lock) {
      UNLOCK_TCPIP_CORE();
    }
  }
  tcp_core_guard(const tcp_core_guard &) = delete;
  tcp_core_guard(tcp_core_guard &&) = delete;
  tcp_core_guard &operator=(const tcp_core_guard &) = delete;
  tcp_core_guard &operator=(tcp_core_guard &&) = delete;
} __attribute__((unused));
#else   // CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
} __attribute__((unused));
#endif  // CONFIG_LWIP_TCPIP_CORE_LOCKING
}  // anonymous namespace

#define INVALID_CLOSED_SLOT -1

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#define CONFIG_ASYNC_TCP_POLL_TIMER 1

/*
 * TCP/IP Event Task
 * */

typedef enum {
  LWIP_TCP_SENT,
  LWIP_TCP_RECV,
  LWIP_TCP_FIN,
  LWIP_TCP_ERROR,
  LWIP_TCP_POLL,
  LWIP_TCP_ACCEPT,
  LWIP_TCP_CONNECTED,
  LWIP_TCP_DNS
} lwip_tcp_event_t;

struct lwip_tcp_event_packet_t {
  lwip_tcp_event_packet_t *next;
  lwip_tcp_event_t event;
  std::shared_ptr<AsyncClientImpl> impl;  // keeps it alive for the life of the event
  union {
    struct {
      tcp_pcb *pcb;
      int8_t err;
    } connected;
    struct {
      int8_t err;
    } error;
    struct {
      tcp_pcb *pcb;
      uint16_t len;
    } sent;
    struct {
      tcp_pcb *pcb;
      pbuf *pb;
      int8_t err;
    } recv;
    struct {
      tcp_pcb *pcb;
      int8_t err;
    } fin;
    struct {
      tcp_pcb *pcb;
    } poll;
    struct {
      AsyncServer *server;
    } accept;
    struct {
      ip_addr_t addr;
      uint16_t port;
      bool resolved;
    } dns;
  };

  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, std::shared_ptr<AsyncClientImpl> _impl) : next(nullptr), event(_event), impl(std::move(_impl)){};
};

// Detail class for interacting with AsyncClient internals, but without exposing the API
class AsyncTCP_detail {
public:
  // Helper functions
  static void __attribute__((visibility("internal"))) handle_async_event(lwip_tcp_event_packet_t *event);

  // LwIP TCP event callbacks that (will) require privileged access
  static int8_t __attribute__((visibility("internal"))) tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, int8_t err);
  static int8_t __attribute__((visibility("internal"))) tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len);
  static void __attribute__((visibility("internal"))) tcp_error(void *arg, int8_t err);
  static int8_t __attribute__((visibility("internal"))) tcp_poll(void *arg, struct tcp_pcb *pcb);
  static int8_t __attribute__((visibility("internal"))) tcp_accept(void *arg, tcp_pcb *pcb, int8_t err);
  static void __attribute__((visibility("internal"))) tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg);
};

// Guard class for the global queue
namespace {

static SemaphoreHandle_t _async_queue_mutex = nullptr;

// The queue is only reachable through an AsyncClient or an AsyncServer, so creating the
// mutex in their constructors puts it ahead of every user.  Unsynchronized, in the same
// way _start_async_task() always has been: the first of those can only be constructed by
// application code, before the async task exists and before LwIP points at anything.
static bool _init_queue_mutex() {
  if (!_async_queue_mutex) {
    _async_queue_mutex = xSemaphoreCreateMutex();
    if (!_async_queue_mutex) {
      async_tcp_log_e("Failed to create the queue mutex");
    }
  }
  return _async_queue_mutex != nullptr;
}

class queue_mutex_guard {
  bool holds_mutex;

public:
  inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
  inline ~queue_mutex_guard() {
    if (holds_mutex) {
      xSemaphoreGive(_async_queue_mutex);
    }
  };
  inline explicit operator bool() const {
    return holds_mutex;
  };
};
}  // anonymous namespace

static SimpleIntrusiveList<lwip_tcp_event_packet_t> _async_queue;
static TaskHandle_t _async_service_task_handle = NULL;

/*
  Reference-counted client implementation.

  The AsyncClient facade is created and destroyed by the application, but LwIP and the
  event queue both hold pointers that outlive it.  Rather than give each of them its own
  liveness dance, every holder takes a reference:

    - the facade, for its whole life
    - each queued event
    - LwIP's callback argument, while a pcb is bound
    - an outstanding DNS lookup

  The count is guarded by _async_queue_mutex.  Because the callbacks live here rather
  than on the facade, they stay alive for the duration of a call: destroying an
  AsyncClient from inside its own callback no longer destroys the std::function that is
  currently executing.

  _facade is nulled when the application's object goes away.  Dispatch is gated on it,
  so a detached implementation runs no user code and simply drains.
*/
class AsyncClientImpl : public std::enable_shared_from_this<AsyncClientImpl> {
public:
  explicit AsyncClientImpl(AsyncClient *facade);
  ~AsyncClientImpl();

  AsyncClientImpl(const AsyncClientImpl &) = delete;
  AsyncClientImpl &operator=(const AsyncClientImpl &) = delete;

  AsyncClient *_facade;  // nulled once the application's object is destroyed

  tcp_pcb *_pcb;

  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;
  AcConnectHandler _discard_cb;
  void *_discard_cb_arg;
  AcAckHandler _sent_cb;
  void *_sent_cb_arg;
  AcErrorHandler _error_cb;
  void *_error_cb_arg;
  AcDataHandler _recv_cb;
  void *_recv_cb_arg;
  AcPacketHandler _pb_cb;
  void *_pb_cb_arg;
  AcTimeoutHandler _timeout_cb;
  void *_timeout_cb_arg;
  AcConnectHandler _poll_cb;
  void *_poll_cb_arg;

  bool _ack_pcb;
  uint32_t _tx_last_packet;
  uint32_t _rx_ack_len;
  uint32_t _rx_last_packet;
  uint32_t _rx_timeout;
  uint32_t _rx_last_ack;
  uint32_t _ack_timeout;
  uint16_t _connect_port;
  bool _dns_pending;              // a lookup is outstanding and holds a reference
  uint32_t _in_callback_ack_len;  // bytes handed to onData but not yet acked

  bool connect(ip_addr_t addr, uint16_t port);
  bool connect(const char *host, uint16_t port);
#ifdef ARDUINO
  bool connect(const IPAddress &ip, uint16_t port);
#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
  bool connect(const IPv6Address &ip, uint16_t port);
#endif
#endif
  void close();
  int8_t abort();
  bool free();

  bool canSend() const;
  size_t space() const;
  size_t add(const char *data, size_t size, uint8_t apiflags);
  bool send();
  size_t write(const char *data, size_t size, uint8_t apiflags);

  uint8_t state() const;
  bool connecting() const;
  bool connected() const;
  bool disconnecting() const;
  bool disconnected() const;
  bool freeable() const;
  void _abandonResolve();

  uint16_t getMss() const;
  uint32_t getRxTimeout() const;
  void setRxTimeout(uint32_t timeout);
  uint32_t getAckTimeout() const;
  void setAckTimeout(uint32_t timeout);
  void setNoDelay(bool nodelay) const;
  bool getNoDelay();
  void setKeepAlive(uint32_t ms, uint8_t cnt);

  uint32_t getRemoteAddress() const;
  uint16_t getRemotePort() const;
  uint32_t getLocalAddress() const;
  uint16_t getLocalPort() const;
  ip4_addr_t getRemoteAddress4() const;
  ip4_addr_t getLocalAddress4() const;
#if LWIP_IPV6
  ip6_addr_t getRemoteAddress6() const;
  ip6_addr_t getLocalAddress6() const;
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
  IPv6Address remoteIP6() const;
  IPv6Address localIP6() const;
#else
  IPAddress remoteIP6() const;
  IPAddress localIP6() const;
#endif
#endif
#endif
#ifdef ARDUINO
  IPAddress remoteIP() const;
  IPAddress localIP() const;
#endif

  void ackPacket(struct pbuf *pb);
  size_t ack(size_t len);
  void ackLater();
  const char *stateToString() const;

  void _adopt(tcp_pcb *pcb);
  int8_t _connected(tcp_pcb *pcb, int8_t err);
  void _error(int8_t err);
  int8_t _poll(tcp_pcb *pcb);
  int8_t _sent(tcp_pcb *pcb, uint16_t len);
  int8_t _fin(tcp_pcb *pcb, int8_t err);
  int8_t _recv(tcp_pcb *pcb, pbuf *pb, int8_t err);
  void _dns_found(bool resolved, ip_addr_t *ipaddr, uint16_t port);
};

static uint32_t _xor_shift_state = 31;  // any nonzero seed will do
static uint32_t _xor_shift_next() {
  uint32_t x = _xor_shift_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return _xor_shift_state = x;
}

static void _free_event(lwip_tcp_event_packet_t *evpkt) {
  if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pb != nullptr)) {
    pbuf_free(evpkt->recv.pb);
  }
  delete evpkt;  // releases the event's reference to the implementation
}

static inline void _send_async_event(lwip_tcp_event_packet_t *e) {
  if (e == nullptr) {
    return;
  }
  _async_queue.push_back(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline void _prepend_async_event(lwip_tcp_event_packet_t *e) {
  if (e == nullptr) {
    return;
  }
  _async_queue.push_front(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline lwip_tcp_event_packet_t *_get_async_event() {
  lwip_tcp_event_packet_t *result = nullptr;
  // Discarded events are freed once the mutex is released: _free_event() drops the
  // implementation's reference, and that takes this same non-recursive mutex.
  lwip_tcp_event_packet_t *discarded = nullptr;

  {
    queue_mutex_guard guard;
    while (1) {
      lwip_tcp_event_packet_t *e = _async_queue.pop_front();

      if ((!e) || (e->event != LWIP_TCP_POLL)) {
        result = e;
        break;
      }

      /*
      Let's try to coalesce two (or more) consecutive poll events into one
      this usually happens with poor implemented user-callbacks that are runs too long and makes poll events to stack in the queue
      if consecutive user callback for a same connection runs longer that poll time then it will fill the queue with events until it deadlocks.
      This is a workaround to mitigate such poor designs and won't let other events/connections to starve the task time.
      It won't be effective if user would run multiple simultaneous long running callbacks due to message interleaving.
      todo: implement some kind of fair dequeuing or (better) simply punish user for a bad designed callbacks by resetting hog connections
    */
      for (lwip_tcp_event_packet_t *next_pkt = _async_queue.begin(); next_pkt && (next_pkt->impl == e->impl) && (next_pkt->event == LWIP_TCP_POLL);
           next_pkt = _async_queue.begin()) {
        // if the next event that will come is a poll event for the same connection, we can discard it and continue
        auto dup = _async_queue.pop_front();
        dup->next = discarded;
        discarded = dup;
        async_tcp_log_d("coalescing polls, network congestion or async callbacks might be too slow!");
      }

      /*
      now we have to decide if to proceed with poll callback handler or discard it?
      poor designed apps using asynctcp without proper dataflow control could flood the queue with interleaved pool/ack events.
      I.e. on each poll app would try to generate more data to send, which in turn results in additional ack event triggering chain effect
      for long connections. Or poll callback could take long time starving other connections. Anyway our goal is to keep the queue length
      grows under control (if possible) and poll events are the safest to discard.
      Let's discard poll events processing using linear-increasing probability curve when queue size grows over 3/4
      Poll events are periodic and connection could get another chance next time
    */
      if (_async_queue.size() > (_xor_shift_next() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 4 + CONFIG_ASYNC_TCP_QUEUE_SIZE * 3 / 4)) {
        e->next = discarded;
        discarded = e;
        async_tcp_log_d("discarding poll due to queue congestion");
        continue;
      }

      result = e;
      break;
    }
  }

  while (discarded) {
    auto t = discarded;
    discarded = t->next;
    _free_event(t);
  }
  return result;
}

static size_t _remove_events_for_client(AsyncClientImpl *client) {
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([=](lwip_tcp_event_packet_t &pkt) {
      return pkt.impl.get() == client;
    });
  }

  size_t count = 0;
  while (removed_event_chain) {
    ++count;
    auto t = removed_event_chain;
    removed_event_chain = t->next;
    _free_event(t);
  }
  return count;
};

// Called from AsyncServer::end() on the application thread, so it can destroy any
// clients that were accepted but never delivered to onClient.
static size_t _remove_events_for_server(AsyncServer *server) {
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([=](lwip_tcp_event_packet_t &pkt) {
      return (pkt.event == LWIP_TCP_ACCEPT) && (pkt.accept.server == server);
    });
  }

  size_t count = 0;
  while (removed_event_chain) {
    ++count;
    auto t = removed_event_chain;
    removed_event_chain = t->next;
    delete t->impl->_facade;
    _free_event(t);
  }
  return count;
};

void AsyncTCP_detail::handle_async_event(lwip_tcp_event_packet_t *e) {
  // A detached implementation has no facade to hand to the user's callbacks, so its
  // events simply drain.  The reference the event holds keeps it alive until then.
  if ((e->impl == NULL) || (e->impl->_facade == NULL)) {
    // ets_printf("event arg == NULL: 0x%08x\n", e->recv.pcb);
  } else if (e->event == LWIP_TCP_RECV) {
    // ets_printf("-R: 0x%08x\n", e->recv.pcb);
    e->impl->_recv(e->recv.pcb, e->recv.pb, e->recv.err);
    e->recv.pb = nullptr;  // given to client
  } else if (e->event == LWIP_TCP_FIN) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    e->impl->_fin(e->fin.pcb, e->fin.err);
  } else if (e->event == LWIP_TCP_SENT) {
    // ets_printf("-S: 0x%08x\n", e->sent.pcb);
    e->impl->_sent(e->sent.pcb, e->sent.len);
  } else if (e->event == LWIP_TCP_POLL) {
    // ets_printf("-P: 0x%08x\n", e->poll.pcb);
    e->impl->_poll(e->poll.pcb);
  } else if (e->event == LWIP_TCP_ERROR) {
    // ets_printf("-E: 0x%08x %d\n", e->impl, e->error.err);
    e->impl->_error(e->error.err);
  } else if (e->event == LWIP_TCP_CONNECTED) {
    // ets_printf("C: 0x%08x 0x%08x %d\n", e->impl, e->connected.pcb, e->connected.err);
    e->impl->_connected(e->connected.pcb, e->connected.err);
  } else if (e->event == LWIP_TCP_ACCEPT) {
    // ets_printf("A: 0x%08x 0x%08x\n", e->impl, e->accept.server);
    // Gated above, so the facade is still alive
    e->accept.server->_accepted(e->impl->_facade);
  } else if (e->event == LWIP_TCP_DNS) {
    // ets_printf("D: 0x%08x = %s\n", e->impl, ipaddr_ntoa(&e->dns.addr));
    e->impl->_dns_found(e->dns.resolved, &e->dns.addr, e->dns.port);
  }
  _free_event(e);
}

static void _async_service_task(void *pvParameters) {
  async_tcp_log_d("Task 'async_tcp' started on core %d", static_cast<int>(xPortGetCoreID()));
#if CONFIG_ASYNC_TCP_USE_WDT
  if (esp_task_wdt_add(NULL) != ESP_OK) {
    async_tcp_log_w("Failed to add async task to WDT");
  }
#endif
  for (;;) {
    while (auto packet = _get_async_event()) {
      async_tcp_log_elapsed("handle_async_event", AsyncTCP_detail::handle_async_event(packet));
#if CONFIG_ASYNC_TCP_USE_WDT
      esp_task_wdt_reset();
#endif
    }
    // queue is empty
    // DEBUG_PRINTF("Async task waiting 0x%08",(intptr_t)_async_queue_head);
    ulTaskNotifyTake(pdTRUE, ASYNC_TCP_MAX_TASK_SLEEP);
    // DEBUG_PRINTF("Async task woke = %d 0x%08x",q, (intptr_t)_async_queue_head);
#if CONFIG_ASYNC_TCP_USE_WDT
    esp_task_wdt_reset();
#endif
  }
#if CONFIG_ASYNC_TCP_USE_WDT
  esp_task_wdt_delete(NULL);
#endif
  vTaskDelete(NULL);
  _async_service_task_handle = NULL;
}

/*
static void _stop_async_task(){
    if(_async_service_task_handle){
        vTaskDelete(_async_service_task_handle);
        _async_service_task_handle = NULL;
    }
}
*/

static bool customTaskCreateUniversal(
  TaskFunction_t pxTaskCode, const char *const pcName, const uint32_t usStackDepth, void *const pvParameters, UBaseType_t uxPriority,
  TaskHandle_t *const pxCreatedTask, const BaseType_t xCoreID
) {
#ifndef CONFIG_FREERTOS_UNICORE
  if (xCoreID >= 0 && xCoreID < 2) {
    return xTaskCreatePinnedToCore(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask, xCoreID);
  } else {
#endif
    return xTaskCreate(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask);
#ifndef CONFIG_FREERTOS_UNICORE
  }
#endif
}

static bool _start_async_task() {
  if (!_init_queue_mutex()) {
    return false;
  }

  if (!_async_service_task_handle) {
    customTaskCreateUniversal(
      _async_service_task, "async_tcp", CONFIG_ASYNC_TCP_STACK_SIZE, NULL, CONFIG_ASYNC_TCP_PRIORITY, &_async_service_task_handle, CONFIG_ASYNC_TCP_RUNNING_CORE
    );
    if (!_async_service_task_handle) {
      return false;
    }
  }
  return true;
}

/*
 * LwIP Callbacks
 * */

// The binding is the implementation's own state: _pcb is non-null for exactly as long
// as LwIP points at us, so nothing else has to track it.  What keeps the implementation
// alive while it is bound is that ~AsyncClient() must close() first, and close() is an
// api call - it cannot run concurrently with a callback.
static void _bind_tcp_callbacks(tcp_pcb *pcb, AsyncClientImpl *client) {
  tcp_arg(pcb, client);
  tcp_recv(pcb, &AsyncTCP_detail::tcp_recv);
  tcp_sent(pcb, &AsyncTCP_detail::tcp_sent);
  tcp_err(pcb, &AsyncTCP_detail::tcp_error);
  tcp_poll(pcb, &AsyncTCP_detail::tcp_poll, CONFIG_ASYNC_TCP_POLL_TIMER);
}

static void _reset_tcp_callbacks(tcp_pcb *pcb, AsyncClientImpl *client) {
  tcp_arg(pcb, NULL);
  tcp_sent(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  if (client) {
    _remove_events_for_client(client);
  }
}

static int8_t _tcp_connected(void *arg, tcp_pcb *pcb, int8_t err) {
  // ets_printf("+C: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CONNECTED, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->connected.pcb = pcb;
  e->connected.err = err;
  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_poll(void *arg, struct tcp_pcb *pcb) {
  // throttle polling events queueing when event queue is getting filled up, let it handle _onack's
  {
    queue_mutex_guard guard;
    // async_tcp_log_d("qs:%u", _async_queue.size());
    if (_async_queue.size() > (_xor_shift_next() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 2 + CONFIG_ASYNC_TCP_QUEUE_SIZE / 4)) {
      async_tcp_log_d("throttling");
      return ERR_OK;
    }
  }

  // ets_printf("+P: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_POLL, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->poll.pcb = pcb;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, int8_t err) {
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_RECV, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  if (pb) {
    // ets_printf("+R: 0x%08x\n", pcb);
    e->recv.pcb = pcb;
    e->recv.pb = pb;
    e->recv.err = err;
  } else {
    // ets_printf("+F: 0x%08x\n", pcb);
    e->event = LWIP_TCP_FIN;
    e->fin.pcb = pcb;
    e->fin.err = err;
  }

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len) {
  // ets_printf("+S: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_SENT, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->sent.pcb = pcb;
  e->sent.len = len;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

void AsyncTCP_detail::tcp_error(void *arg, int8_t err) {
  // ets_printf("+E: 0x%08x\n", arg);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  if ((client == nullptr) || (client->_pcb == nullptr)) {
    // Not the client that owns this pcb: there is nothing to report, and LwIP's
    // reference was already released when we forgot the pcb.
    async_tcp_log_e("error callback for a client with no pcb");
    return;
  }

  // The pcb has already been freed by LwIP; do not attempt to clear the callbacks!
  _remove_events_for_client(client);

  // enqueue event to be processed in the async task for the user callback
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, client->shared_from_this()};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
  } else {
    e->error.err = err;
  }

  {
    queue_mutex_guard guard;
    client->_pcb = nullptr;
    _send_async_event(e);  // no-op if the allocation failed
  }
  // Nothing may touch the client past this point.  Clearing _pcb above released the
  // binding, so ~AsyncClient() is free to drop the last reference as soon as it reads
  // _pcb as null - and it can only reach that read through the mutex just released.
}

void AsyncTCP_detail::tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg) {
  // ets_printf("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
  // 'name' points into LwIP's DNS table, which the next lookup recycles; don't keep it.
  (void)name;
  // LwIP cannot cancel a lookup, but it does promise exactly one callback, so the
  // context is ours to destroy here.  It is a weak reference: an AsyncClient that goes
  // away mid-lookup is not kept alive waiting for an answer nobody wants.
  std::unique_ptr<std::weak_ptr<AsyncClientImpl>> callback_state(reinterpret_cast<std::weak_ptr<AsyncClientImpl> *>(arg));
  auto client = callback_state->lock();
  if (!client) {
    return;  // the implementation was destroyed while the lookup was in flight
  }

  bool wanted;
  {
    queue_mutex_guard guard;
    wanted = client->_dns_pending;
    client->_dns_pending = false;
  }
  if (!wanted) {
    return;  // close() or abort() gave up on this lookup while it was in flight
  }

  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DNS, client};
  if (!e) {
    async_tcp_log_e("Failed to allocate event packet");
  } else {
    e->dns.port = client->_connect_port;
    e->dns.resolved = (ipaddr != nullptr);
    if (ipaddr) {
      memcpy(&e->dns.addr, ipaddr, sizeof(ip_addr_t));
    } else {
      memset(&e->dns.addr, 0, sizeof(e->dns.addr));
    }
  }

  queue_mutex_guard guard;
  _send_async_event(e);  // no-op if the allocation failed
}

/*
 * TCP/IP API Calls
 * */

#include "lwip/priv/tcpip_priv.h"

typedef struct {
  struct tcpip_api_call_data call;
  tcp_pcb **pcb;
  int8_t err;
  union {
    AsyncClientImpl *close;
    struct {
      const char *data;
      size_t size;
      uint8_t apiflags;
    } write;
    size_t received;
    struct {
      ip_addr_t *addr;
      uint16_t port;
      tcp_connected_fn cb;
    } connect;
    struct {
      ip_addr_t *addr;
      uint16_t port;
    } bind;
    uint8_t backlog;
  };
} tcp_api_call_t;

static err_t _tcp_output_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    msg->err = tcp_output(*msg->pcb);
  }
  return msg->err;
}

static esp_err_t _tcp_output(tcp_pcb **pcb) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  tcpip_api_call(_tcp_output_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_write_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    msg->err = tcp_write(*msg->pcb, msg->write.data, msg->write.size, msg->write.apiflags);
  }
  return msg->err;
}

static esp_err_t _tcp_write(tcp_pcb **pcb, const char *data, size_t size, uint8_t apiflags) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.write.data = data;
  msg.write.size = size;
  msg.write.apiflags = apiflags;
  tcpip_api_call(_tcp_write_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    msg->err = 0;
    tcp_recved(*msg->pcb, msg->received);
  }
  return msg->err;
}

static esp_err_t _tcp_recved(tcp_pcb **pcb, size_t len) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.received = len;
  tcpip_api_call(_tcp_recved_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg) {
  // Unlike the other calls, this is not a direct wrapper of the LwIP function;
  // we perform the AsyncClient teardown interlocked safely with the LwIP task.

  // As a postcondition, the queue must not have any events referencing
  // the AsyncClient in api_call_msg->close.  This is because it is possible for
  // an error event to have been queued, clearing the pcb*, but after the async
  // thread has committed to closing/destructing the AsyncClient object.

  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (*msg->pcb) {
    tcp_pcb *pcb = *msg->pcb;
    _reset_tcp_callbacks(pcb, msg->close);
    if (tcp_close(pcb) != ERR_OK) {
      // We do not permit failure here: abandon the pcb anyways.
      tcp_abort(pcb);
    }
    msg->err = ERR_OK;
    *msg->pcb = nullptr;  // PCB is now the property of LwIP
  } else {
    // Ensure there is not an error event queued for this client
    if (_remove_events_for_client(msg->close)) {
      msg->err = ERR_OK;  // dispose needs to be run
    }
  }
  return msg->err;
}

static esp_err_t _tcp_close(tcp_pcb **pcb, AsyncClientImpl *client) {
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
  tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg) {
  // Like close(), we must ensure that the queue is cleared of any events referencing the AsyncClient.
  // ERR_ABRT: the pcb was aborted.
  // ERR_OK:   the pcb was already gone, but a queued error event was purged, so the
  //           caller must still run the discard callback (dispose needs to run).
  // ERR_CONN: nothing to do (pcb already null and no queued events).
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  if (*msg->pcb) {
    _reset_tcp_callbacks(*msg->pcb, msg->close);
    tcp_abort(*msg->pcb);
    *msg->pcb = nullptr;  // PCB is now the property of LwIP
    msg->err = ERR_ABRT;
  } else {
    // Ensure there is not an error event queued for this client
    msg->err = _remove_events_for_client(msg->close) ? ERR_OK : ERR_CONN;
  }
  return msg->err;
}

static esp_err_t _tcp_abort(tcp_pcb **pcb, AsyncClientImpl *client) {
  if (!pcb || !*pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.close = client;
  tcpip_api_call(_tcp_abort_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  tcp_pcb *pcb = *msg->pcb;
  // Non-zero only if the caller handed us an already-bound pcb
  u16_t bound_port = pcb->local_port;

  msg->err = tcp_connect(pcb, msg->connect.addr, msg->connect.port, msg->connect.cb);
  if (msg->err != ERR_OK) {
    // LwIP neither frees nor registers the pcb when the connect fails, so it is ours
    // to dispose of.  No callback can have fired yet: an unregistered pcb is invisible
    // to LwIP's timers and input path.
    _reset_tcp_callbacks(pcb, nullptr);
    if (bound_port == 0) {
      // tcp_connect() may have taken a local port without adding the pcb to
      // tcp_bound_pcbs.  Clear it, or tcp_close() will try to remove the pcb from a
      // list it was never on - which trips an assert on an empty list.
      pcb->local_port = 0;
    }
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    *msg->pcb = nullptr;  // PCB is now the property of LwIP
  }
  return msg->err;
}

static esp_err_t _tcp_connect(tcp_pcb **pcb, ip_addr_t *addr, uint16_t port, tcp_connected_fn cb) {
  if (!pcb || !*pcb) {
    return ESP_FAIL;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.connect.addr = addr;
  msg.connect.port = port;
  msg.connect.cb = cb;
  tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_bind_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  tcp_pcb *pcb = *msg->pcb;
  msg->err = tcp_bind(pcb, msg->bind.addr, msg->bind.port);
  if (msg->err != ERR_OK) {
    // Close the pcb on behalf of the server without an extra round-trip through the LwIP lock
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    *msg->pcb = nullptr;  // PCB is now owned by LwIP
  }
  return msg->err;
}

static esp_err_t _tcp_bind(tcp_pcb **pcb, ip_addr_t *addr, uint16_t port) {
  if (!pcb || !*pcb) {
    return ESP_FAIL;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.bind.addr = addr;
  msg.bind.port = port;
  tcpip_api_call(_tcp_bind_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_listen_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = 0;
  *msg->pcb = tcp_listen_with_backlog(*msg->pcb, msg->backlog);
  return msg->err;
}

static tcp_pcb *_tcp_listen_with_backlog(tcp_pcb *pcb, uint8_t backlog) {
  if (!pcb) {
    return NULL;
  }
  tcp_api_call_t msg;
  msg.pcb = &pcb;
  msg.backlog = backlog ? backlog : 0xFF;
  tcpip_api_call(_tcp_listen_api, (struct tcpip_api_call_data *)&msg);
  return pcb;
}

/*
  Async TCP Client
 */

AsyncClientImpl::AsyncClientImpl(AsyncClient *facade)
  : _facade(facade), _pcb(nullptr), _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0),
    _error_cb_arg(0), _recv_cb(0), _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true),
    _tx_last_packet(0), _rx_ack_len(0), _rx_last_packet(0), _rx_timeout(0), _rx_last_ack(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _connect_port(0),
    _dns_pending(false), _in_callback_ack_len(0) {}

AsyncClientImpl::~AsyncClientImpl() {
  // Every path that drops the last reference clears the binding first, so arriving here
  // with a pcb still attached means LwIP is left pointing at freed memory.  Closing it
  // here is not the fix: that would RPC to the LwIP thread from whichever thread dropped
  // the last reference, possibly the LwIP thread itself.
  if (_pcb) {
    async_tcp_log_e("implementation destroyed with a live pcb");
  }
}

AsyncClient::AsyncClient(tcp_pcb *pcb) : _impl(std::make_shared<AsyncClientImpl>(this)) {
  _init_queue_mutex();
  if (pcb) {
    _impl->_adopt(pcb);
  }
}

AsyncClient::~AsyncClient() {
  if (_impl->_pcb) {
    _impl->close();
  }
  {
    // Detach: queued events and LwIP callbacks may still reach the implementation, but
    // must not run user code against a facade that no longer exists.
    queue_mutex_guard guard;
    _impl->_facade = nullptr;
  }
}

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) const {
  return _impl->_pcb == other._impl->_pcb;
}

/*
 * Callback Setters
 * */

/*
 * Main Public Methods
 * */

bool AsyncClientImpl::connect(ip_addr_t addr, uint16_t port) {
  if (_pcb) {
    async_tcp_log_d("already connected, state %d", _pcb->state);
    return false;
  }
  if (_dns_pending) {
    async_tcp_log_d("name resolution in progress");
    return false;
  }
  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  tcp_pcb *pcb;
  {
    tcp_core_guard tcg;
#if LWIP_IPV4 && LWIP_IPV6
    pcb = tcp_new_ip_type(addr.type);
#else
    pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
#endif
    if (!pcb) {
      async_tcp_log_e("pcb == NULL");
      return false;
    }
    // Take ownership now: until _connected() arrives the pcb is only reachable
    // through us, so close(), abort() and ~AsyncClient() must be able to find it.
    _adopt(pcb);
  }

  if (_tcp_connect(&_pcb, &addr, port, (tcp_connected_fn)&_tcp_connected) == ESP_OK) {
    return true;
  }
  // _pcb is now NULL and the api call cleared tcp_arg(), so the binding is gone.  No
  // callbacks are raised: we are returning failure.
  async_tcp_log_d("connect failed");
  return false;
}

#ifdef ARDUINO
bool AsyncClientImpl::connect(const IPAddress &ip, uint16_t port) {
  ip_addr_t addr;
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  // if both IPv4 and IPv6 are enabled, ip_addr_t has a union field and the address type
  addr.u_addr.ip4.addr = ip;
  addr.type = IPADDR_TYPE_V4;
#else
  addr.addr = ip;
#endif
#else
  ip.to_ip_addr_t(&addr);
#endif

  return connect(addr, port);
}
#endif

#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClientImpl::connect(const IPv6Address &ip, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(ip);
  ip_addr_t addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

  return connect(addr, port);
}
#endif

bool AsyncClientImpl::connect(const char *host, uint16_t port) {
  ip_addr_t addr;

  if (_pcb) {
    async_tcp_log_d("already connected, state %d", _pcb->state);
    return false;
  }
  if (_dns_pending) {
    // LwIP coalesces a duplicate lookup onto the outstanding one anyway, so a retry
    // never bought anything.  Let the attempt already in flight run to completion.
    async_tcp_log_d("name resolution already in progress");
    return true;
  }
  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  // LwIP keeps the argument until the callback fires, and calls back if and only if it
  // returns ERR_INPROGRESS - always exactly once, including on timeout.  So ownership
  // of the context transfers there and nowhere else; every other return frees it by
  // leaving this scope.
  std::unique_ptr<std::weak_ptr<AsyncClientImpl>> callback_state(new (std::nothrow) std::weak_ptr<AsyncClientImpl>(shared_from_this()));
  if (!callback_state) {
    async_tcp_log_e("Failed to allocate the lookup context");
    return false;
  }

  err_t err;
  {
    tcp_core_guard tcg;
    err = dns_gethostbyname(host, &addr, (dns_found_callback)&AsyncTCP_detail::tcp_dns_found, callback_state.get());
  }

  if (err == ERR_INPROGRESS) {
    _connect_port = port;
    _dns_pending = true;
    callback_state.release();  // now LwIP's to destroy
    return true;
  }

  if (err == ERR_OK) {
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV6
    if (addr.type == IPADDR_TYPE_V6) {
      return connect(IPv6Address(addr.u_addr.ip6.addr), port);
    }
    return connect(IPAddress(addr.u_addr.ip4.addr), port);
#else
    return connect(IPAddress(addr.addr), port);
#endif
#else
    return connect(addr, port);
#endif
  }
  async_tcp_log_d("error: %d", err);
  return false;
}

void AsyncClientImpl::close() {
  _abandonResolve();
  // Ack anything withheld by ackLater(), plus the packet onData is holding right now if
  // we are being called from inside it.  Without this the peer gets an RST rather than a
  // FIN for data the application did in fact process.
  size_t pending = _rx_ack_len + _in_callback_ack_len;
  _rx_ack_len = 0;
  _in_callback_ack_len = 0;
  if (_pcb && pending) {
    _tcp_recved(&_pcb, pending);
  }
  int8_t err = _tcp_close(&_pcb, this);
  // _pcb is now NULL
  if ((err == ERR_OK) && _discard_cb) {
    // _pcb was closed here
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
  }
}

int8_t AsyncClientImpl::abort() {
  _abandonResolve();
  int8_t err = _tcp_abort(&_pcb, this);
  // _pcb is now NULL
  // LwIP invokes the error callback when abort is issued; preserve this semantic.
  // This will also trigger the dispose callback.
  // If the pcb was previously invalidated by some other queued error, we've discarded that value; so we always send ERR_ABRT.
  if (err != ERR_CONN) {
    _error(ERR_ABRT);
  }
  return err;
}

size_t AsyncClientImpl::space() const {
  if ((_pcb != NULL) && (_pcb->state == ESTABLISHED)) {
    return tcp_sndbuf(_pcb);
  }
  return 0;
}

size_t AsyncClientImpl::add(const char *data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    return 0;
  }
  size_t room = space();
  if (!room) {
    return 0;
  }
  size_t will_send = (room < size) ? room : size;
  int8_t err = ERR_OK;
  err = _tcp_write(&_pcb, data, will_send, apiflags);
  if (err != ERR_OK) {
    return 0;
  }
  return will_send;
}

bool AsyncClientImpl::send() {
  auto backup = _tx_last_packet;
  _tx_last_packet = millis();
  if (_tcp_output(&_pcb) == ERR_OK) {
    return true;
  }
  _tx_last_packet = backup;
  return false;
}

size_t AsyncClientImpl::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  if (len) {
    _tcp_recved(&_pcb, len);
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClientImpl::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  _tcp_recved(&_pcb, pb->len);
  pbuf_free(pb);
}

void AsyncClientImpl::ackLater() {
  _ack_pcb = false;
}

/*
 * Main Private Methods
 * */

/*
 * Private Callbacks
 * */

// LwIP has no way to cancel a lookup, so record that we no longer want the answer.
// tcp_dns_found() drops it and releases LwIP's reference when it eventually fires.
void AsyncClientImpl::_abandonResolve() {
  queue_mutex_guard guard;
  _dns_pending = false;
}

// Adopt a pcb and reset all per-connection state.  Callers must already be
// serialized against the LwIP core (accept callback, or tcp_core_guard).
void AsyncClientImpl::_adopt(tcp_pcb *pcb) {
  _pcb = pcb;
  _rx_ack_len = 0;
  _tx_last_packet = 0;
  _rx_last_ack = 0;
  _rx_last_packet = millis();
  _bind_tcp_callbacks(pcb, this);
}

int8_t AsyncClientImpl::_connected(tcp_pcb *pcb, int8_t err) {
  if (pcb != _pcb) {
    // Stale event for a pcb we no longer own
    async_tcp_log_d("%p != %p", (const void *)pcb, (const void *)_pcb);
    return ERR_OK;
  }
  _rx_last_packet = millis();
  if (_connect_cb) {
    async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, _facade));
  }
  return ERR_OK;
}

void AsyncClientImpl::_error(int8_t err) {
  if (_error_cb) {
    async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, _facade, err));
  }
  if (_discard_cb) {
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
  }
}

int8_t AsyncClientImpl::_fin(tcp_pcb *pcb, int8_t err) {
  close();
  return ERR_OK;
}

int8_t AsyncClientImpl::_sent(tcp_pcb *pcb, uint16_t len) {
  _rx_last_ack = _rx_last_packet = millis();
  if (_sent_cb) {
    async_tcp_log_elapsed("onAck", _sent_cb(_sent_cb_arg, _facade, len, (_rx_last_packet - _tx_last_packet)));
  }
  return ERR_OK;
}

int8_t AsyncClientImpl::_recv(tcp_pcb *pcb, pbuf *pb, int8_t err) {
  while (pb != NULL) {
    _rx_last_packet = millis();
    // we should not ack before we assimilate the data
    _ack_pcb = true;
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    if (_pb_cb) {
      // The callback owns b now, and must ackPacket() or free it
      async_tcp_log_elapsed("onPacket", _pb_cb(_pb_cb_arg, _facade, b));
    } else {
      // Visible to close(), so closing from inside onData still acks this packet
      _in_callback_ack_len = b->len;
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, _facade, b->payload, b->len));
      }
      if (_in_callback_ack_len) {  // still ours - close() did not take it
        if (!_ack_pcb) {
          _rx_ack_len += _in_callback_ack_len;
        } else if (_pcb) {
          _tcp_recved(&_pcb, _in_callback_ack_len);
        }
        _in_callback_ack_len = 0;
      }
      pbuf_free(b);
    }
    // Stop if the callback closed the connection or destroyed the client.  We outlive
    // the facade, but there is nobody left to hand the remaining packets to.
    if (!_pcb || !_facade) {
      break;
    }
  }
  if (pb) {
    pbuf_free(pb);  // release whatever we did not get to
  }
  return ERR_OK;
}

int8_t AsyncClientImpl::_poll(tcp_pcb *pcb) {
  if (!_pcb) {
    // async_tcp_log_d("pcb is NULL");
    return ERR_OK;
  }
  if (pcb != _pcb) {
    async_tcp_log_d("%p != %p", (const void *)pcb, (const void *)_pcb);
    return ERR_OK;
  }

  if (_pcb->state < ESTABLISHED) {
    // Still connecting; LwIP handles the SYN timeout itself
    return ERR_OK;
  }

  uint32_t now = millis();

  // ACK Timeout
  if (_ack_timeout) {
    const uint32_t one_day = 86400000;
    bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
    if (last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
      async_tcp_log_d("ack timeout %d", pcb->state);
      if (_timeout_cb) {
        async_tcp_log_elapsed("onTimeout", _timeout_cb(_timeout_cb_arg, _facade, (now - _tx_last_packet)));
      }
      return ERR_OK;
    }
  }
  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    async_tcp_log_d("rx timeout %d", pcb->state);
    close();
    return ERR_OK;
  }
  // Everything is fine
  if (_poll_cb) {
    async_tcp_log_elapsed("onPoll", _poll_cb(_poll_cb_arg, _facade));
  }
  return ERR_OK;
}

void AsyncClientImpl::_dns_found(bool resolved, ip_addr_t *ipaddr, uint16_t port) {
  if (resolved && ip_addr_isany_val(*ipaddr)) {
    // A resolver that answers with the any-address - a sinkhole, or a blocklist - has
    // not given us anywhere to go.  Report it as a failed lookup rather than dialling it.
    resolved = false;
  }
  if (resolved && connect(*ipaddr, port)) {
    return;
  }
  // connect() reported success to the caller, so this attempt owes them exactly one
  // of onConnect or onError.
  _error(resolved ? ERR_CONN : -55);
}

/*
 * Public Helper Methods
 * */

bool AsyncClientImpl::free() {
  if (!_pcb) {
    return true;
  }
  if (_pcb->state == CLOSED || _pcb->state > ESTABLISHED) {
    return true;
  }
  return false;
}

size_t AsyncClientImpl::write(const char *data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) {
    return 0;
  }
  return will_send;
}

void AsyncClientImpl::setRxTimeout(uint32_t timeout) {
  _rx_timeout = timeout;
}

uint32_t AsyncClientImpl::getRxTimeout() const {
  return _rx_timeout;
}

uint32_t AsyncClientImpl::getAckTimeout() const {
  return _ack_timeout;
}

void AsyncClientImpl::setAckTimeout(uint32_t timeout) {
  _ack_timeout = timeout;
}

void AsyncClientImpl::setNoDelay(bool nodelay) const {
  if (!_pcb) {
    return;
  }
  if (nodelay) {
    tcp_nagle_disable(_pcb);
  } else {
    tcp_nagle_enable(_pcb);
  }
}

bool AsyncClientImpl::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClientImpl::setKeepAlive(uint32_t ms, uint8_t cnt) {
  if (!_pcb) {
    return;
  }
  if (ms != 0) {
    _pcb->so_options |= SOF_KEEPALIVE;  // Turn on TCP Keepalive for the given pcb
    // Set the time between keepalive messages in milli-seconds
    _pcb->keep_idle = ms;
    _pcb->keep_intvl = ms;
    _pcb->keep_cnt = cnt;  // The number of unanswered probes required to force closure of the socket
  } else {
    _pcb->so_options &= ~SOF_KEEPALIVE;  // Turn off TCP Keepalive for the given pcb
  }
}

uint16_t AsyncClientImpl::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClientImpl::getRemoteAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->remote_ip.u_addr.ip4.addr;
#else
  return _pcb->remote_ip.addr;
#endif
}

#if LWIP_IPV6
ip6_addr_t AsyncClientImpl::getRemoteAddress6() const {
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V6) {
    return _pcb->remote_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip6_addr_t AsyncClientImpl::getLocalAddress6() const {
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V6) {
    return _pcb->local_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
IPv6Address AsyncClientImpl::remoteIP6() const {
  return IPv6Address(getRemoteAddress6().addr);
}

IPv6Address AsyncClientImpl::localIP6() const {
  return IPv6Address(getLocalAddress6().addr);
}
#else
IPAddress AsyncClientImpl::remoteIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
}

IPAddress AsyncClientImpl::localIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
}
#endif
#endif
#endif

uint16_t AsyncClientImpl::getRemotePort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->remote_port;
}

uint32_t AsyncClientImpl::getLocalAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->local_ip.u_addr.ip4.addr;
#else
  return _pcb->local_ip.addr;
#endif
}

uint16_t AsyncClientImpl::getLocalPort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->local_port;
}

ip4_addr_t AsyncClientImpl::getRemoteAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V4) {
    return _pcb->remote_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->remote_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip4_addr_t AsyncClientImpl::getLocalAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V4) {
    return _pcb->local_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->local_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

#ifdef ARDUINO
IPAddress AsyncClientImpl::remoteIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getRemoteAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
#endif
}

IPAddress AsyncClientImpl::localIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getLocalAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
#endif
}
#endif

uint8_t AsyncClientImpl::state() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}

bool AsyncClientImpl::connected() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state == ESTABLISHED;
}

bool AsyncClientImpl::connecting() const {
  if (_dns_pending) {
    return true;  // resolving the hostname
  }
  if (!_pcb) {
    return false;
  }
  return _pcb->state > CLOSED && _pcb->state < ESTABLISHED;
}

bool AsyncClientImpl::disconnecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT;
}

bool AsyncClientImpl::disconnected() const {
  if (_dns_pending) {
    return false;  // resolving the hostname
  }
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClientImpl::freeable() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state > ESTABLISHED;
}

bool AsyncClientImpl::canSend() const {
  return space() > 0;
}

const char *AsyncClient::errorToString(int8_t error) {
  switch (error) {
    case ERR_OK:         return "OK";
    case ERR_MEM:        return "Out of memory error";
    case ERR_BUF:        return "Buffer error";
    case ERR_TIMEOUT:    return "Timeout";
    case ERR_RTE:        return "Routing problem";
    case ERR_INPROGRESS: return "Operation in progress";
    case ERR_VAL:        return "Illegal value";
    case ERR_WOULDBLOCK: return "Operation would block";
    case ERR_USE:        return "Address in use";
    case ERR_ALREADY:    return "Already connected";
    case ERR_CONN:       return "Not connected";
    case ERR_IF:         return "Low-level netif error";
    case ERR_ABRT:       return "Connection aborted";
    case ERR_RST:        return "Connection reset";
    case ERR_CLSD:       return "Connection closed";
    case ERR_ARG:        return "Illegal argument";
    case -55:            return "DNS failed";
    default:             return "UNKNOWN";
  }
}

const char *AsyncClientImpl::stateToString() const {
  switch (state()) {
    case 0:  return "Closed";
    case 1:  return "Listen";
    case 2:  return "SYN Sent";
    case 3:  return "SYN Received";
    case 4:  return "Established";
    case 5:  return "FIN Wait 1";
    case 6:  return "FIN Wait 2";
    case 7:  return "Close Wait";
    case 8:  return "Closing";
    case 9:  return "Last ACK";
    case 10: return "Time Wait";
    default: return "UNKNOWN";
  }
}

/*
 * AsyncClient - the application-facing facade.
 *
 * Every method below forwards to the reference-counted implementation.  _impl is never
 * null for a live AsyncClient: it is created in the constructor and only released in
 * the destructor.
 */

bool AsyncClient::connect(ip_addr_t addr, uint16_t port) {
  return _impl->connect(addr, port);
}

bool AsyncClient::connect(const char *host, uint16_t port) {
  return _impl->connect(host, port);
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port) {
  return _impl->connect(ip, port);
}
#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port) {
  return _impl->connect(ip, port);
}
#endif
#endif

void AsyncClient::close() {
  _impl->close();
}

int8_t AsyncClient::abort() {
  return _impl->abort();
}

bool AsyncClient::free() {
  return _impl->free();
}

bool AsyncClient::canSend() const {
  return _impl->canSend();
}

size_t AsyncClient::space() const {
  return _impl->space();
}

size_t AsyncClient::add(const char *data, size_t size, uint8_t apiflags) {
  return _impl->add(data, size, apiflags);
}

bool AsyncClient::send() {
  return _impl->send();
}

size_t AsyncClient::write(const char *data, size_t size, uint8_t apiflags) {
  return _impl->write(data, size, apiflags);
}

uint8_t AsyncClient::state() const {
  return _impl->state();
}

bool AsyncClient::connecting() const {
  return _impl->connecting();
}

bool AsyncClient::connected() const {
  return _impl->connected();
}

bool AsyncClient::disconnecting() const {
  return _impl->disconnecting();
}

bool AsyncClient::disconnected() const {
  return _impl->disconnected();
}

bool AsyncClient::freeable() const {
  return _impl->freeable();
}

uint16_t AsyncClient::getMss() const {
  return _impl->getMss();
}

uint32_t AsyncClient::getRxTimeout() const {
  return _impl->getRxTimeout();
}

void AsyncClient::setRxTimeout(uint32_t timeout) {
  _impl->setRxTimeout(timeout);
}

uint32_t AsyncClient::getAckTimeout() const {
  return _impl->getAckTimeout();
}

void AsyncClient::setAckTimeout(uint32_t timeout) {
  _impl->setAckTimeout(timeout);
}

void AsyncClient::setNoDelay(bool nodelay) const {
  _impl->setNoDelay(nodelay);
}

bool AsyncClient::getNoDelay() {
  return _impl->getNoDelay();
}

void AsyncClient::setKeepAlive(uint32_t ms, uint8_t cnt) {
  _impl->setKeepAlive(ms, cnt);
}

uint32_t AsyncClient::getRemoteAddress() const {
  return _impl->getRemoteAddress();
}

uint16_t AsyncClient::getRemotePort() const {
  return _impl->getRemotePort();
}

uint32_t AsyncClient::getLocalAddress() const {
  return _impl->getLocalAddress();
}

uint16_t AsyncClient::getLocalPort() const {
  return _impl->getLocalPort();
}

ip4_addr_t AsyncClient::getRemoteAddress4() const {
  return _impl->getRemoteAddress4();
}

ip4_addr_t AsyncClient::getLocalAddress4() const {
  return _impl->getLocalAddress4();
}

#if LWIP_IPV6
ip6_addr_t AsyncClient::getRemoteAddress6() const {
  return _impl->getRemoteAddress6();
}

ip6_addr_t AsyncClient::getLocalAddress6() const {
  return _impl->getLocalAddress6();
}
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
IPv6Address AsyncClient::remoteIP6() const {
  return _impl->remoteIP6();
}

IPv6Address AsyncClient::localIP6() const {
  return _impl->localIP6();
}
#else
IPAddress AsyncClient::remoteIP6() const {
  return _impl->remoteIP6();
}

IPAddress AsyncClient::localIP6() const {
  return _impl->localIP6();
}
#endif
#endif
#endif

#ifdef ARDUINO
IPAddress AsyncClient::remoteIP() const {
  return _impl->remoteIP();
}

IPAddress AsyncClient::localIP() const {
  return _impl->localIP();
}
#endif

void AsyncClient::ackPacket(struct pbuf *pb) {
  _impl->ackPacket(pb);
}

size_t AsyncClient::ack(size_t len) {
  return _impl->ack(len);
}

void AsyncClient::ackLater() {
  _impl->ackLater();
}

const char *AsyncClient::stateToString() const {
  return _impl->stateToString();
}

int8_t AsyncClient::_recv(tcp_pcb *pcb, pbuf *pb, int8_t err) {
  return _impl->_recv(pcb, pb, err);
}

tcp_pcb *AsyncClient::pcb() {
  return _impl->_pcb;
}

void AsyncClient::onConnect(AcConnectHandler cb, void *arg) {
  _impl->_connect_cb = cb;
  _impl->_connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void *arg) {
  _impl->_discard_cb = cb;
  _impl->_discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void *arg) {
  _impl->_sent_cb = cb;
  _impl->_sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void *arg) {
  _impl->_error_cb = cb;
  _impl->_error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void *arg) {
  _impl->_recv_cb = cb;
  _impl->_recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void *arg) {
  _impl->_pb_cb = cb;
  _impl->_pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void *arg) {
  _impl->_timeout_cb = cb;
  _impl->_timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void *arg) {
  _impl->_poll_cb = cb;
  _impl->_poll_cb_arg = arg;
}

/*
  Async TCP Server
 */

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port)
  : _port(port), _addr(addr), _noDelay(false), _pcb(nullptr), _connect_cb(nullptr), _connect_cb_arg(nullptr) {
  _init_queue_mutex();
}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0) {
  _init_queue_mutex();
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V4;
  _addr.u_addr.ip4.addr = addr;
#else
  _addr.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&_addr);
#endif
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0) {
  _init_queue_mutex();
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V6;
#endif
  auto ipaddr = static_cast<const uint32_t *>(addr);
  _addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) : _port(port), _noDelay(false), _pcb(0), _connect_cb(0), _connect_cb_arg(0) {
  _init_queue_mutex();
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_ANY;
  _addr.u_addr.ip4.addr = INADDR_ANY;
#else
  _addr.addr = INADDR_ANY;
#endif
}

AsyncServer::~AsyncServer() {
  end();
}

void AsyncServer::onClient(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServer::begin() {
  if (_pcb) {
    return;
  }

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return;
  }
  int8_t err;
  {
    tcp_core_guard tcg;
#if LWIP_IPV4 && LWIP_IPV6
    _pcb = tcp_new_ip_type(_addr.type);
#else
    _pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
#endif
  }
  if (!_pcb) {
    async_tcp_log_e("_pcb == NULL");
    return;
  }

  err = _tcp_bind(&_pcb, &_addr, _port);

  if (err != ERR_OK) {
    // pcb was closed by _tcp_bind
    async_tcp_log_e("bind error: %d", err);
    return;
  }

  static uint8_t backlog = 5;
  tcp_pcb *listen_pcb = _tcp_listen_with_backlog(_pcb, backlog);
  if (!listen_pcb) {
    // LwIP frees the original pcb only on success; ours is still bound, and holds
    // the port reserved until we release it.
    async_tcp_log_e("listen_pcb == NULL");
    tcp_core_guard tcg;
    if (tcp_close(_pcb) != ERR_OK) {
      tcp_abort(_pcb);
    }
    _pcb = nullptr;
    return;
  }
  _pcb = listen_pcb;
  tcp_core_guard tcg;
  tcp_arg(_pcb, (void *)this);
  tcp_accept(_pcb, &AsyncTCP_detail::tcp_accept);
}

void AsyncServer::end() {
  if (_pcb) {
    {
      tcp_core_guard tcg;
      tcp_arg(_pcb, NULL);
      tcp_accept(_pcb, NULL);
      if (tcp_close(_pcb) != ERR_OK) {
        tcp_abort(_pcb);
      }
      _pcb = NULL;
    }
    // No further accept callbacks can fire, so anything still queued is the last of it.
    _remove_events_for_server(this);
  }
}

// runs on LwIP thread
int8_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *pcb, int8_t err) {
  if (!pcb) {
    async_tcp_log_e("_accept failed: pcb is NULL");
    return ERR_ABRT;
  }
  auto server = reinterpret_cast<AsyncServer *>(arg);
  if (server->_connect_cb) {
    AsyncClient *c = new (std::nothrow) AsyncClient(pcb);
    if (c && c->pcb()) {
      c->setNoDelay(server->_noDelay);

      lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, c->_impl};
      if (e) {
        e->accept.server = server;

        queue_mutex_guard guard;
        _prepend_async_event(e);
        return ERR_OK;  // success
      }

      // Couldn't allocate accept event.  Reset the callbacks first: tcp_abort() raises
      // the error callback, and this client is being discarded, not reported on.
      _reset_tcp_callbacks(pcb, c->_impl.get());
      // Clear the pcb before destroying c - we're on the LwIP thread, and letting it
      // call in to close would deadlock trying to RPC to itself
      c->_impl->_pcb = nullptr;
      tcp_abort(pcb);
      delete c;
      async_tcp_log_e("_accept failed: couldn't accept client");
      return ERR_ABRT;
    }
    if (c) {
      // Couldn't complete setup
      // pcb has already been aborted
      delete c;
      pcb = nullptr;
      async_tcp_log_e("_accept failed: couldn't complete setup");
      return ERR_ABRT;
    }
    async_tcp_log_e("_accept failed: couldn't allocate client");
  } else {
    async_tcp_log_e("_accept failed: no onConnect callback");
  }
  tcp_abort(pcb);
  return ERR_OK;
}

int8_t AsyncServer::_accepted(AsyncClient *client) {
  if (_connect_cb) {
    async_tcp_log_elapsed("onClient", _connect_cb(_connect_cb_arg, client));
  }
  return ERR_OK;
}

void AsyncServer::setNoDelay(bool nodelay) {
  _noDelay = nodelay;
}

bool AsyncServer::getNoDelay() const {
  return _noDelay;
}

uint8_t AsyncServer::status() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}
