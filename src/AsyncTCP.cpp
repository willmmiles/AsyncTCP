// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2026 Hristo Gochkov, Mathieu Carbou, Emil Muratov, Will Miles

#include "AsyncTCP.h"
#include "AsyncTCPLogging.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <memory>
#include <new>
#include <type_traits>

/**
 * Assertion macros
 * ESP-IDF leaves assertions on by default; we prefer the opposite as performance in this layer is critical.
 */
#ifdef CONFIG_ASYNC_TCP_ASSERTIONS
#define ASYNCTCP_ASSERT(x) assert(x)
#else
#define ASYNCTCP_ASSERT(x) ((void)0)
#endif

/**
 * Utility macro
 *
 * Most API functions are delegated to the impl class.  Ensure the wrapped functions are always inlined
 * to avoid the extra function call overhead.
*/
#define ASYNCTCP_ALWAYS_INLINE __attribute__((always_inline)) inline

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
#include "lwip/priv/tcpip_priv.h"
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

/**
 * async_tcp_log_elapsed
 * Log the time elapsed in a given statement (typically the user callbacks).  Useful for performance monitoring and debugging.
 * The complex gate is because micros() is opaque to the compiler and cannot be optimized away when unused, so we
 * only enable this feature if verbose logging is enabled.
 */
#if defined(CONFIG_ASYNC_TCP_DEBUG) || defined(CONFIG_ASYNC_TCP_LOG_CUSTOM) || (defined(CORE_DEBUG_LEVEL) && (CORE_DEBUG_LEVEL >= 5)) \
  || (defined(LOG_LOCAL_LEVEL) && (LOG_LOCAL_LEVEL >= 5))
#define async_tcp_log_elapsed(tag, statement)                                                 \
  {                                                                                           \
    const uint32_t s_time = micros();                                                         \
    statement;                                                                                \
    async_tcp_log_v("%s took %" PRIu32 " us", tag, static_cast<uint32_t>(micros()) - s_time); \
  }
#else
#define async_tcp_log_elapsed(tag, statement) \
  { statement; }
#endif

/**
 * LwIP locking
 *
 * Utilities for managing LwIP TCP core mutexing.  Includes two features
 * - tcp_core_guard: a guard class usable when LWIP_TCPIP_CORE_LOCKING exposes the mutex for direct usage
 * - with_tcp_core_lock: a metafunction that runs a function inside the LwIP TCP core lock context, using the most efficient method available on the current build.
 *
 * https://github.com/espressif/arduino-esp32/issues/10526
 */
namespace {
#if LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
  inline tcp_core_guard() {
    LOCK_TCPIP_CORE();
  }
  inline ~tcp_core_guard() {
    UNLOCK_TCPIP_CORE();
  }
  tcp_core_guard(const tcp_core_guard &) = delete;
  tcp_core_guard(tcp_core_guard &&) = delete;
  tcp_core_guard &operator=(const tcp_core_guard &) = delete;
  tcp_core_guard &operator=(tcp_core_guard &&) = delete;
} __attribute__((unused));
#else   // LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
} __attribute__((unused));
#endif  // LWIP_TCPIP_CORE_LOCKING

/*
  Locking metafunction for TCP core operations.

  Runs a function inside the LwIP context by whichever route is cheapest on this build.
  Where the core lock exists we take it and call straight through, which avoids marshaling
  the arguments through a message.  Where direct locking is not available, we wrap the function
  call with tcpip_api_call.
*/
template<typename T> err_t with_tcp_core_lock(T &&func) {
#if LWIP_TCPIP_CORE_LOCKING || NO_SYS
  tcp_core_guard guard;
  return func();
#else
  // The functor is reached by pointer: a reference member would leave the struct without
  // a default constructor, and it only has to outlive the call.
  struct call_data {
    struct tcpip_api_call_data call;  // must be first member
    typename std::remove_reference<T>::type *f;
  } data;
  data.f = &func;
  return tcpip_api_call(
    // The lambda here constructs a C function which perfectly forwards the call to the functor.
    +[](struct tcpip_api_call_data *c) -> err_t {
      return (*reinterpret_cast<call_data *>(c)->f)();
    },
    &data.call
  );
#endif
}

}  // anonymous namespace

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#define CONFIG_ASYNC_TCP_POLL_TIMER 1

// Depth of the pending-connection queue handed to tcp_listen_with_backlog()
#define ASYNCTCP_LISTEN_BACKLOG 5

/*
 * TCP/IP Event Task
 * */

typedef enum {
  LWIP_TCP_NONE,
  LWIP_TCP_SENT,
  LWIP_TCP_RECV,
  LWIP_TCP_FIN,
  LWIP_TCP_ERROR,
  LWIP_TCP_POLL,
  LWIP_TCP_CONNECTED
} lwip_tcp_event_t;

// One thing the async task takes from a client to deliver.  It lives on the task's stack.
struct lwip_tcp_event_packet_t {
  lwip_tcp_event_t event;
  tcp_pcb *pcb;
  union {
    struct {
      int8_t err;
    } error;
    struct {
      uint32_t len;
      uint32_t time;
    } sent;
    struct {
      pbuf *pb;
    } recv;
  };
};

// Detail class for interacting with AsyncClient internals, but without exposing the API
class AsyncTCP_detail {
public:
  // Helper functions
  static bool __attribute__((visibility("internal"))) service();
  static bool __attribute__((visibility("internal"))) service_accept();

  // LwIP TCP event callbacks that (will) require privileged access
  static int8_t __attribute__((visibility("internal"))) tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, int8_t err);
  static int8_t __attribute__((visibility("internal"))) tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len);
  static void __attribute__((visibility("internal"))) tcp_error(void *arg, int8_t err);
  static int8_t __attribute__((visibility("internal"))) tcp_poll(void *arg, struct tcp_pcb *pcb);
  static int8_t __attribute__((visibility("internal"))) tcp_accept(void *arg, tcp_pcb *pcb, int8_t err);
  static void __attribute__((visibility("internal"))) tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg);
};

namespace {
// Global queue mutex: guards the ready lists and what each client is owed
static SemaphoreHandle_t _async_queue_mutex = nullptr;

// Created by _start_async_task(), which every path that can list a client passes first.
// Unsynchronized, as _start_async_task() always has been.
static bool _init_queue_mutex() {
  if (!_async_queue_mutex) {
    _async_queue_mutex = xSemaphoreCreateMutex();
    if (!_async_queue_mutex) {
      async_tcp_log_e("Failed to create the queue mutex");
    }
  }
  return _async_queue_mutex != nullptr;
}

// Guard class for the global queue mutex
class queue_mutex_guard {
  bool holds_mutex;

public:
  // For paths that can only run once _start_async_task() has succeeded.
  inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
  // For paths that can run before it ever has: takes nothing if the mutex was never created,
  // in which case nothing can have been listed and no task is reading.
  enum if_created_t {
    if_created
  };
  inline explicit queue_mutex_guard(if_created_t) : holds_mutex(_async_queue_mutex && xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
  inline ~queue_mutex_guard() {
    if (holds_mutex) {
      xSemaphoreGive(_async_queue_mutex);
    }
  };
  inline explicit operator bool() const {
    return holds_mutex;
  };
};

/**
 * make_shared_nothrow - nonthrowing shared_ptr construction
 *
 * std::make_shared cannot report allocation failure without exceptions.  Instead, allocate
 * the storage up front and hand it to std::allocate_shared, so the library still builds its
 * own control block and object together, and failure is reported before anything is built.
 *
 * The storage is sized from libstdc++'s control block type, so it is exact; allocate()
 * checks that this is the type the library actually requests.  The allocator stored in the
 * block is empty, so the block is the same size as make_shared's.  The copy that allocates
 * is built from a reference to the caller's request, which is how it finds the storage.
 */
template<typename T> struct prealloc_tag;
template<typename U, typename T> struct prealloc_alloc;
template<typename U, typename T> using prealloc_rebind = typename std::conditional<std::is_same<U, T>::value, prealloc_tag<T>, prealloc_alloc<U, T>>::type;
#if defined(__GLIBCXX__)
template<typename T> using prealloc_block = std::_Sp_counted_ptr_inplace<T, prealloc_tag<T>, __gnu_cxx::__default_lock_policy>;
#else
#error "This C++ stdlib is not supported yet; please define prealloc_block as the in-place control block type"
#endif

// Deallocation tag - stored in control block, 0 bytes size
template<typename T> struct prealloc_tag {
  using value_type = T;
  // Rebinding to any other type promotes to a prealloc_alloc.
  // This allows us to store 0 bytes in the control block, but supply the actual storage to allocate_shared
  template<typename U> struct rebind {
    using other = prealloc_rebind<U, T>;
  };
  T *allocate(size_t);  // never called
  void deallocate(T *p, size_t) {
    delete[] reinterpret_cast<char *>(p);
  }
};

// Subclass of the above that stores the buffer.  Allows us to upcast to the 0-byte type.
template<typename T> struct prealloc_request : prealloc_tag<T> {
  char *buf;
};

// Actual allocation implementation, constructed via prealloc_rebind around a prealloc_tag
// Essentially promotes the prealloc_request to a full allocator for the control block; origin
// is assumed to be a reference to an underlying prealloc_request that was previously allocated
// by make_shared_nothrow.
// During deallocation, we can simply delete the buffer as we are directly passed the pointer.
template<typename U, typename T> struct prealloc_alloc {
  using value_type = U;
  template<typename V> struct rebind {
    using other = prealloc_rebind<V, T>;
  };
  const prealloc_tag<T> *origin;  // only a prealloc_request when allocating
  prealloc_alloc(const prealloc_tag<T> &tag) : origin(&tag) {}
  U *allocate(size_t) {
    static_assert(std::is_same<U, prealloc_block<T>>::value, "storage was sized for a different control block");
    return reinterpret_cast<U *>(static_cast<const prealloc_request<T> *>(origin)->buf);
  }
  void deallocate(U *p, size_t) {
    delete[] reinterpret_cast<char *>(p);
  }
};

// make_shared_nothrow
// Nonthrowing version of make_shared: returns an empty shared_ptr if the allocation fails.
// Like `make_shared`, uses a single, correctly-sized allocation for control block and object in one transaction.
template<typename T, typename... Args> std::shared_ptr<T> make_shared_nothrow(Args &&...args) {
  static_assert(alignof(prealloc_block<T>) <= alignof(std::max_align_t), "overaligned control block");
  prealloc_request<T> request;
  request.buf = new (std::nothrow) char[sizeof(prealloc_block<T>)];
  if (!request.buf) {
    return nullptr;
  }
  return std::allocate_shared<T>(static_cast<const prealloc_tag<T> &>(request), std::forward<Args>(args)...);
}

/*
  Received chains waiting to be delivered, each as LwIP delivered it.

  The chains are threaded into a ring through the pbufs' own links and held by the ring's
  last pbuf, so any number of them costs one pointer.  tot_len is left alone: each chain keeps
  LwIP's end marker - its last pbuf has tot_len == len - which is how pop() finds where the
  oldest one ends.
*/
class pbuf_ring {
public:
  pbuf_ring() : _last(nullptr) {}

  bool empty() const {
    return !_last;
  }

  // A chain's last pbuf; separate from push() so the walk can be made before taking a lock.
  static pbuf *end_of(pbuf *chain) {
    while (chain->next) {
      chain = chain->next;
    }
    return chain;
  }

  // Append a chain, given its last pbuf.
  void push(pbuf *chain, pbuf *end) {
    end->next = _last ? _last->next : chain;
    if (_last) {
      _last->next = chain;
    }
    _last = end;
  }

  // Remove the oldest chain, null-terminated; nullptr if there is none.
  pbuf *pop() {
    if (!_last) {
      return nullptr;
    }
    pbuf *head = _last->next;
    pbuf *end = head;
    while (end != _last && end->tot_len != end->len) {
      end = end->next;
    }
    if (end == _last) {
      _last = nullptr;
    } else {
      _last->next = end->next;
    }
    end->next = nullptr;
    return head;
  }

  // Remove everything, so it can be freed outside a lock.
  pbuf_ring take() {
    pbuf_ring taken;
    taken._last = _last;
    _last = nullptr;
    return taken;
  }

  // Chain by chain: pbuf_free() stops at a pbuf someone else still holds.
  void free() {
    while (pbuf *pb = pop()) {
      pbuf_free(pb);
    }
  }

private:
  pbuf *_last;
};

// A FIFO linked through T::_ready_next, which points back at its own object while that is
// on no list.  It does not own what it holds.  Moving empties the source.
template<typename T> struct ready_fifo {
  T *head = nullptr;
  T **tail = &head;

  ready_fifo() = default;

  ready_fifo &operator=(ready_fifo &&o) {
    ASYNCTCP_ASSERT(!head);
    head = o.head;
    tail = head ? o.tail : &head;
    o.head = nullptr;
    o.tail = &o.head;
    return *this;
  }

  static bool listed(const T *t) {
    return t->_ready_next != t;
  }

  void push_back(T *t) {
    t->_ready_next = nullptr;
    *tail = t;
    tail = &t->_ready_next;
  }

  T *pop_front() {
    T *t = head;
    if (t) {
      head = t->_ready_next;
      if (!head) {
        tail = &head;
      }
      t->_ready_next = t;
    }
    return t;
  }
};
}  // anonymous namespace

static TaskHandle_t _async_service_task_handle = NULL;

/*
  Client implementation, held by shared_ptr.

  The AsyncClient facade is created and destroyed by the application, but LwIP and the
  ready list both hold pointers that outlive it.  Putting the state here and sharing
  ownership of it means neither has to care: the facade and the ready list (or, until it
  is delivered, its server's accept list) own the implementation, and it lives until the
  last of them lets go.

  Because the callbacks live here rather than on the facade, they stay in scope while
  being called, ensuring that any captures remain alive until the callback completes,
  even if the AsyncClient object is destroyed.

  The context passed to LwIP callbacks are deliberately not owners -- instead this class
  owns them and ensures that all are released before destruction.

  _facade is nulled when the application's object is destroyed.  Callback dispatch is
  always gated on it, so a detached implementation runs no user code.
*/
class AsyncClientImpl : public std::enable_shared_from_this<AsyncClientImpl> {
public:
  explicit AsyncClientImpl(AsyncClient *facade);
  ~AsyncClientImpl();

  AsyncClientImpl(const AsyncClientImpl &) = delete;
  AsyncClientImpl &operator=(const AsyncClientImpl &) = delete;

  /*
    Members held under LwIP context
  */
  tcp_pcb *_pcb;
  uint16_t _connect_port;
  std::weak_ptr<AsyncClientImpl> *_dns_token;  // non-owning pointer to the most recent DNS lookup token
  bool _dispose_owed;                          // a terminal notification is owed to the application

  /*
    Members held under the queue mutex: what LwIP has reported that the async task has yet
    to deliver.  A pending error replaces everything else.
  */
  int8_t _pending_err;  // nonzero: the connection has ended with this error
  uint8_t _pending;     // pending_* flags
  pbuf_ring _rx;
  uint32_t _acked;  // bytes acked
  uint32_t _acked_time;
  // The facade owns us; this holds us instead while we wait to be delivered to one, or once it
  // is destroyed while the async task still has us listed or in hand.
  std::shared_ptr<AsyncClientImpl> _ready_self;
  AsyncClientImpl *_ready_next;

  /*
    Written under the queue mutex, as LwIP's callbacks read it there to decide whether to
    list the client; nulled once the application's object is destroyed.
  */
  AsyncClient *_facade;

  /*
    Not synchronized.  The handlers are installed by the application before it connects
    and read by the async task when it dispatches; the rest is connection state that the
    async task owns in practice, touched from the calling task only through calls the
    application is expected not to make from two tasks at once against one client.
  */

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
  uint32_t _ack_since;  // ack timer; 0 = idle
  uint32_t _ack_timeout;
  uint32_t _in_callback_ack_len;  // bytes handed to onData but not yet acked

  ASYNCTCP_ALWAYS_INLINE bool connect(ip_addr_t addr, uint16_t port);
  ASYNCTCP_ALWAYS_INLINE bool connect(const char *host, uint16_t port);
#ifdef ARDUINO
  ASYNCTCP_ALWAYS_INLINE bool connect(const IPAddress &ip, uint16_t port);
#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
  ASYNCTCP_ALWAYS_INLINE bool connect(const IPv6Address &ip, uint16_t port);
#endif
#endif
  ASYNCTCP_ALWAYS_INLINE void close();
  ASYNCTCP_ALWAYS_INLINE int8_t abort();
  ASYNCTCP_ALWAYS_INLINE bool free();

  ASYNCTCP_ALWAYS_INLINE bool canSend() const;
  ASYNCTCP_ALWAYS_INLINE size_t space() const;
  ASYNCTCP_ALWAYS_INLINE size_t add(const char *data, size_t size, uint8_t apiflags);
  ASYNCTCP_ALWAYS_INLINE bool send();
  ASYNCTCP_ALWAYS_INLINE size_t write(const char *data, size_t size, uint8_t apiflags);

  ASYNCTCP_ALWAYS_INLINE uint8_t state() const;
  ASYNCTCP_ALWAYS_INLINE bool connecting() const;
  ASYNCTCP_ALWAYS_INLINE bool connected() const;
  ASYNCTCP_ALWAYS_INLINE bool disconnecting() const;
  ASYNCTCP_ALWAYS_INLINE bool disconnected() const;
  ASYNCTCP_ALWAYS_INLINE bool freeable() const;

  ASYNCTCP_ALWAYS_INLINE uint16_t getMss() const;
  ASYNCTCP_ALWAYS_INLINE uint32_t getRxTimeout() const;
  ASYNCTCP_ALWAYS_INLINE void setRxTimeout(uint32_t timeout);
  ASYNCTCP_ALWAYS_INLINE uint32_t getAckTimeout() const;
  ASYNCTCP_ALWAYS_INLINE void setAckTimeout(uint32_t timeout);
  ASYNCTCP_ALWAYS_INLINE void setNoDelay(bool nodelay) const;
  ASYNCTCP_ALWAYS_INLINE bool getNoDelay();
  ASYNCTCP_ALWAYS_INLINE void setKeepAlive(uint32_t ms, uint8_t cnt);

  ASYNCTCP_ALWAYS_INLINE uint32_t getRemoteAddress() const;
  ASYNCTCP_ALWAYS_INLINE uint16_t getRemotePort() const;
  ASYNCTCP_ALWAYS_INLINE uint32_t getLocalAddress() const;
  ASYNCTCP_ALWAYS_INLINE uint16_t getLocalPort() const;
  ASYNCTCP_ALWAYS_INLINE ip4_addr_t getRemoteAddress4() const;
  ASYNCTCP_ALWAYS_INLINE ip4_addr_t getLocalAddress4() const;
#if LWIP_IPV6
  ASYNCTCP_ALWAYS_INLINE ip6_addr_t getRemoteAddress6() const;
  ASYNCTCP_ALWAYS_INLINE ip6_addr_t getLocalAddress6() const;
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
  ASYNCTCP_ALWAYS_INLINE IPv6Address remoteIP6() const;
  ASYNCTCP_ALWAYS_INLINE IPv6Address localIP6() const;
#else
  ASYNCTCP_ALWAYS_INLINE IPAddress remoteIP6() const;
  ASYNCTCP_ALWAYS_INLINE IPAddress localIP6() const;
#endif
#endif
#endif
#ifdef ARDUINO
  ASYNCTCP_ALWAYS_INLINE IPAddress remoteIP() const;
  ASYNCTCP_ALWAYS_INLINE IPAddress localIP() const;
#endif

  ASYNCTCP_ALWAYS_INLINE void ackPacket(struct pbuf *pb);
  ASYNCTCP_ALWAYS_INLINE size_t ack(size_t len);
  ASYNCTCP_ALWAYS_INLINE void ackLater();
  ASYNCTCP_ALWAYS_INLINE const char *stateToString() const;

  void _adopt(tcp_pcb *pcb);
  int8_t _connected(tcp_pcb *pcb, int8_t err);
  void _error(int8_t err);
  int8_t _poll(tcp_pcb *pcb);
  int8_t _sent(tcp_pcb *pcb, uint32_t len, uint32_t time);
  int8_t _fin(tcp_pcb *pcb, int8_t err);
  int8_t _recv(tcp_pcb *pcb, pbuf *pb, int8_t err);

  // Add and send internal implementations; must be called in LwIP context
  // These are called out to share code with write(), but allow the whole
  // sequence to go in a single LwIP lock transaction.
  size_t _add_locked(const char *data, size_t size, uint8_t apiflags);
  err_t _send_locked();
};

/*
  Server implementation class

  This has the same basic pattern as AsyncClient: the async task takes over the facade's
  reference if the application destroys it while the task still has the implementation
  listed, or is delivering a connection from it.

  Accepted connections wait in _accepts, and the server on the ready list, until the async
  task hands them to onClient.  end() closes any still waiting; one the task has already
  taken is delivered, as a client's callback is after close().
*/
class AsyncServerImpl {
public:
  AsyncServerImpl(ip_addr_t addr, uint16_t port)
    : _pcb(nullptr), _ready_next(this), _addr(addr), _port(port), _noDelay(false), _connect_cb(nullptr), _connect_cb_arg(nullptr) {}
  ~AsyncServerImpl() {
    // Every path that releases the implementation has already stopped it listening.
    ASYNCTCP_ASSERT(!_pcb);
    ASYNCTCP_ASSERT(!ready_fifo<AsyncServerImpl>::listed(this));
  }

  AsyncServerImpl(const AsyncServerImpl &) = delete;
  AsyncServerImpl &operator=(const AsyncServerImpl &) = delete;

  // Written only inside the LwIP context; null once we have stopped listening.
  tcp_pcb *_pcb;

  // Held under the queue mutex.  Each accepted client holds itself in _ready_self until delivered.
  ready_fifo<AsyncClientImpl> _accepts;
  // The facade owns us; this holds us instead once it is destroyed while the async task still
  // has us listed or in hand.
  std::shared_ptr<AsyncServerImpl> _ready_self;
  AsyncServerImpl *_ready_next;

  // Not synchronized: set up before begin() and read afterwards.
  ip_addr_t _addr;
  uint16_t _port;
  bool _noDelay;
  AcConnectHandler _connect_cb;
  void *_connect_cb_arg;

  ASYNCTCP_ALWAYS_INLINE void onClient(AcConnectHandler cb, void *arg);
  ASYNCTCP_ALWAYS_INLINE void begin();
  ASYNCTCP_ALWAYS_INLINE void end();
  ASYNCTCP_ALWAYS_INLINE void setNoDelay(bool nodelay);
  ASYNCTCP_ALWAYS_INLINE bool getNoDelay() const;
  ASYNCTCP_ALWAYS_INLINE uint8_t status() const;
  int8_t _accepted(AsyncClient *client);
};

/*
  Ready list

  What LwIP reports for a client is recorded on the client itself, and the client goes on
  this list - once, however much it is owed.  The async task takes the client at the front
  and delivers one thing; if more is owed, the client goes to the back.  Recording an event
  never allocates, so nothing LwIP reports can be lost for want of memory.

  A client that has not yet been handed to the application (it has no facade) is not
  listed; what it is owed waits until it is.  Guarded by the queue mutex.
*/
enum : uint8_t {
  pending_connected = 1 << 0,
  pending_fin = 1 << 1,
  pending_poll = 1 << 2,
};

static ready_fifo<AsyncClientImpl> _ready_clients;
static ready_fifo<AsyncServerImpl> _ready_servers;  // servers with accepted connections waiting

// The task sleeps only once it has found both lists empty, so only then does it need waking.
static bool _ready_idle() {
  return !_ready_clients.head && !_ready_servers.head;
}

// The client whose callback the async task is running, if any.  Guarded by the queue mutex.
static AsyncClientImpl *_servicing = nullptr;
static AsyncServerImpl *_servicing_server = nullptr;  // likewise, the server whose onClient is running

static bool _is_owed(const AsyncClientImpl *client) {
  return client->_pending_err || client->_pending || client->_acked || !client->_rx.empty();
}

// List a client that is owed something, unless it already is, or has no facade yet.
static void _ready_client(AsyncClientImpl *client) {
  if (!ready_fifo<AsyncClientImpl>::listed(client) && client->_facade) {
    const bool idle = _ready_idle();
    _ready_clients.push_back(client);
    if (idle) {
      xTaskNotifyGive(_async_service_task_handle);
    }
  }
}

// Must hold the queue mutex.  Forget everything a client is owed, returning its data for
// the caller to free once the mutex is released.
static pbuf_ring _discard_locked(AsyncClientImpl *client) {
  client->_pending_err = 0;
  client->_pending = 0;
  client->_acked = 0;
  return client->_rx.take();
}

// Must hold the queue mutex.  End the connection with err, which replaces anything else
// still owed, including a connect not yet reported.
static pbuf_ring _fail_locked(AsyncClientImpl *client, int8_t err) {
  ASYNCTCP_ASSERT(err != ERR_OK);
  pbuf_ring rx = _discard_locked(client);
  client->_pending_err = err;
  _ready_client(client);
  return rx;
}

// Forget everything a client is owed.  Must be called in LwIP context, so nothing new can
// arrive behind it.  Returns whether an error was pending.
static bool _clear_pending(AsyncClientImpl *client) {
  pbuf_ring rx;
  bool had_error;
  {
    queue_mutex_guard guard(queue_mutex_guard::if_created);
    if (!guard) {
      // Never started, so nothing can have been recorded.
      return false;
    }
    had_error = client->_pending_err != 0;
    rx = _discard_locked(client);
  }
  rx.free();
  return had_error;
}

// Release an implementation whose facade was destroyed while the async task had it.  Out
// of line: it is rare.
template<typename T> static void __attribute__((noinline)) _release(T *impl) {
  impl->_ready_self.reset();
}

// Must hold the queue mutex.  Finished with impl: return it if its facade went meanwhile, as
// it is then ours to release.
template<typename T> static ASYNCTCP_ALWAYS_INLINE T *_finish(T *&servicing) {
  T *impl = servicing;
  servicing = nullptr;
  return (impl && impl->_ready_self && !ready_fifo<T>::listed(impl)) ? impl : nullptr;
}

// Deliver one accepted connection.  Out of line: accepts are rare.
bool __attribute__((noinline)) AsyncTCP_detail::service_accept() {
  AsyncServerImpl *server;
  AsyncServerImpl *orphan;
  std::shared_ptr<AsyncClientImpl> client;  // released after the mutex
  int8_t err = 0;
  {
    queue_mutex_guard guard;
    orphan = _finish(_servicing_server);
    server = _ready_servers.pop_front();
    ASYNCTCP_ASSERT(server);  // only this task takes servers off the list
    _servicing_server = server;
    if (AsyncClientImpl *accepted = server->_accepts.pop_front()) {
      client = std::move(accepted->_ready_self);
      err = accepted->_pending_err;
    }
    if (server->_accepts.head) {
      _ready_servers.push_back(server);
    }
  }
  if (orphan) {
    _release(orphan);
  }
  // One that failed before it could be delivered is dropped as though it never arrived.
  if (client && !err) {
    AsyncClient *c = new (std::nothrow) AsyncClient(client);
    if (c) {
      server->_accepted(c);
    } else {
      client->close();  // Failed to create a client facade
    }
  }
  return true;
}

/*
  Must hold the queue mutex.  Take the one thing next owed to a client: connected, ack, data,
  FIN, then poll.  A pending error is taken alone, as it discarded the rest when it arrived.
*/
static ASYNCTCP_ALWAYS_INLINE lwip_tcp_event_packet_t _take_event(AsyncClientImpl *client) {
  lwip_tcp_event_packet_t e;
  e.pcb = client->_pcb;
  if (client->_pending_err) {
    e.event = LWIP_TCP_ERROR;
    e.error.err = client->_pending_err;
    client->_pending_err = 0;
  } else if (client->_pending & pending_connected) {
    e.event = LWIP_TCP_CONNECTED;
    client->_pending &= ~pending_connected;
  } else if (client->_acked) {
    e.event = LWIP_TCP_SENT;
    e.sent.len = client->_acked;
    e.sent.time = client->_acked_time;
    client->_acked = 0;
  } else if (!client->_rx.empty()) {
    e.event = LWIP_TCP_RECV;
    e.recv.pb = client->_rx.pop();
  } else if (client->_pending & pending_fin) {
    e.event = LWIP_TCP_FIN;
    client->_pending &= ~pending_fin;
  } else if (client->_pending & pending_poll) {
    e.event = LWIP_TCP_POLL;
    client->_pending &= ~pending_poll;
  } else {
    e.event = LWIP_TCP_NONE;  // closed since it was listed
  }
  return e;
}

static ASYNCTCP_ALWAYS_INLINE void handle_async_event(AsyncClientImpl *client, lwip_tcp_event_packet_t &e) {
  if (!client->_facade) {
    // Detached since it was taken: closing discarded the rest, but not what we took.  The
    // check is unlocked, so a facade destroyed on another task can still slip past it into
    // a callback, as the facade pointer handed to callbacks always could.
    if (e.event == LWIP_TCP_RECV) {
      pbuf_free(e.recv.pb);
    }
    return;
  }
  switch (e.event) {
    case LWIP_TCP_ERROR:     client->_error(e.error.err); break;
    case LWIP_TCP_CONNECTED: client->_connected(e.pcb, ERR_OK); break;
    case LWIP_TCP_SENT:      client->_sent(e.pcb, e.sent.len, e.sent.time); break;
    case LWIP_TCP_RECV:      client->_recv(e.pcb, e.recv.pb, ERR_OK); break;
    case LWIP_TCP_FIN:       client->_fin(e.pcb, ERR_OK); break;
    case LWIP_TCP_POLL:      client->_poll(e.pcb); break;
    case LWIP_TCP_NONE:      break;
  }
}

/*
  Deliver one thing.  Accepted connections come first, so the application learns of a
  connection promptly; what it is owed waits regardless, as it is not listed until it has a
  facade.  Otherwise, deliver one thing owed to the client at the front of the ready list.
  Returns false if there was nothing to do.
*/
bool AsyncTCP_detail::service() {
  AsyncClientImpl *client = nullptr;
  AsyncClientImpl *orphan;
  AsyncServerImpl *orphan_server = nullptr;
  bool accept;
  lwip_tcp_event_packet_t e;
  {
    queue_mutex_guard guard;
    orphan = _finish(_servicing);
    accept = _ready_servers.head;
    if (!accept && _servicing_server) {
      orphan_server = _finish(_servicing_server);
    }
    if (!accept && (client = _ready_clients.pop_front())) {
      _servicing = client;
      e = _take_event(client);
      if (_is_owed(client)) {
        _ready_clients.push_back(client);
      }
    }
  }
  if (orphan) {
    _release(orphan);
  }
  if (orphan_server) {
    _release(orphan_server);
  }
  if (accept) {
    return service_accept();
  }
  if (!client) {
    return false;
  }
  handle_async_event(client, e);
  return true;
}

static void _async_service_task(void *pvParameters) {
  async_tcp_log_d("Task 'async_tcp' started on core %d", static_cast<int>(xPortGetCoreID()));
#if CONFIG_ASYNC_TCP_USE_WDT
  if (esp_task_wdt_add(NULL) != ESP_OK) {
    async_tcp_log_w("Failed to add async task to WDT");
  }
#endif
  for (;;) {
    while (AsyncTCP_detail::service()) {
#if CONFIG_ASYNC_TCP_USE_WDT
      esp_task_wdt_reset();
#endif
    }
    ulTaskNotifyTake(pdTRUE, ASYNC_TCP_MAX_TASK_SLEEP);
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

// Defined with the other api calls below; tcp_dns_found() dials through it directly.
static err_t _tcp_connect_in_context(AsyncClientImpl *client, const ip_addr_t *addr, uint16_t port);

// Attach an AsyncClient to a TCP PCB by setting the appropriate LwIP callbacks and argument.
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
    _clear_pending(client);
  }
}

//  Stand down any outstanding name lookup.  Run in LwIP context to ensure atomicity with the tcp_dns_found() callback.
static void _abandon_resolve(AsyncClientImpl *client) {
  if (client) {
    client->_dns_token = nullptr;
  }
}

// Callback when a connection is established.  pcb is already bound to the client.
static int8_t _tcp_connected(void *arg, tcp_pcb *pcb, int8_t err) {
  // ets_printf("+C: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  client->_rx_last_packet = millis();
  queue_mutex_guard guard;
  client->_pending |= pending_connected;
  _ready_client(client);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_poll(void *arg, struct tcp_pcb *pcb) {
  if (pcb->state < ESTABLISHED) {
    // Still connecting; LwIP handles the SYN timeout itself
    return ERR_OK;
  }

  // ets_printf("+P: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  queue_mutex_guard guard;
  client->_pending |= pending_poll;
  _ready_client(client);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, int8_t err) {
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  client->_rx_last_packet = millis();
  pbuf *end = pb ? pbuf_ring::end_of(pb) : nullptr;
  queue_mutex_guard guard;
  if (pb) {
    // ets_printf("+R: 0x%08x\n", pcb);
    client->_rx.push(pb, end);
  } else {
    // ets_printf("+F: 0x%08x\n", pcb);
    client->_pending |= pending_fin;
  }
  _ready_client(client);
  return ERR_OK;
}

int8_t AsyncTCP_detail::tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len) {
  // ets_printf("+S: 0x%08x\n", pcb);
  AsyncClientImpl *client = reinterpret_cast<AsyncClientImpl *>(arg);
  uint32_t now = millis();
  // Update timeout tracking
  if (client->_ack_since) {
    // Re-arm the timer if we've still got outstanding data; otherwise cancel it
    client->_ack_since = (tcp_sndqueuelen(pcb) ? (now - (now == 0)) : 0);
  }
  client->_rx_last_packet = now;

  queue_mutex_guard guard;
  // Acks not yet delivered are merged; the time is the latest one's.
  client->_acked += len;
  client->_acked_time = now - client->_tx_last_packet;
  _ready_client(client);
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

  // LwIP has already freed the pcb; do not attempt to clear the callbacks.  Clear the
  // saved value in the client object to avoid future use.
  client->_pcb = nullptr;

  pbuf_ring rx;
  {
    queue_mutex_guard guard;
    rx = _fail_locked(client, err);
  }
  rx.free();
}

void AsyncTCP_detail::tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg) {
  // ets_printf("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
  // 'name' points into LwIP's DNS table, which the next lookup recycles; don't keep it.
  (void)name;
  // Adopt ownership of the callback state from the argument passed by LwIP.
  std::unique_ptr<std::weak_ptr<AsyncClientImpl>> callback_state(reinterpret_cast<std::weak_ptr<AsyncClientImpl> *>(arg));
  // Validate that our client still exists.
  auto client = callback_state->lock();
  if (!client) {
    return;  // the implementation was destroyed while the lookup was in flight
  }

  // Validate that we're the most recent DNS lookup for this client.
  if (client->_dns_token != callback_state.get()) {
    return;  // close(), abort() or a newer lookup superseded this query
  }
  const uint16_t port = client->_connect_port;
  client->_dns_token = nullptr;  // lookup complete

  // Check that client isn't already open?
  if (client->_pcb) {
    return;  // connected by some other route while we were resolving
  }

  // Treat any-address or blocklist responses as failed lookups.
  const bool resolved = (ipaddr != nullptr) && !ip_addr_isany_val(*ipaddr);

  // Start the connection right away; we're already in LwIP context
  if (resolved && _tcp_connect_in_context(client.get(), ipaddr, port) == ERR_OK) {
    return;
  }

  // The original DNS-based connect() reported "success" to the caller, so we must notify
  // them of the failure.
  pbuf_ring rx;
  {
    queue_mutex_guard guard;
    rx = _fail_locked(client.get(), resolved ? ERR_CONN : -55);
  }
  rx.free();
}

/*
 * TCP/IP API Calls
 * */

/*
  Context structure for `tcpip_api_call`, ie. code running in LwIP context.
  The pcb is always reached through `client`.
*/
typedef struct {
  struct tcpip_api_call_data call;
  AsyncClientImpl *client;
  int8_t err;
  union {
    size_t close_ack;  // bytes to tcp_recved() before closing, in the same pass
    size_t received;
    struct {
      const ip_addr_t *addr;
      uint16_t port;
    } connect;
    struct {
      const char *host;
      ip_addr_t *addr;
      std::weak_ptr<AsyncClientImpl> *token;
      uint16_t port;
    } dns;
  };
} tcp_api_call_t;

static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (msg->client->_pcb) {
    msg->err = 0;
    tcp_recved(msg->client->_pcb, msg->received);
  }
  return msg->err;
}

static esp_err_t _tcp_recved(AsyncClientImpl *client, size_t len) {
  if (!client->_pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.client = client;
  msg.received = len;
  tcpip_api_call(_tcp_recved_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg) {
  // Unlike the other calls, this is not a direct wrapper of the LwIP function; we perform
  // the AsyncClient teardown interlocked safely with the LwIP task.

  // As a postcondition, nothing is pending for this client.  This is because an error
  // can have arrived, clearing the pcb*, after the async thread has committed to
  // closing/destructing the AsyncClient.

  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  AsyncClientImpl *client = msg->client;
  msg->err = ERR_CONN;
  _abandon_resolve(client);
  if (client->_pcb) {
    tcp_pcb *pcb = client->_pcb;
    // Ack anything the application withheld, in this same pass.  Done as a separate call
    // the LwIP thread could run in between, and the peer would get an RST rather than a
    // FIN for data that was in fact processed.
    if (msg->close_ack) {
      tcp_recved(pcb, msg->close_ack);
    }
    _reset_tcp_callbacks(pcb, client);
    if (tcp_close(pcb) != ERR_OK) {
      // We do not permit failure here: abandon the pcb anyways.
      tcp_abort(pcb);
    }
    msg->err = ERR_OK;
    client->_pcb = nullptr;  // PCB is now the property of LwIP
  } else {
    // Ensure there is not an error pending for this client
    if (_clear_pending(client)) {
      msg->err = ERR_OK;  // dispose needs to be run
    }
  }
  return msg->err;
}

static esp_err_t _tcp_close(AsyncClientImpl *client, size_t ack) {
  tcp_api_call_t msg;
  msg.client = client;
  msg.close_ack = ack;
  tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg) {
  // Like close(), we must ensure that nothing is left pending for the AsyncClient.
  // ERR_ABRT: the pcb was aborted.
  // ERR_OK:   the pcb was already gone, but a pending error was discarded, so the
  //           caller must still run the discard callback (dispose needs to run).
  // ERR_CONN: nothing to do (pcb already null and no pending error).
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  AsyncClientImpl *client = msg->client;
  _abandon_resolve(client);
  if (client->_pcb) {
    _reset_tcp_callbacks(client->_pcb, client);
    tcp_abort(client->_pcb);
    client->_pcb = nullptr;  // PCB is now the property of LwIP
    msg->err = ERR_ABRT;
  } else {
    msg->err = _clear_pending(client) ? ERR_OK : ERR_CONN;
  }
  return msg->err;
}

static esp_err_t _tcp_abort(AsyncClientImpl *client) {
  // No early return on a null pcb.  An outstanding lookup is a second thing LwIP is
  // holding, and standing it down has to happen inside the interlock.
  tcp_api_call_t msg;
  msg.client = client;
  tcpip_api_call(_tcp_abort_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_connect_in_context(AsyncClientImpl *client, const ip_addr_t *addr, uint16_t port) {
#if LWIP_IPV4 && LWIP_IPV6
  tcp_pcb *pcb = tcp_new_ip_type(addr->type);
#else
  tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
#endif
  if (!pcb) {
    async_tcp_log_e("pcb == NULL");
    return ERR_MEM;
  }

  // Take ownership of the pcb
  client->_adopt(pcb);

  err_t err = tcp_connect(pcb, addr, port, (tcp_connected_fn)&_tcp_connected);
  if (err != ERR_OK) {
    // Failure - clean up
    _reset_tcp_callbacks(pcb, nullptr);
    // Work around LwIP bug
    // tcp_connect() may have taken a local port without adding the pcb to
    // tcp_bound_pcbs.  Clear it, or tcp_close() will try to remove the pcb from a list
    // it was never on.
    pcb->local_port = 0;
    if (tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
    }
    client->_pcb = nullptr;
    // Note that _adopt() armed _dispose_owed; the caller will need to clear it if it is no longer needed.
  }

  return err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = _tcp_connect_in_context(msg->client, msg->connect.addr, msg->connect.port);
  // On a failure, release _dispose_owed while we still hold the LwIP lock.
  if (msg->err != ERR_OK) {
    msg->client->_dispose_owed = false;
  }
  return msg->err;
}

static esp_err_t _tcp_connect(AsyncClientImpl *client, const ip_addr_t *addr, uint16_t port) {
  tcp_api_call_t msg;
  msg.client = client;
  msg.connect.addr = addr;
  msg.connect.port = port;
  tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

/*
  Start a name lookup and publish its token as one transaction.

  These cannot be separate steps.  LwIP answers on its own thread, so a token published
  after dns_gethostbyname() returns can arrive too late: the callback finds no token,
  concludes it has been superseded, and drops an answer the caller is still waiting for -
  leaving connect() having reported success that never resolves either way.

  Taking the LwIP core lock around just the lookup would not fix it, and not only because
  the window would remain: that lock does not exist without CONFIG_LWIP_TCPIP_CORE_LOCKING,
  where the interlock is the api call itself and nothing else.
*/
static err_t _tcp_dns_start_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  AsyncClientImpl *client = msg->client;

  // Supersedes any lookup already outstanding; that one will find the token moved on.
  if (client->_dns_token) {
    // The displaced lookup will never report, so its obligation dies with it rather than
    // passing to this attempt - which may answer from cache and never arm one of its own,
    // and would then refuse itself on a notice nobody can ever deliver.
    client->_dispose_owed = false;
  }
  client->_connect_port = msg->dns.port;
  client->_dns_token = msg->dns.token;

  msg->err = dns_gethostbyname(msg->dns.host, msg->dns.addr, (dns_found_callback)&AsyncTCP_detail::tcp_dns_found, msg->dns.token);
  if (msg->err == ERR_INPROGRESS) {
    // Reporting success promises onConnect or onError, and a dispose with it, even though no
    // pcb exists yet (and may never).  Armed here rather than on return: the answer can land
    // the instant this transaction ends, and an error reported before the caller had armed it
    // would consume a notification that was not yet owed - and then rearm it forever.
    client->_dispose_owed = true;
  } else {
    client->_dns_token = nullptr;  // no callback is coming
  }
  return msg->err;
}

static err_t _tcp_dns_start(AsyncClientImpl *client, const char *host, ip_addr_t *addr, uint16_t port, std::weak_ptr<AsyncClientImpl> *token) {
  tcp_api_call_t msg;
  msg.client = client;
  msg.dns.host = host;
  msg.dns.addr = addr;
  msg.dns.port = port;
  msg.dns.token = token;
  tcpip_api_call(_tcp_dns_start_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

/*
  Async TCP Client
 */

AsyncClientImpl::AsyncClientImpl(AsyncClient *facade)
  : _pcb(nullptr), _connect_port(0), _dns_token(nullptr), _dispose_owed(false), _pending_err(0), _pending(0), _acked(0), _acked_time(0), _ready_next(this),
    _facade(facade), _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0), _error_cb_arg(0),
    _recv_cb(0), _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true),
    _tx_last_packet(0), _rx_ack_len(0), _rx_last_packet(0), _rx_timeout(0), _ack_since(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME),
    _in_callback_ack_len(0) {}

AsyncClientImpl::~AsyncClientImpl() {
  // Every path that drops the last reference must ensure the binding was cleared first.
  // This can be called from the LwIP thread, so any cleanup must have been performed already.
  ASYNCTCP_ASSERT(!_pcb);
  ASYNCTCP_ASSERT(!ready_fifo<AsyncClientImpl>::listed(this));
}

AsyncClient::AsyncClient(tcp_pcb *pcb) : _impl(make_shared_nothrow<AsyncClientImpl>(this)) {
  if (pcb) {
    // The pcb's callbacks list the client, so the task must be there to service it.
    if (!_impl) {
      async_tcp_log_e("failed to allocate client");
    } else if (!_start_async_task()) {
      async_tcp_log_e("failed to start task");
    } else {
      _impl->_adopt(pcb);
      return;
    }
    // The pcb is ours, and nothing could deliver its events.  Close rather than abort:
    // in an accept callback, only the callback's return value can report ERR_ABRT.
    if (tcp_close(pcb) != ERR_OK) {
      async_tcp_log_e("failed to close pcb");
    }
  }
}

AsyncClient::AsyncClient(std::shared_ptr<AsyncClientImpl> impl) : _impl(std::move(impl)) {
  // Under the queue mutex, so LwIP either holds what it reports until now, or lists it.
  queue_mutex_guard guard;
  _impl->_facade = this;
  if (_is_owed(_impl.get())) {
    _ready_client(_impl.get());
  }
}

AsyncClient::~AsyncClient() {
  if (!_impl) {
    return;
  }
  // Unconditional, because whether there is anything to close is not knowable from here -
  // _pcb and the lookup token are both written by the LwIP thread, and a name lookup can
  // still turn into a bound pcb after we have looked.
  _impl->close();
  // Detach: the async task may still reach the implementation, but must not run user code
  // against a facade that no longer exists.  If it has the implementation listed or in hand,
  // it takes over our reference and releases it once done.
  queue_mutex_guard guard(queue_mutex_guard::if_created);
  _impl->_facade = nullptr;
  if (ready_fifo<AsyncClientImpl>::listed(_impl.get()) || _servicing == _impl.get()) {
    _impl->_ready_self = std::move(_impl);
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
  if (_dns_token) {
    async_tcp_log_d("name resolution in progress");
    return false;
  }
  if (_dispose_owed) {
    // A previous failed connection has not reported yet - the error is
    // still pending (otherwise we'd have _pcb).  Treat this as "not ready
    // for a new connection".
    async_tcp_log_d("previous connection not yet reported");
    return false;
  }
  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  // One pass through the LwIP context for the whole sequence; see
  // _tcp_connect_in_context().  On failure it has already disposed of the pcb and cleared
  // _pcb, and no callbacks were raised.
  if (_tcp_connect(this, &addr, port) == ERR_OK) {
    return true;
  }
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
  // For compatibility, calling `connect()` with a lookup outstanding supersedes
  // the previous lookup.
  if (_dispose_owed && !_dns_token) {
    // The previous connection has errored out but its error hasn't been delivered.
    // We can't cancel it -- it may already be pending on the async task.
    // So we treat this as "not ready for a new connection".
    async_tcp_log_d("previous connection not yet reported");
    return false;
  }

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return false;
  }

  // A lookup already in flight is superseded rather than refused.  Ignoring the new
  // call would silently dial the *previous* host and port and report success for it;
  // refusing would be the better API, but previous versions would (brokenly) accept
  // this (and then leak).  The classic case is a client retrying a "wedged" lookup --
  // it's not really wedged, LwIP guarantees a return, but the timeouts might be longer
  // than a client might expect.
  // To avoid this leak, we allocate a unique "lookup context" for each request, and
  // validate it when the request completes.  Ownership of the context lives in the
  // LwIP DNS callback once triggered.
  std::unique_ptr<std::weak_ptr<AsyncClientImpl>> callback_state(new (std::nothrow) std::weak_ptr<AsyncClientImpl>(shared_from_this()));
  if (!callback_state) {
    async_tcp_log_e("Failed to allocate the lookup context");
    return false;
  }

  // Initiate DNS transaction
  const err_t err = _tcp_dns_start(this, host, &addr, port, callback_state.get());

  if (err == ERR_INPROGRESS) {
    // DNS lookup in progress; _tcp_dns_start_api armed _dispose_owed inside the transaction
    callback_state.release();  // now tcp_dns_found's to destroy
    return true;
  }

  if (err == ERR_OK) {
    // Answered from the cache, or the name was a literal address
    // Validate the resolved address (same rules as tcp_dns_found)
    if (ip_addr_isany_val(addr)) {
      async_tcp_log_d("lookup returned the any-address");
      return false;
    }
    // We can delegate to the direct connection function here.
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
  // Ack anything withheld by ackLater(), plus the packet onData is holding right now if
  // we are being called from inside it.  Without this the peer gets an RST rather than a
  // FIN for data the application did in fact process.
  const size_t pending = _rx_ack_len + _in_callback_ack_len;
  _rx_ack_len = 0;
  _in_callback_ack_len = 0;
  _tcp_close(this, pending);
  // _pcb is now NULL, nothing is pending, and any outstanding lookup has been
  // stood down.  Call the dispose callback if owed.
  if (_facade && _dispose_owed) {
    _dispose_owed = false;
    if (_discard_cb) {
      auto self = shared_from_this();  // ensure our object stays in scope during the callback
      async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
    }
  }
}

int8_t AsyncClientImpl::abort() {
  int8_t err = _tcp_abort(this);
  // _pcb is now NULL
  // LwIP invokes the error callback when abort is issued; preserve this semantic.
  // This will also trigger the dispose callback if otherwise owed (ie. error is already pending or canceling a DNS lookup).
  // If the pcb was previously invalidated by some other pending error, we've discarded that value; so we always send ERR_ABRT.
  if (err != ERR_CONN || _dispose_owed) {
    _error(ERR_ABRT);
  }
  return err;
}

size_t AsyncClientImpl::space() const {
  auto st = state();
  if (st == ESTABLISHED || st == CLOSE_WAIT) {
    return tcp_sndbuf(_pcb);
  }
  return 0;
}

// Callers must hold the TCP core lock
size_t AsyncClientImpl::_add_locked(const char *data, size_t size, uint8_t apiflags) {
  size = std::min(size, space());
  if (size == 0 || tcp_write(_pcb, data, size, apiflags) != ERR_OK) {
    return 0;
  }
  return size;
}

err_t AsyncClientImpl::_send_locked() {
  uint32_t now = millis();
  _tx_last_packet = now;  // Save timestamp for `sent` callback
  // Re-arm the timer only if it's not already active and there's something to send
  if (!_ack_since && tcp_sndqueuelen(_pcb)) {
    _ack_since = now - (now == 0);  // ensure is nonzero
  }
  return tcp_output(_pcb);
}

size_t AsyncClientImpl::add(const char *data, size_t size, uint8_t apiflags) {
  if (size == 0 || data == NULL) {
    return 0;
  }
  with_tcp_core_lock([&]() -> err_t {
    if (!_pcb) {
      size = 0;
      return ERR_CONN;
    };
    size = _add_locked(data, size, apiflags);
    return ERR_OK;
  });
  return size;
}

bool AsyncClientImpl::send() {
  auto err = with_tcp_core_lock([&]() -> err_t {
    if (!_pcb) {
      return ERR_CONN;
    };
    return _send_locked();
  });
  return (err == ERR_OK);
}

size_t AsyncClientImpl::write(const char *data, size_t size, uint8_t apiflags) {
  if (size == 0 || data == NULL) {
    return 0;
  }
  size_t added = 0;
  with_tcp_core_lock([&]() -> err_t {
    if (_pcb) {
      added = _add_locked(data, size, apiflags);
      if (added) {
        _send_locked();  // on failure lwIP keeps the data queued and retries
      }
    }
    return ERR_OK;
  });
  return added;
}

size_t AsyncClientImpl::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  if (len) {
    _tcp_recved(this, len);
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClientImpl::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  _tcp_recved(this, pb->len);
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

// Adopt a pcb and reset all per-connection state.  Callers must already be
// serialized against the LwIP core - called from inside a transaction, or from a callback.
void AsyncClientImpl::_adopt(tcp_pcb *pcb) {
  _dispose_owed = true;  // a bound pcb owes the application a terminal notification
  _pcb = pcb;
  _rx_ack_len = 0;
  _tx_last_packet = 0;
  _ack_since = 0;
  _rx_last_packet = millis();
  _bind_tcp_callbacks(pcb, this);
}

int8_t AsyncClientImpl::_connected(tcp_pcb *pcb, int8_t err) {
  if (pcb != _pcb) {
    // Stale event for a pcb we no longer own
    async_tcp_log_d("%p != %p", (const void *)pcb, (const void *)_pcb);
    return ERR_OK;
  }
  if (_connect_cb) {
    async_tcp_log_elapsed("onConnect", _connect_cb(_connect_cb_arg, _facade));
  }
  return ERR_OK;
}

void AsyncClientImpl::_error(int8_t err) {
  // Hold a reference to self to ensure this remains valid throughout the user callbacks.
  auto self = shared_from_this();
  // Claim the notification before running anything: onError may destroy the AsyncClient,
  // and ~AsyncClient() closes, which would otherwise report this same connection again.
  const bool owed = _dispose_owed;
  _dispose_owed = false;
  // Run error callback
  if (_error_cb) {
    async_tcp_log_elapsed("onError", _error_cb(_error_cb_arg, _facade, err));
  }
  // Things could have been changed under that callback:
  // - User might have deleted the AsyncClient (_facade is now nullptr)
  // - User might have reconnected the object (re-armed _dispose_owed)
  // In either case, we skip the dispose.
  if (owed && _facade && !_dispose_owed && _discard_cb) {
    async_tcp_log_elapsed("onDisconnect", _discard_cb(_discard_cb_arg, _facade));
  }
}

int8_t AsyncClientImpl::_fin(tcp_pcb *pcb, int8_t err) {
  if (_pcb != pcb) {
    return ERR_CONN;
  }
  close();
  return ERR_OK;
}

int8_t AsyncClientImpl::_sent(tcp_pcb *pcb, uint32_t len, uint32_t time) {
  if (_pcb != pcb) {
    return ERR_CONN;
  }
  if (_sent_cb) {
    async_tcp_log_elapsed("onAck", _sent_cb(_sent_cb_arg, _facade, len, time));
  }
  return ERR_OK;
}

int8_t AsyncClientImpl::_recv(tcp_pcb *pcb, pbuf *pb, int8_t err) {
  while (pb != NULL) {
    // Ensure the object is still valid and the pcb we're processing for is still the one held.
    // The callback (or other user code) could close the connection, destroy the client, or
    // replace the connection outright while we're in the loop.
    if (_pcb != pcb || !_facade) {
      break;
    }

    // we should not ack before we assimilate the data
    _ack_pcb = true;
    // Inline pbuf pop, similar to pbuf_dechain
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    b->tot_len = b->len;
    if (_pb_cb) {
      // The callback owns b now, and must ackPacket() or free it
      async_tcp_log_elapsed("onPacket", _pb_cb(_pb_cb_arg, _facade, b));
    } else {
      // Visible to close(), so closing from inside onData still acks this packet
      _in_callback_ack_len = b->len;
      if (_recv_cb) {
        async_tcp_log_elapsed("onData", _recv_cb(_recv_cb_arg, _facade, b->payload, b->len));
      }
      pbuf_free(b);
      if (_pcb != pcb) {
        // Bizarre as it might sound, it's actually possible for the user callback to reconnect.
        _in_callback_ack_len = 0;
        break;
      }
      if (_in_callback_ack_len) {
        if (!_ack_pcb) {
          _rx_ack_len += _in_callback_ack_len;
        } else {
          _tcp_recved(this, _in_callback_ack_len);
        }
        _in_callback_ack_len = 0;
      }
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
    async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)(uintptr_t)pcb, (uint32_t)(uintptr_t)_pcb);
    return ERR_OK;
  }

  uint32_t now = millis();

  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    async_tcp_log_d("rx timeout %d", state());
    close();
    return ERR_OK;  // connection is now closed; don't call poll callback
  }

  // ACK Timeout
  if (_ack_timeout) {
    uint32_t since = _ack_since;  // Not quite interlocked with LwIP - safe enough
    // If timeout is armed and timeout has expired
    if (since && (now - since) >= _ack_timeout) {
      async_tcp_log_d("ack timeout %d", state());
      if (_timeout_cb) {
        async_tcp_log_elapsed("onTimeout", _timeout_cb(_timeout_cb_arg, _facade, (now - since)));
        return ERR_OK;  // do not call poll callback
      }
      // Otherwise fall through to poll
    }
  }

  // Everything is fine
  if (_poll_cb) {
    async_tcp_log_elapsed("onPoll", _poll_cb(_poll_cb_arg, _facade));
  }
  return ERR_OK;
}

/*
 * Public Helper Methods
 * */

bool AsyncClientImpl::free() {
  return this->freeable();  // these are synonymous
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
  with_tcp_core_lock([&]() {
    if (!_pcb) {
      return ERR_CONN;
    }
    if (nodelay) {
      tcp_nagle_disable(_pcb);
    } else {
      tcp_nagle_enable(_pcb);
    }
    return ERR_OK;
  });
}

bool AsyncClientImpl::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClientImpl::setKeepAlive(uint32_t ms, uint8_t cnt) {
  with_tcp_core_lock([&]() {
    if (!_pcb) {
      return ERR_CONN;
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
    return ERR_OK;
  });
}

uint16_t AsyncClientImpl::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClientImpl::getRemoteAddress() const {
  return getRemoteAddress4().addr;
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
  return getLocalAddress4().addr;
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
  if (_dns_token) {
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
  if (_dns_token) {
    return false;  // resolving the hostname
  }
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClientImpl::freeable() const {
  return !connecting() && !connected();
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
    case ERR_ALREADY:    return "Already connecting";
    case ERR_ISCONN:     return "Already connected";
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
 * Every method below forwards to the reference-counted implementation.  _impl is null only
 * if it could not be allocated.  Such a client can never connect, so only the methods used
 * before connecting, and to clean up, check for it.
 */

bool AsyncClient::connect(ip_addr_t addr, uint16_t port) {
  return _impl && _impl->connect(addr, port);
}

bool AsyncClient::connect(const char *host, uint16_t port) {
  return _impl && _impl->connect(host, port);
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port) {
  return _impl && _impl->connect(ip, port);
}
#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port) {
  return _impl && _impl->connect(ip, port);
}
#endif
#endif

void AsyncClient::close() {
  if (_impl) {
    _impl->close();
  }
}

int8_t AsyncClient::abort() {
  if (!_impl) {
    return ERR_CONN;
  }
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
  if (_impl) {
    _impl->_connect_cb = cb;
    _impl->_connect_cb_arg = arg;
  }
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void *arg) {
  if (_impl) {
    _impl->_discard_cb = cb;
    _impl->_discard_cb_arg = arg;
  }
}

void AsyncClient::onAck(AcAckHandler cb, void *arg) {
  if (_impl) {
    _impl->_sent_cb = cb;
    _impl->_sent_cb_arg = arg;
  }
}

void AsyncClient::onError(AcErrorHandler cb, void *arg) {
  if (_impl) {
    _impl->_error_cb = cb;
    _impl->_error_cb_arg = arg;
  }
}

void AsyncClient::onData(AcDataHandler cb, void *arg) {
  if (_impl) {
    _impl->_recv_cb = cb;
    _impl->_recv_cb_arg = arg;
  }
}

void AsyncClient::onPacket(AcPacketHandler cb, void *arg) {
  if (_impl) {
    _impl->_pb_cb = cb;
    _impl->_pb_cb_arg = arg;
  }
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void *arg) {
  if (_impl) {
    _impl->_timeout_cb = cb;
    _impl->_timeout_cb_arg = arg;
  }
}

void AsyncClient::onPoll(AcConnectHandler cb, void *arg) {
  if (_impl) {
    _impl->_poll_cb = cb;
    _impl->_poll_cb_arg = arg;
  }
}

/*
  Async TCP Server
 */

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port) : _impl(make_shared_nothrow<AsyncServerImpl>(addr, port)) {}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) {
  ip_addr_t a;
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_V4;
  a.u_addr.ip4.addr = addr;
#else
  a.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&a);
#endif
  _impl = make_shared_nothrow<AsyncServerImpl>(a, port);
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(addr);
  ip_addr_t a = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_V6;
#endif
  _impl = make_shared_nothrow<AsyncServerImpl>(a, port);
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) {
  ip_addr_t a;
#if LWIP_IPV4 && LWIP_IPV6
  a.type = IPADDR_TYPE_ANY;
  a.u_addr.ip4.addr = INADDR_ANY;
#else
  a.addr = INADDR_ANY;
#endif
  _impl = make_shared_nothrow<AsyncServerImpl>(a, port);
}

AsyncServer::~AsyncServer() {
  if (!_impl) {
    return;
  }
  _impl->end();
  // If the async task has the implementation listed or in hand, it takes over our reference
  // and releases it once done.
  queue_mutex_guard guard(queue_mutex_guard::if_created);
  if (guard && (ready_fifo<AsyncServerImpl>::listed(_impl.get()) || _servicing_server == _impl.get())) {
    _impl->_ready_self = std::move(_impl);
  }
}

void AsyncServer::onClient(AcConnectHandler cb, void *arg) {
  if (_impl) {
    _impl->onClient(cb, arg);
  }
}
void AsyncServer::begin() {
  if (_impl) {
    _impl->begin();
  }
}
void AsyncServer::end() {
  if (_impl) {
    _impl->end();
  }
}
void AsyncServer::setNoDelay(bool nodelay) {
  if (_impl) {
    _impl->setNoDelay(nodelay);
  }
}
bool AsyncServer::getNoDelay() const {
  return _impl && _impl->getNoDelay();
}
uint8_t AsyncServer::status() const {
  return _impl ? _impl->status() : 0;
}

void AsyncServerImpl::begin() {
  if (_pcb) {
    return;
  }

  if (!_start_async_task()) {
    async_tcp_log_e("failed to start task");
    return;
  }

  /*
    Allocate, bind, listen and hook up the accept callback as one transaction.  This used
    to be five separate entries into the LwIP context, three of them taking only the core
    lock - which does not exist without CONFIG_LWIP_TCPIP_CORE_LOCKING - so the LwIP thread
    could see a pcb bound but not listening, or listening with no accept callback and no
    argument, and _pcb itself was published in stages.
  */
  auto err = with_tcp_core_lock([&]() -> err_t {
#if LWIP_IPV4 && LWIP_IPV6
    tcp_pcb *pcb = tcp_new_ip_type(_addr.type);
#else
    tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
#endif
    if (!pcb) {
      return ERR_MEM;
    }

    auto err = tcp_bind(pcb, &_addr, _port);
    if (err != ERR_OK) {
      // Never registered, so nothing can reach it; dispose of it here.
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return err;
    }

    tcp_pcb *listen_pcb = tcp_listen_with_backlog(pcb, ASYNCTCP_LISTEN_BACKLOG);
    if (!listen_pcb) {
      // LwIP frees the original only on success; ours is still bound, and holds the
      // port reserved until we release it.
      if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
      return ERR_MEM;
    }

    // Published last, and with its callbacks already attached: an accept cannot arrive
    // against a server that is not ready for it.
    tcp_arg(listen_pcb, this);
    tcp_accept(listen_pcb, &AsyncTCP_detail::tcp_accept);
    _pcb = listen_pcb;
    return ERR_OK;
  });  // end LwIP scope

  if (err != ERR_OK) {
    async_tcp_log_e("begin failed: %d", (int)err);
  }
}

void AsyncServerImpl::end() {
  // The mirror of begin(): stop listening, and close anything accepted but not yet delivered.
  // Those are released once we are out of the LwIP context.
  ready_fifo<AsyncClientImpl> orphans;
  with_tcp_core_lock([&]() -> err_t {
    if (_pcb) {
      tcp_arg(_pcb, NULL);
      tcp_accept(_pcb, NULL);
      if (tcp_close(_pcb) != ERR_OK) {
        tcp_abort(_pcb);
      }
      _pcb = NULL;  // PCB is now the property of LwIP
    }
    // Inside the transaction, so nothing more can be accepted behind it.
    {
      queue_mutex_guard guard(queue_mutex_guard::if_created);
      if (guard) {
        orphans = std::move(_accepts);
      }
    }
    for (AsyncClientImpl *c = orphans.head; c; c = c->_ready_next) {
      if (c->_pcb) {
        _reset_tcp_callbacks(c->_pcb, c);
        if (tcp_close(c->_pcb) != ERR_OK) {
          tcp_abort(c->_pcb);
        }
        c->_pcb = nullptr;
      }
    }
    return ERR_OK;
  });
  while (AsyncClientImpl *c = orphans.pop_front()) {
    c->_ready_self.reset();
  }
}

// runs on LwIP thread
int8_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *pcb, int8_t err) {
  // Note LwIP return value semantics:
  //  - ERR_OK: delivery successful
  //  - ERR_ABRT: the connection was aborted, discard your reference
  //  - Anything else: abort the connection

  if (!pcb) {
    async_tcp_log_e("_accept failed: pcb is NULL");
    return ERR_ABRT;
  }

  auto server = reinterpret_cast<AsyncServerImpl *>(arg);
  if (!server->_connect_cb) {
    async_tcp_log_e("_accept failed: no onConnect callback");
    tcp_abort(pcb);
    return ERR_ABRT;
  }

  // Apply our nodelay setting
  if (server->_noDelay) {
    tcp_nagle_disable(pcb);
  } else {
    tcp_nagle_enable(pcb);
  }

  // Allocate and initialize the AsyncClient implementation for this accepted connection.
  // The facade will be constructed by the async task when it delivers it -- if the connection
  // errors out before then, it is dropped as there's no API to inform the server of the error.
  auto client = make_shared_nothrow<AsyncClientImpl>(nullptr);
  if (!client) {
    async_tcp_log_e("_accept failed: couldn't allocate client");
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  client->_adopt(pcb);

  queue_mutex_guard guard;
  AsyncClientImpl *c = client.get();
  c->_ready_self = std::move(client);
  server->_accepts.push_back(c);
  if (!ready_fifo<AsyncServerImpl>::listed(server)) {
    const bool idle = _ready_idle();
    _ready_servers.push_back(server);
    if (idle) {
      xTaskNotifyGive(_async_service_task_handle);
    }
  }
  return ERR_OK;
}

int8_t AsyncServerImpl::_accepted(AsyncClient *client) {
  if (_connect_cb) {
    async_tcp_log_elapsed("onClient", _connect_cb(_connect_cb_arg, client));
  } else {
    delete client;  // nowhere to go
  }
  return ERR_OK;
}

void AsyncServerImpl::onClient(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServerImpl::setNoDelay(bool nodelay) {
  _noDelay = nodelay;
}

bool AsyncServerImpl::getNoDelay() const {
  return _noDelay;
}

uint8_t AsyncServerImpl::status() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}
