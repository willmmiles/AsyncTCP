# Host-native test harness

Compiles `src/AsyncTCP.cpp` with plain `g++` against mock lwIP, FreeRTOS and
Arduino headers, so the library's logic can be exercised on a Linux desktop
with no ESP32 and no network.

Nothing under `src/` is modified or needs to be.

## Running

```
make -C test/native run          # build + run           <- the primary path
make -C test/native SANITIZE=1 run   # + ASan/UBSan
make -C test/native verbose run  # also print the library's log_* output
make -C test/native clean
./test/native/build/asynctcp_tests server_   # run a subset by name substring
```

There is deliberately no `[env:native]` in `platformio.ini`: PlatformIO would
need `src_dir = .`, which breaks the ESP32 example builds that share the file.
Use the Makefile.

<!-- retained for reference if the src_dir clash is ever resolved:

```
pio run -e native            # build only
pio run -e native -t exec    # build and run
```

Both paths exit non-zero when a test fails.

`pio test -e native` is **not** wired up: the harness has its own `main()` and
does not use Unity, and PlatformIO's test runner wants to own both. Use
`pio run -e native -t exec`.
-->

## How the async task is pumped

`AsyncTCP` does its application-callback work on a FreeRTOS task
(`_async_service_task`), started once via `xTaskCreateUniversal`. Running that
as a real thread would make every test a race, so the harness does not.

Instead:

* the FreeRTOS mock's `xTaskCreateUniversal()` **records** the task function
  and its parameter and returns a fake handle, without starting anything;
* `asynctcp_test_pump()` calls that recorded function **on the calling
  thread**. The task's `for (;;)` body drains the library's event queue exactly
  as it would on target;
* when the queue is empty the task calls `ulTaskNotifyTake(pdTRUE,
  portMAX_DELAY)` to sleep. The mock notices it is inside a pump and throws a
  private `PumpExit` exception, which `asynctcp_test_pump()` catches.

So `asynctcp_test_pump()` means "run the async task until its queue is empty,
then return", and it returns the number of events handled.

This needs no hook in `src/`. It relies on two properties of the task loop, both
true today:

* no live objects span the `ulTaskNotifyTake()` call (the queue mutex guard
  lives and dies inside `_get_async_event()`), so the unwind is safe. It is a
  real C++ unwind, so destructors run — unlike a `longjmp`;
* the loop keeps no state across iterations, so re-entering it from the top on
  each pump is equivalent to letting it spin.

The build therefore **must** keep `-fexceptions`.

The event count comes from `esp_task_wdt_add()`, which the task calls exactly
once per handled event. If a future build sets `CONFIG_ASYNC_TCP_USE_WDT=0`,
pumping still works but the return value will be 0.

`_async_service_task_handle` is a file-static inside `src/AsyncTCP.cpp` that the
harness cannot reach, so once the library has started its task it stays
started for the life of the process. That is fine (the task is stateless) and is
why `mockrtos::reset()` deliberately does not forget the recorded task function.

## Layout

```
test/native/
  Makefile              build + run
  test_framework.h      TEST / CHECK macros
  test_main.cpp         registry, runner, per-test reset
  tests/*.cpp           the tests; add files here, the Makefile globs them
  mocks/
    include/            fake system headers -- on the include path FIRST, so
                        #include "lwip/tcp.h" etc. resolve here
      Arduino.h  IPAddress.h  IPv6Address.h  sdkconfig.h  esp_*.h
      NetworkInterface.h
      freertos/{FreeRTOS,task,semphr}.h   and bare {FreeRTOS,task,semphr}.h
      lwip/{arch,opt,err,pbuf,ip_addr,ip4_addr,ip6_addr,inet,tcp,dns,tcpip}.h
      lwip/priv/tcpip_priv.h
    mock_lwip.h/.cpp    mock lwIP stack + its test-facing control API
    mock_rtos.h/.cpp    FreeRTOS, mock clock, logging, the pump
```

`mock_lwip.h` and `mock_rtos.h` are for tests only; the library never sees them.

## What the mock lwIP models

Behaviour is matched to real lwIP wherever AsyncTCP's lifetime handling depends
on it:

* `tcp_abort()` frees the pcb and **then** invokes the error callback with
  `ERR_ABRT` (except on `LISTEN` pcbs).
* A fatal error (`fire_error`) frees the pcb **before** the error callback runs,
  so the pointer the library sees is already dangling.
* `tcp_close()` frees the pcb only when it returns `ERR_OK`.
* `tcp_listen_with_backlog()` on success allocates a **new** listen pcb and
  frees the one passed in; on failure it returns `NULL` and leaves the caller's
  pcb alone. (That asymmetry is what the `server_begin_frees_the_bound_pcb_when_listen_fails`
  known-fail test is about.)
* `tcp_connect()` failure does **not** free the pcb.
* Ports are tracked, so a second bind to a live port returns `ERR_USE` and a
  leaked listen pcb shows up as a leaked port.

`tcpip_api_call(fn, msg)` is the `CONFIG_LWIP_TCPIP_CORE_LOCKING` flavour: it
calls `fn(msg)` directly on the calling thread.

Addresses are kept in **host** byte order throughout (`htonl` and friends are
no-ops), which keeps `IPAddress(10,0,0,1)` and `pcb->remote_ip.u_addr.ip4.addr`
directly comparable.

## Adding a test

Drop a `.cpp` in `tests/`; the Makefile and `build_src_filter` both glob the
directory. Registration is automatic:

```cpp
#include "test_framework.h"
#include "AsyncTCP.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

using namespace mocklwip;

TEST(my_test) {
  AsyncClient c;
  CHECK(c.connect(IPAddress(10, 0, 0, 1), 80));
  ...
}
```

`test_main.cpp` calls `mocklwip::reset()`, `mockrtos::reset()` and
`mockclock::reset()` before every test, and `mocklwip::reset()` again after, so
each test starts from zero pcbs, zero pbufs, no faults and `millis() == 0`.

**Destroy your `AsyncClient`/`AsyncServer` before the test returns** if you want
leak assertions to mean anything — `reset()` reclaims whatever is left, but a
client that outlives the reset would hold a dangling pcb pointer.

### Driving a new lwIP callback

The `mocklwip::fire_*` functions play the part of the lwIP thread: they call
straight into the callback the library registered on the pcb. Nothing reaches
the application until you then call `asynctcp_test_pump()`. That two-step is the
whole point — it is where the queue-handling bugs live.

```cpp
fire_connected(pcb, ERR_OK);   // tcp_connected_fn; moves pcb to ESTABLISHED
fire_recv(pcb, "data", 4);     // tcp_recv_fn with a pbuf the mock allocates
fire_recv_pbuf(pcb, chain);    // ... or with a chain you built via make_pbuf()
fire_fin(pcb);                 // tcp_recv_fn with a NULL pbuf
fire_sent(pcb, 4);             // tcp_sent_fn
fire_poll(pcb);                // tcp_poll_fn
fire_error(pcb, ERR_RST);      // frees pcb, then tcp_err_fn -- pcb is dead after
fire_accept(listen_pcb);       // builds a new ESTABLISHED pcb, offers it
fire_dns(0x0A000005);          // deferred dns_found_callback with an address
fire_dns_failure();            // ... or with NULL
asynctcp_test_pump();          // now the application callbacks run
```

To add a callback the mock does not fire yet: store the callback pointer on
`struct tcp_pcb` in `mocks/include/lwip/tcp.h`, set it in the corresponding
`tcp_*` setter in `mock_lwip.cpp`, and add a `fire_*` that checks `is_live(pcb)`
and then calls it with `pcb->callback_arg`.

### Injecting failures

`mocklwip::faults()` returns a mutable struct, reset before each test:

```cpp
faults().fail_tcp_new = 1;          // next tcp_new_ip_type() returns NULL
faults().connect_result = ERR_RTE;  // tcp_connect() fails
faults().bind_result = ERR_USE;
faults().listen_returns_null = true;
faults().close_result = ERR_MEM;    // tcp_close() fails, pcb stays allocated
faults().write_result = ERR_MEM;
faults().fail_pbuf_alloc = 2;       // next 2 pbuf_alloc() return NULL
faults().dns_result = ERR_INPROGRESS;  // or ERR_OK / an error
faults().dns_addr = 0x0A000005;        // used when dns_result == ERR_OK
```

### Asserting

```cpp
live_pcbs()               // outstanding pcbs -- the leak check
live_pbufs()
port_is_bound(8080)
is_live(pcb)
count("tcp_close")        // number of calls
count("tcp_close", pcb)
saw("tcp_recved", pcb, 42)   // called on this pcb with first arg 42
written(pcb)              // everything handed to tcp_write(), concatenated
dump_calls()              // the whole call log, for when a CHECK is confusing
mockrtos::deadlocks()     // non-recursive mutex re-taken -- a deadlock on target
mockclock::advance(1500)  // move millis() forward
```

### Known-failing tests

`TEST_KNOWN_FAIL(name)` marks a test that reproduces a bug the library still
has. It runs, its failures are reported as `xfail`, and it does **not** fail the
build. If it starts passing the runner prints `XPASS` and tells you to promote
it to `TEST()`.

## Caveats

* The harness is single-threaded by construction, so it cannot find races. It
  finds lifetime, ordering and leak bugs.
* `reset()` cannot un-start the library's async task or free its queue mutex;
  those are process-lifetime singletons in `src/AsyncTCP.cpp`.
* The mocks target the API surface of `src/AsyncTCP.cpp` on this branch, plus
  the extra symbols the `yet-more-safety` rewrite uses (`tcp_bound_pcbs`,
  `esp_timer_get_time`, `xTaskCreatePinnedToCore`, `LOCK_TCPIP_CORE`,
  `esp32-hal-log.h`/`esp_log.h`, `IPADDR6_INIT`, `INADDR_ANY`, IPv6 helpers).
  A rewrite that reaches for more lwIP will need the mocks extended to match.

## Porting the harness to the `yet-more-safety` rewrite

The mocks were checked against `yet-more-safety`'s `src/AsyncTCP.cpp`
(`g++ -fsyntax-only`). It compiles except for one thing, which is in the
library rather than the mocks:

```
src/AsyncTCP.cpp:1207  async_tcp_log_d("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
src/AsyncTCP.cpp:1313  (the same line, in _fin())
```

Casting a `tcp_pcb*` to `uint32_t` is fine on a 32-bit ESP32 but an error on a
64-bit host. Two-line fix in `src/`: use `(uintptr_t)` with `PRIxPTR`, or
`%p` with `(void *)`. As a stopgap the build can add `-fpermissive`, which
downgrades it to a warning.

The tests themselves will need adjusting: that branch changes several
signatures (`_connected(tcp_pcb*, int8_t)`, const-qualified getters) and adds
IPv6 and keep-alive API.
