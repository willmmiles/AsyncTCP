// Test-facing control surface for the FreeRTOS / clock / logging mocks.
//
// This header is for tests only -- the library never sees it.
#ifndef ASYNCTCP_MOCK_RTOS_H
#define ASYNCTCP_MOCK_RTOS_H

#include <cstddef>
#include <cstdint>

// ---------------------------------------------------------------------------
// The async-task pump
// ---------------------------------------------------------------------------
//
// AsyncTCP starts its event-service task with xTaskCreateUniversal(). The mock
// records the task function and parameter but never runs it. Calling
// asynctcp_test_pump() invokes that recorded function on the *calling* thread;
// it drains the library's event queue exactly as the real task would, and when
// it reaches its ulTaskNotifyTake() "sleep" the mock unwinds out of it with a
// private C++ exception which asynctcp_test_pump() catches.
//
// Net effect: pump() == "run the async task until its queue is empty, then
// return". Everything stays on one thread, so tests are fully deterministic.
//
// Safe because the library's task loop holds no live objects across the
// ulTaskNotifyTake() call -- the queue mutex guard lives and dies inside
// _get_async_event(). If a future rewrite changes that, the unwinding is still
// a proper C++ unwind (destructors run), unlike a longjmp.
//
// Returns the number of events the pump handled.
size_t asynctcp_test_pump();

// True once the library has created its async service task.
bool asynctcp_test_task_started();

namespace mockrtos {

// Clears task/semaphore/notification state. Call between tests.
void reset();

// Number of xTaskNotifyGive() calls since reset().
unsigned notify_count();

// Number of times a non-recursive mutex was taken while already held. On the
// real target that is a deadlock; here it is recorded and allowed to proceed.
unsigned deadlocks();

// Takes or gives against a null handle.  FreeRTOS faults on those; the runner treats
// any occurrence as a test failure.
unsigned null_semaphores();

// Number of mutexes created and not yet deleted.
unsigned live_semaphores();

// esp_task_wdt_add / esp_task_wdt_delete call counts.
unsigned wdt_adds();
unsigned wdt_deletes();

}  // namespace mockrtos

namespace mockclock {

void reset();  // back to t=0
void set_millis(uint32_t ms);
void advance(uint32_t ms);
uint32_t now_millis();
uint64_t now_micros();

}  // namespace mockclock

namespace mocklog {

// Route log_e/log_w/... to stderr. Off by default; forced on by setting the
// environment variable ASYNCTCP_TEST_VERBOSE=1.
void set_enabled(bool on);
bool enabled();

// Counts since reset(), by level character ('E', 'W', 'I', 'D', 'V').
void reset();
unsigned count(char level);

}  // namespace mocklog

#endif
