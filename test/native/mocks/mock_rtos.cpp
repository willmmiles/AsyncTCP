// Implementation of the FreeRTOS / clock / logging mocks.

#include "mock_rtos.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

extern "C" {
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------
namespace {
uint64_t g_micros = 0;
}

namespace mockclock {
void reset() {
  g_micros = 0;
}
void set_millis(uint32_t ms) {
  g_micros = (uint64_t)ms * 1000ULL;
}
void advance(uint32_t ms) {
  g_micros += (uint64_t)ms * 1000ULL;
}
uint32_t now_millis() {
  return (uint32_t)(g_micros / 1000ULL);
}
uint64_t now_micros() {
  return g_micros;
}
}  // namespace mockclock

extern "C" unsigned long millis(void) {
  return (unsigned long)mockclock::now_millis();
}

extern "C" unsigned long micros(void) {
  return (unsigned long)g_micros;
}

extern "C" void delay(unsigned long ms) {
  mockclock::advance((uint32_t)ms);
}

extern "C" int64_t esp_timer_get_time(void) {
  return (int64_t)g_micros;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
namespace {
int g_log_enabled = -1;  // -1 = not yet resolved from the environment
unsigned g_log_counts[128] = {0};
}  // namespace

namespace mocklog {
void set_enabled(bool on) {
  g_log_enabled = on ? 1 : 0;
}
bool enabled() {
  if (g_log_enabled < 0) {
    const char *v = getenv("ASYNCTCP_TEST_VERBOSE");
    g_log_enabled = (v && *v && *v != '0') ? 1 : 0;
  }
  return g_log_enabled != 0;
}
void reset() {
  memset(g_log_counts, 0, sizeof(g_log_counts));
}
unsigned count(char level) {
  return g_log_counts[(unsigned char)level & 0x7F];
}
}  // namespace mocklog

extern "C" void asynctcp_mock_log(char level, const char *file, int line, const char *fmt, ...) {
  g_log_counts[(unsigned char)level & 0x7F]++;
  if (!mocklog::enabled()) {
    return;
  }
  const char *base = strrchr(file, '/');
  fprintf(stderr, "[%c][%s:%d] ", level, base ? base + 1 : file, line);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

// ---------------------------------------------------------------------------
// Semaphores
// ---------------------------------------------------------------------------
namespace {

struct MockSemaphore {
  bool recursive;
  int depth;
};

std::set<MockSemaphore *> g_semaphores;
unsigned g_deadlocks = 0;

}  // namespace

extern "C" SemaphoreHandle_t xSemaphoreCreateMutex(void) {
  MockSemaphore *s = new MockSemaphore{false, 0};
  g_semaphores.insert(s);
  return (SemaphoreHandle_t)s;
}

extern "C" SemaphoreHandle_t xSemaphoreCreateRecursiveMutex(void) {
  MockSemaphore *s = new MockSemaphore{true, 0};
  g_semaphores.insert(s);
  return (SemaphoreHandle_t)s;
}

extern "C" SemaphoreHandle_t xSemaphoreCreateBinary(void) {
  MockSemaphore *s = new MockSemaphore{true, 0};
  g_semaphores.insert(s);
  return (SemaphoreHandle_t)s;
}

extern "C" SemaphoreHandle_t xSemaphoreCreateCounting(UBaseType_t, UBaseType_t) {
  MockSemaphore *s = new MockSemaphore{true, 0};
  g_semaphores.insert(s);
  return (SemaphoreHandle_t)s;
}

extern "C" void vSemaphoreDelete(SemaphoreHandle_t xSemaphore) {
  MockSemaphore *s = (MockSemaphore *)xSemaphore;
  if (!s) {
    return;
  }
  g_semaphores.erase(s);
  delete s;
}

extern "C" BaseType_t xSemaphoreTake(SemaphoreHandle_t xSemaphore, TickType_t) {
  MockSemaphore *s = (MockSemaphore *)xSemaphore;
  if (!s) {
    return pdFALSE;
  }
  // Single-threaded, so we can never actually block; a re-take of a
  // non-recursive mutex would deadlock on the target, so record it.
  if (!s->recursive && s->depth > 0) {
    g_deadlocks++;
  }
  s->depth++;
  return pdTRUE;
}

extern "C" BaseType_t xSemaphoreGive(SemaphoreHandle_t xSemaphore) {
  MockSemaphore *s = (MockSemaphore *)xSemaphore;
  if (!s) {
    return pdFALSE;
  }
  if (s->depth > 0) {
    s->depth--;
  }
  return pdTRUE;
}

extern "C" BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t s, TickType_t t) {
  return xSemaphoreTake(s, t);
}

extern "C" BaseType_t xSemaphoreGiveRecursive(SemaphoreHandle_t s) {
  return xSemaphoreGive(s);
}

// ---------------------------------------------------------------------------
// Tasks and the pump
// ---------------------------------------------------------------------------
namespace {

struct PumpExit {};  // thrown by ulTaskNotifyTake to unwind out of the task loop

TaskFunction_t g_task_fn = nullptr;
void *g_task_param = nullptr;
int g_task_handle_storage = 0;  // address used as the fake TaskHandle_t
unsigned g_notify_count = 0;
bool g_in_pump = false;
size_t g_pump_events = 0;
unsigned g_wdt_adds = 0;
unsigned g_wdt_deletes = 0;

BaseType_t create_task(TaskFunction_t fn, void *param, TaskHandle_t *handle) {
  g_task_fn = fn;
  g_task_param = param;
  if (handle) {
    *handle = (TaskHandle_t)&g_task_handle_storage;
  }
  return pdPASS;
}

}  // namespace

extern "C" BaseType_t xTaskCreate(TaskFunction_t fn, const char *, const configSTACK_DEPTH_TYPE, void *param, UBaseType_t, TaskHandle_t *handle) {
  return create_task(fn, param, handle);
}

extern "C" BaseType_t xTaskCreatePinnedToCore(TaskFunction_t fn, const char *, const configSTACK_DEPTH_TYPE, void *param, UBaseType_t, TaskHandle_t *handle, BaseType_t) {
  return create_task(fn, param, handle);
}

extern "C" BaseType_t xTaskCreateUniversal(TaskFunction_t fn, const char *, const configSTACK_DEPTH_TYPE, void *param, UBaseType_t, TaskHandle_t *handle, BaseType_t) {
  return create_task(fn, param, handle);
}

extern "C" void vTaskDelete(TaskHandle_t) {
  // The task loop only reaches this after its infinite for(;;), which the pump
  // unwinds out of, so this is unreachable in practice.
}

extern "C" void vTaskDelay(const TickType_t ticks) {
  mockclock::advance((uint32_t)ticks);
}

extern "C" TaskHandle_t xTaskGetCurrentTaskHandle(void) {
  return (TaskHandle_t)&g_task_handle_storage;
}

extern "C" UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t) {
  return 1024;
}

extern "C" const char *pcTaskGetName(TaskHandle_t) {
  return "async_tcp";
}

extern "C" BaseType_t xPortGetCoreID(void) {
  return 0;
}

extern "C" BaseType_t xTaskNotifyGive(TaskHandle_t) {
  g_notify_count++;
  return pdPASS;
}

extern "C" BaseType_t xTaskNotify(TaskHandle_t, uint32_t, eNotifyAction) {
  g_notify_count++;
  return pdPASS;
}

extern "C" BaseType_t xTaskNotifyAndQuery(TaskHandle_t, uint32_t, eNotifyAction, uint32_t *prev) {
  if (prev) {
    *prev = g_notify_count;
  }
  g_notify_count++;
  return pdPASS;
}

extern "C" uint32_t ulTaskNotifyTake(BaseType_t, TickType_t) {
  if (g_in_pump) {
    // The task has drained its queue and is about to sleep. Unwind back out to
    // asynctcp_test_pump() rather than blocking forever.
    throw PumpExit{};
  }
  return 0;
}

extern "C" esp_err_t esp_task_wdt_add(TaskHandle_t) {
  g_wdt_adds++;
  return ESP_OK;
}

extern "C" esp_err_t esp_task_wdt_delete(TaskHandle_t) {
  g_wdt_deletes++;
  return ESP_OK;
}

extern "C" esp_err_t esp_task_wdt_reset(void) {
  // The task kicks the watchdog once per handled event, so this is our event
  // counter.  Its other call site, after the idle wait, is unreachable here:
  // ulTaskNotifyTake() unwinds the pump before returning.
  g_pump_events++;
  return ESP_OK;
}

extern "C" esp_err_t esp_task_wdt_status(TaskHandle_t) {
  return ESP_OK;
}

size_t asynctcp_test_pump() {
  if (!g_task_fn) {
    return 0;  // library never started its task
  }
  g_pump_events = 0;
  g_in_pump = true;
  try {
    g_task_fn(g_task_param);
  } catch (const PumpExit &) {
    // Expected: the task reached its idle wait.
  }
  g_in_pump = false;
  return g_pump_events;
}

bool asynctcp_test_task_started() {
  return g_task_fn != nullptr;
}

namespace mockrtos {

void reset() {
  // NOTE: g_task_fn is deliberately *not* cleared. The library caches its task
  // handle in a file-static that we cannot reach, so once started it stays
  // started for the life of the process -- which is fine, the task is
  // stateless.
  g_notify_count = 0;
  g_deadlocks = 0;
  g_pump_events = 0;
  g_wdt_adds = 0;
  g_wdt_deletes = 0;
  for (MockSemaphore *s : g_semaphores) {
    s->depth = 0;
  }
  mocklog::reset();
}

unsigned notify_count() {
  return g_notify_count;
}
unsigned deadlocks() {
  return g_deadlocks;
}
unsigned live_semaphores() {
  return (unsigned)g_semaphores.size();
}
unsigned wdt_adds() {
  return g_wdt_adds;
}
unsigned wdt_deletes() {
  return g_wdt_deletes;
}

}  // namespace mockrtos
