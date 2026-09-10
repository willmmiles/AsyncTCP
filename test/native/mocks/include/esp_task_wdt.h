// Host-native mock of esp_task_wdt.h. Always succeeds; calls are counted so a
// test can assert the async task registers/deregisters as expected.
#ifndef MOCK_ESP_TASK_WDT_H
#define MOCK_ESP_TASK_WDT_H

#include "esp_err.h"
#include "freertos/task.h"

#ifndef CONFIG_ESP_TASK_WDT_TIMEOUT_S
#define CONFIG_ESP_TASK_WDT_TIMEOUT_S 5
#endif

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t esp_task_wdt_add(TaskHandle_t handle);
esp_err_t esp_task_wdt_delete(TaskHandle_t handle);
esp_err_t esp_task_wdt_reset(void);
esp_err_t esp_task_wdt_status(TaskHandle_t handle);

#ifdef __cplusplus
}
#endif

#endif
