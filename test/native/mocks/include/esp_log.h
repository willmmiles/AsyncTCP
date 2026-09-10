// Host-native mock of esp_log.h, routed to the same sink as the log_* macros.
#ifndef MOCK_ESP_LOG_H
#define MOCK_ESP_LOG_H

#include "Arduino.h"

#define ESP_LOG_NONE 0
#define ESP_LOG_ERROR 1
#define ESP_LOG_WARN 2
#define ESP_LOG_INFO 3
#define ESP_LOG_DEBUG 4
#define ESP_LOG_VERBOSE 5

#define ESP_LOGE(tag, fmt, ...) asynctcp_mock_log('E', tag, __LINE__, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) asynctcp_mock_log('W', tag, __LINE__, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) asynctcp_mock_log('I', tag, __LINE__, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) asynctcp_mock_log('D', tag, __LINE__, fmt, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) asynctcp_mock_log('V', tag, __LINE__, fmt, ##__VA_ARGS__)

#endif
