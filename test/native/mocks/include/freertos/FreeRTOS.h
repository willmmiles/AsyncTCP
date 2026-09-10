// Host-native mock of freertos/FreeRTOS.h
//
// Must stay C-compatible: AsyncTCP.h pulls freertos/semphr.h in from inside an
// extern "C" block.
#ifndef MOCK_FREERTOS_H
#define MOCK_FREERTOS_H

#include <stddef.h>
#include <stdint.h>

typedef long BaseType_t;
typedef unsigned long UBaseType_t;
typedef uint32_t TickType_t;
typedef size_t configSTACK_DEPTH_TYPE;

#define pdFALSE ((BaseType_t)0)
#define pdTRUE ((BaseType_t)1)
#define pdPASS pdTRUE
#define pdFAIL pdFALSE

#define portMAX_DELAY ((TickType_t)0xffffffffUL)
#define portTICK_PERIOD_MS ((TickType_t)1)
#define configTICK_RATE_HZ 1000
#define configMINIMAL_STACK_SIZE 768
#define configMAX_PRIORITIES 25

#define pdMS_TO_TICKS(xTimeInMs) ((TickType_t)(xTimeInMs))
#define pdTICKS_TO_MS(xTicks) ((uint32_t)(xTicks))

#define tskNO_AFFINITY ((BaseType_t)0x7FFFFFFF)

#ifndef CONFIG_FREERTOS_UNICORE
#define CONFIG_FREERTOS_UNICORE 1
#endif

#endif
