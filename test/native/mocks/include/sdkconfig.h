// Host-native mock of sdkconfig.h.
#ifndef MOCK_SDKCONFIG_H
#define MOCK_SDKCONFIG_H

// Direct-call flavour of tcpip_api_call: no TCPIP thread, fully deterministic.
#define CONFIG_LWIP_TCPIP_CORE_LOCKING 1

#define CONFIG_FREERTOS_UNICORE 1
#define CONFIG_ESP_TASK_WDT_TIMEOUT_S 5

#endif
