// Host-native mock of esp_idf_version.h.
// Reported as "not IDF 5" so the library takes its pre-5 / portable branches.
#ifndef MOCK_ESP_IDF_VERSION_H
#define MOCK_ESP_IDF_VERSION_H

#define ESP_IDF_VERSION_MAJOR 4
#define ESP_IDF_VERSION_MINOR 4
#define ESP_IDF_VERSION_PATCH 0

#define ESP_IDF_VERSION_VAL(major, minor, patch) ((major) * 10000 + (minor) * 100 + (patch))
#define ESP_IDF_VERSION ESP_IDF_VERSION_VAL(ESP_IDF_VERSION_MAJOR, ESP_IDF_VERSION_MINOR, ESP_IDF_VERSION_PATCH)

#endif
