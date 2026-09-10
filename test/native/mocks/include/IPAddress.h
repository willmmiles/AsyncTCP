// Host-native mock of the Arduino/ESP32 IPAddress class.
// Header-only; only the surface AsyncTCP uses is provided.
#ifndef MOCK_IPADDRESS_H
#define MOCK_IPADDRESS_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>

enum class IPType : uint8_t { IPv4 = 0, IPv6 = 6 };

class IPAddress {
public:
  IPAddress() : _addr(0), _type(IPType::IPv4) {}
  IPAddress(uint32_t address) : _addr(address), _type(IPType::IPv4) {}
  IPAddress(int address) : _addr((uint32_t)address), _type(IPType::IPv4) {}
  IPAddress(IPType t) : _addr(0), _type(t) {}
  IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
    : _addr(((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d), _type(IPType::IPv4) {}
  IPAddress(const uint8_t *address)
    : _addr(((uint32_t)address[0] << 24) | ((uint32_t)address[1] << 16) | ((uint32_t)address[2] << 8) | (uint32_t)address[3]),
      _type(IPType::IPv4) {}

  operator uint32_t() const {
    return _addr;
  }
  uint32_t v4() const {
    return _addr;
  }
  IPType type() const {
    return _type;
  }

  bool operator==(const IPAddress &other) const {
    return _addr == other._addr && _type == other._type;
  }
  bool operator!=(const IPAddress &other) const {
    return !(*this == other);
  }
  bool operator==(uint32_t other) const {
    return _addr == other;
  }

  uint8_t operator[](int index) const {
    return (uint8_t)(_addr >> (8 * (3 - index)));
  }

  std::string toString() const {
    char buf[24];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (unsigned)((_addr >> 24) & 0xFF), (unsigned)((_addr >> 16) & 0xFF), (unsigned)((_addr >> 8) & 0xFF), (unsigned)(_addr & 0xFF));
    return std::string(buf);
  }

  // Helper for tests: build from dotted quad.
  static IPAddress fromString(const char *s) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
      return IPAddress();
    }
    return IPAddress((uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d);
  }

private:
  uint32_t _addr;
  IPType _type;
};

#define INADDR_NONE_IPADDRESS IPAddress(0, 0, 0, 0)

#endif
