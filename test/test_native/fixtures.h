// Shared test fixtures: the addresses the tests dial and listen on, and the steps most
// tests start with.
#ifndef ASYNCTCP_TEST_FIXTURES_H
#define ASYNCTCP_TEST_FIXTURES_H

#include "runner.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "AsyncTCP.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

extern "C" {
#include "lwip/tcp.h"
}

const IPAddress kPeer(10, 0, 0, 1);     // where clients dial
const uint16_t kPort = 8080;            // ... and on what port
const uint16_t kServerPort = 8081;      // where servers listen
const uint32_t kResolved = 0x0A000005;  // what a name lookup answers: 10.0.0.5

// Connects to kPeer and completes the handshake.  Returns the client's pcb.
inline tcp_pcb *establish(AsyncClient &c) {
  TEST_ASSERT_TRUE(c.connect(kPeer, kPort));
  tcp_pcb *pcb = mocklwip::dialled_pcb();
  TEST_ASSERT_NOT_NULL(pcb);
  TEST_ASSERT_EQUAL_INT((int)ERR_OK, (int)mocklwip::fire_connected(pcb));
  asynctcp_test_pump();
  TEST_ASSERT_TRUE(c.connected());
  return pcb;
}

// The listening pcb on <port>, or on any port when it is 0.  nullptr if there is none.
inline tcp_pcb *listen_pcb(uint16_t port = 0) {
  for (tcp_pcb *p : mocklwip::pcbs()) {
    if (p->state == LISTEN && (port == 0 || p->local_port == port)) {
      return p;
    }
  }
  return nullptr;
}

// Records a client's callbacks as one letter each, in the order they run, so that order,
// count and exactly-once are one assertion: "ED" is onError then onDisconnect, "" is
// silence.
//
//   C onConnect   E onError   D onDisconnect   R onData
//   A onAck                   T onTimeout
//
// attach() registers only the callbacks it is given -- by default the three that open and
// end a connection -- because registering a handler can change what the library does.
class Recorder {
public:
  std::string seq;
  int8_t err = 0;          // what the last onError was given
  std::string data;        // everything onData was given, concatenated
  size_t acked = 0;        // what the last onAck was given
  uint32_t timed_out = 0;  // what the last onTimeout was given

  Recorder() = default;
  Recorder(const Recorder &) = delete;
  Recorder &operator=(const Recorder &) = delete;

  void attach(AsyncClient &c, const char *events = "CED") {
    if (strchr(events, 'C')) {
      c.onConnect([this](void *, AsyncClient *cl) {
        note('C', cl);
      });
    }
    if (strchr(events, 'E')) {
      c.onError([this](void *, AsyncClient *cl, int8_t e) {
        note('E', cl, e);
        err = e;
      });
    }
    if (strchr(events, 'D')) {
      c.onDisconnect([this](void *, AsyncClient *cl) {
        note('D', cl);
      });
    }
    if (strchr(events, 'R')) {
      c.onData([this](void *, AsyncClient *cl, void *d, size_t n) {
        note('R', cl);
        data.append((const char *)d, n);
      });
    }
    if (strchr(events, 'A')) {
      c.onAck([this](void *, AsyncClient *cl, size_t n, uint32_t t) {
        note('A', cl);
        acked = n;
      });
    }
    if (strchr(events, 'T')) {
      c.onTimeout([this](void *, AsyncClient *cl, uint32_t t) {
        note('T', cl);
        timed_out = t;
      });
    }
  }

  // Records <event> for client <c>, as the handlers attach() registers do.
  void note(char event, const AsyncClient *c, int8_t e = 0) {
    seq += event;
  }

  int count(char event) const {
    return (int)std::count(seq.begin(), seq.end(), event);
  }
};

// Takes delivery of a server's clients, in order, and deletes whatever is left of them when
// it goes out of scope.  <setup> runs on each client as it is delivered.
class Accepted {
public:
  explicit Accepted(AsyncServer &s, std::function<void(AsyncClient *)> setup = nullptr) {
    s.onClient(
      [this, setup](void *, AsyncClient *c) {
        _clients.push_back(c);
        if (setup) {
          setup(c);
        }
      },
      nullptr
    );
  }
  ~Accepted() {
    clear();
  }
  Accepted(const Accepted &) = delete;
  Accepted &operator=(const Accepted &) = delete;

  size_t size() const {
    return _clients.size();
  }
  AsyncClient *operator[](size_t i) const {
    return _clients.at(i);
  }
  void clear() {
    std::vector<AsyncClient *> doomed;
    doomed.swap(_clients);
    for (AsyncClient *c : doomed) {
      delete c;
    }
  }

private:
  std::vector<AsyncClient *> _clients;
};

#endif
