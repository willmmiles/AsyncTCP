// Object-lifetime tests.
//
// These cover the paths the reference-counted implementation exists for: destroying a
// client from inside its own callbacks, dropping one that still has queued events, and
// abandoning a name lookup.  LiveProbe below is the leak check.

#include "test_framework.h"

#include <memory>

#include "AsyncTCP.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

extern "C" {
#include "lwip/tcp.h"
}

using namespace mocklwip;

namespace {

const IPAddress kPeer(10, 0, 0, 1);
const uint16_t kPort = 8080;

/*
  Answers "has this client's implementation been destroyed yet?" without the library
  carrying a counter for us.  The callbacks live in the implementation, so a shared_ptr
  captured by one of them is released at exactly the moment the implementation is - and
  a weak_ptr to it then expires.  It reports per client rather than as a global count,
  which is what these tests actually want to assert.

  It rides in onTimeout, which none of these tests use.  Overwrite that callback and
  the probe releases early and starts lying.
*/
class LiveProbe {
public:
  void attach(AsyncClient &c) {
    auto tag = std::make_shared<int>(0);
    _weak = tag;
    c.onTimeout([tag](void *, AsyncClient *, uint32_t) {});
  }
  bool alive() const {
    return !_weak.expired();
  }

private:
  std::weak_ptr<int> _weak;
};

}  // namespace

// ---------------------------------------------------------------------------

TEST(lifetime_client_releases_its_implementation) {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    CHECK(probe.alive());
  }
  CHECK(!probe.alive());
}

TEST(lifetime_connected_client_releases_on_close) {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    CHECK(c.connect(kPeer, kPort));
    fire_connected(c.pcb());
    asynctcp_test_pump();
    c.close();
  }
  asynctcp_test_pump();
  CHECK(!probe.alive());
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_destroy_inside_onData_is_safe) {
  LiveProbe probe;
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  probe.attach(*c);
  c->onData([&](void *, AsyncClient *client, void *, size_t) {
    ran = true;
    delete client;  // destroys the std::function we are executing inside
  });

  CHECK(c->connect(kPeer, kPort));
  tcp_pcb *pcb = c->pcb();
  fire_connected(pcb);
  asynctcp_test_pump();

  fire_recv(pcb, "hello", 5);
  asynctcp_test_pump();

  CHECK(ran);
  CHECK(!probe.alive());
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);
}

TEST(lifetime_destroy_inside_onError_is_safe) {
  LiveProbe probe;
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  probe.attach(*c);
  c->onError([&](void *, AsyncClient *client, int8_t) {
    ran = true;
    delete client;
  });

  CHECK(c->connect(kPeer, kPort));
  tcp_pcb *pcb = c->pcb();
  fire_connected(pcb);
  asynctcp_test_pump();

  fire_error(pcb, ERR_RST);
  asynctcp_test_pump();

  CHECK(ran);
  CHECK(!probe.alive());
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_destroy_inside_onConnect_is_safe) {
  LiveProbe probe;
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  probe.attach(*c);
  c->onConnect([&](void *, AsyncClient *client) {
    ran = true;
    delete client;
  });

  CHECK(c->connect(kPeer, kPort));
  fire_connected(c->pcb());
  asynctcp_test_pump();

  CHECK(ran);
  CHECK(!probe.alive());
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_destroy_with_a_queued_event_delivers_nothing) {
  LiveProbe probe;
  bool ran = false;
  {
    AsyncClient c;
    probe.attach(c);
    c.onData([&](void *, AsyncClient *, void *, size_t) {
      ran = true;
    });
    CHECK(c.connect(kPeer, kPort));
    tcp_pcb *pcb = c.pcb();
    fire_connected(pcb);
    asynctcp_test_pump();

    // Queue an event, then destroy the client before the async task runs
    fire_recv(pcb, "hello", 5);
  }

  asynctcp_test_pump();  // the event is still queued, and must simply drain
  CHECK(!ran);
  CHECK(!probe.alive());
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);
}

TEST(lifetime_close_inside_onData_acks_the_packet) {
  LiveProbe probe;
  // Without the ack the peer gets an RST for data the application did process.
  {
    AsyncClient c;
    probe.attach(c);
    c.onData([](void *, AsyncClient *client, void *, size_t) {
      client->close();
    });
    CHECK(c.connect(kPeer, kPort));
    tcp_pcb *pcb = c.pcb();
    fire_connected(pcb);
    asynctcp_test_pump();

    fire_recv(pcb, "hello", 5);
    asynctcp_test_pump();

    CHECK(saw("tcp_recved", pcb, 5));  // the packet onData was handed
    CHECK_EQ(count("tcp_close"), (size_t)1);
  }
  CHECK(!probe.alive());
}

TEST(lifetime_destroy_during_a_lookup_leaves_no_dangling_argument) {
  LiveProbe probe;
  faults().dns_result = ERR_INPROGRESS;
  {
    AsyncClient c;
    probe.attach(c);
    CHECK(c.connect("slow.test", kPort));
    CHECK(c.connecting());  // the resolution phase is observable
  }
  // The implementation outlives the facade because LwIP still holds a reference
  CHECK(probe.alive());

  // Firing the callback would be a use-after-free without that reference
  fire_dns(0x0A000001);
  asynctcp_test_pump();

  CHECK(!probe.alive());
  CHECK_EQ(count("tcp_connect"), (size_t)0);  // the client is gone; do not dial out
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_close_abandons_a_lookup) {
  LiveProbe probe;
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  probe.attach(c);
  CHECK(c.connect("slow.test", kPort));
  c.close();
  CHECK(!c.connecting());

  fire_dns(0x0A000001);
  asynctcp_test_pump();

  CHECK_EQ(count("tcp_connect"), (size_t)0);  // the answer is no longer wanted
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_second_connect_during_a_lookup_is_swallowed) {
  LiveProbe probe;
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  probe.attach(c);
  CHECK(c.connect("slow.test", kPort));
  CHECK(c.connect("slow.test", kPort));  // returns true, starts nothing new
  CHECK_EQ(count("dns_gethostbyname"), (size_t)1);

  c.close();
  fire_dns(0x0A000001);
  asynctcp_test_pump();
}

TEST(lifetime_reconnect_after_close_starts_clean) {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    CHECK(c.connect(kPeer, kPort));
    tcp_pcb *first = c.pcb();
    fire_connected(first);
    asynctcp_test_pump();

    // Withhold an ack, then close: the debt must not survive into the next connection
    c.ackLater();
    fire_recv(first, "hello", 5);
    asynctcp_test_pump();
    c.close();
    asynctcp_test_pump();

    const size_t recved_before = count("tcp_recved");
    CHECK(c.connect(kPeer, kPort));
    tcp_pcb *second = c.pcb();
    CHECK(second != nullptr);
    fire_connected(second);
    asynctcp_test_pump();

    CHECK_EQ(c.ack(5), (size_t)0);                 // nothing outstanding on the new pcb
    CHECK_EQ(count("tcp_recved"), recved_before);  // and nothing acked against it

    c.close();
    asynctcp_test_pump();
  }
  CHECK(!probe.alive());
}
