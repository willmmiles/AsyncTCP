// Object-lifetime tests.
//
// These cover the paths the reference-counted implementation exists for: destroying a
// client from inside its own callbacks, dropping one that still has queued events, and
// abandoning a name lookup.  asyncTcpLiveClientCount() is the leak check - it only
// falls back to zero once every holder has released its reference.

#include "test_framework.h"

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

}  // namespace

// ---------------------------------------------------------------------------

TEST(lifetime_client_releases_its_implementation) {
  const size_t base = asyncTcpLiveClientCount();
  {
    AsyncClient c;
    CHECK_EQ(asyncTcpLiveClientCount(), base + 1);
  }
  CHECK_EQ(asyncTcpLiveClientCount(), base);
}

TEST(lifetime_connected_client_releases_on_close) {
  const size_t base = asyncTcpLiveClientCount();
  {
    AsyncClient c;
    CHECK(c.connect(kPeer, kPort));
    fire_connected(c.pcb());
    asynctcp_test_pump();
    c.close();
  }
  asynctcp_test_pump();
  CHECK_EQ(asyncTcpLiveClientCount(), base);
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_destroy_inside_onData_is_safe) {
  const size_t base = asyncTcpLiveClientCount();
  bool ran = false;
  AsyncClient *c = new AsyncClient();
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
  CHECK_EQ(asyncTcpLiveClientCount(), base);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);
}

TEST(lifetime_destroy_inside_onError_is_safe) {
  const size_t base = asyncTcpLiveClientCount();
  bool ran = false;
  AsyncClient *c = new AsyncClient();
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
  CHECK_EQ(asyncTcpLiveClientCount(), base);
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_destroy_inside_onConnect_is_safe) {
  const size_t base = asyncTcpLiveClientCount();
  bool ran = false;
  AsyncClient *c = new AsyncClient();
  c->onConnect([&](void *, AsyncClient *client) {
    ran = true;
    delete client;
  });

  CHECK(c->connect(kPeer, kPort));
  fire_connected(c->pcb());
  asynctcp_test_pump();

  CHECK(ran);
  CHECK_EQ(asyncTcpLiveClientCount(), base);
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_destroy_with_a_queued_event_delivers_nothing) {
  const size_t base = asyncTcpLiveClientCount();
  bool ran = false;
  {
    AsyncClient c;
    c.onData([&](void *, AsyncClient *, void *, size_t) { ran = true; });
    CHECK(c.connect(kPeer, kPort));
    tcp_pcb *pcb = c.pcb();
    fire_connected(pcb);
    asynctcp_test_pump();

    // Queue an event, then destroy the client before the async task runs
    fire_recv(pcb, "hello", 5);
  }

  asynctcp_test_pump();  // the event is still queued, and must simply drain
  CHECK(!ran);
  CHECK_EQ(asyncTcpLiveClientCount(), base);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);
}

TEST(lifetime_close_inside_onData_acks_the_packet) {
  const size_t base = asyncTcpLiveClientCount();
  // Without the ack the peer gets an RST for data the application did process.
  {
    AsyncClient c;
    c.onData([](void *, AsyncClient *client, void *, size_t) { client->close(); });
    CHECK(c.connect(kPeer, kPort));
    tcp_pcb *pcb = c.pcb();
    fire_connected(pcb);
    asynctcp_test_pump();

    fire_recv(pcb, "hello", 5);
    asynctcp_test_pump();

    CHECK(saw("tcp_recved", pcb, 5));  // the packet onData was handed
    CHECK_EQ(count("tcp_close"), (size_t)1);
  }
  CHECK_EQ(asyncTcpLiveClientCount(), base);
}

TEST(lifetime_destroy_during_a_lookup_leaves_no_dangling_argument) {
  const size_t base = asyncTcpLiveClientCount();
  faults().dns_result = ERR_INPROGRESS;
  {
    AsyncClient c;
    CHECK(c.connect("slow.test", kPort));
    CHECK(c.connecting());  // the resolution phase is observable
  }
  // The implementation outlives the facade because LwIP still holds a reference
  CHECK_EQ(asyncTcpLiveClientCount(), base + 1);

  // Firing the callback would be a use-after-free without that reference
  fire_dns(0x0A000001);
  asynctcp_test_pump();

  CHECK_EQ(asyncTcpLiveClientCount(), base);
  CHECK_EQ(count("tcp_connect"), (size_t)0);  // the client is gone; do not dial out
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_close_abandons_a_lookup) {
  const size_t base = asyncTcpLiveClientCount();
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  CHECK(c.connect("slow.test", kPort));
  c.close();
  CHECK(!c.connecting());

  fire_dns(0x0A000001);
  asynctcp_test_pump();

  CHECK_EQ(count("tcp_connect"), (size_t)0);  // the answer is no longer wanted
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(lifetime_second_connect_during_a_lookup_is_swallowed) {
  const size_t base = asyncTcpLiveClientCount();
  faults().dns_result = ERR_INPROGRESS;
  AsyncClient c;
  CHECK(c.connect("slow.test", kPort));
  CHECK(c.connect("slow.test", kPort));  // returns true, starts nothing new
  CHECK_EQ(count("dns_gethostbyname"), (size_t)1);

  c.close();
  fire_dns(0x0A000001);
  asynctcp_test_pump();
}

TEST(lifetime_reconnect_after_close_starts_clean) {
  const size_t base = asyncTcpLiveClientCount();
  {
    AsyncClient c;
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
  CHECK_EQ(asyncTcpLiveClientCount(), base);
}
