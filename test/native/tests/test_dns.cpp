// DNS resolution tests for AsyncClient::connect(const char*, uint16_t).

#include "test_framework.h"

#include "AsyncTCP.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

extern "C" {
#include "lwip/tcp.h"
}

using namespace mocklwip;

namespace {
const uint32_t kResolved = 0x0A000005;  // 10.0.0.5
const uint16_t kPort = 443;
}  // namespace

// ---------------------------------------------------------------------------

TEST(dns_immediate_hit_connects_straight_away) {
  faults().dns_result = ERR_OK;
  faults().dns_addr = kResolved;

  AsyncClient c;
  int connects = 0;
  c.onConnect([&](void *, AsyncClient *) { connects++; });

  CHECK(c.connect("example.test", kPort));
  CHECK_EQ(count("dns_gethostbyname"), (size_t)1);
  CHECK(!dns_pending());
  CHECK_EQ(count("tcp_connect"), (size_t)1);

  tcp_pcb *pcb = c.pcb();
  CHECK(pcb != nullptr);
  CHECK_EQ(pcb->remote_ip.u_addr.ip4.addr, kResolved);
  CHECK_EQ((int)pcb->remote_port, (int)kPort);

  fire_connected(pcb);
  asynctcp_test_pump();
  CHECK_EQ(connects, 1);

  c.close();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(dns_deferred_hit_connects_when_the_callback_fires) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  int connects = 0;
  c.onConnect([&](void *, AsyncClient *) { connects++; });

  // connect() reports success optimistically while the lookup is outstanding.
  CHECK(c.connect("example.test", kPort));
  CHECK(dns_pending());
  CHECK_EQ(dns_pending_host(), std::string("example.test"));
  CHECK_EQ(count("tcp_connect"), (size_t)0);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);

  // Resolver answers on the lwIP thread; still nothing until we pump.
  fire_dns(kResolved);
  CHECK_EQ(count("tcp_connect"), (size_t)0);

  CHECK_EQ(asynctcp_test_pump(), (size_t)1);
  CHECK_EQ(count("tcp_connect"), (size_t)1);

  tcp_pcb *pcb = c.pcb();
  CHECK(pcb != nullptr);
  CHECK_EQ(pcb->remote_ip.u_addr.ip4.addr, kResolved);
  // _dns_found() must have carried the port through _connect_port.
  CHECK_EQ((int)pcb->remote_port, (int)kPort);

  fire_connected(pcb);
  asynctcp_test_pump();
  CHECK_EQ(connects, 1);

  c.close();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(dns_failure_reports_error_55_and_does_not_connect) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  int order = 0, err_order = 0, disc_order = 0, connects = 0;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) {
    err_seen = e;
    err_order = ++order;
  });
  c.onDisconnect([&](void *, AsyncClient *) { disc_order = ++order; });
  c.onConnect([&](void *, AsyncClient *) { connects++; });

  CHECK(c.connect("nx.test", kPort));
  CHECK(dns_pending());

  // Resolver gives up: callback with a NULL address.
  fire_dns_failure();
  CHECK_EQ(err_order, 0);

  CHECK_EQ(asynctcp_test_pump(), (size_t)1);

  CHECK_EQ((int)err_seen, -55);  // AsyncTCP's "DNS failed" pseudo-error
  CHECK_EQ(err_order, 1);
  CHECK_EQ(disc_order, 2);
  CHECK_EQ(connects, 0);

  // Crucially: no connection attempt, and no pcb allocated for 0.0.0.0.
  CHECK_EQ(count("tcp_connect"), (size_t)0);
  CHECK_EQ(count("tcp_new_ip_type"), (size_t)0);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);
}

TEST(dns_resolved_to_zero_address_is_treated_as_failure) {
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient c;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) { err_seen = e; });

  CHECK(c.connect("zero.test", kPort));
  fire_dns(0);  // resolver returned 0.0.0.0
  asynctcp_test_pump();

  CHECK_EQ((int)err_seen, -55);
  CHECK_EQ(count("tcp_connect"), (size_t)0);
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(dns_hard_error_fails_connect_immediately) {
  faults().dns_result = ERR_VAL;

  AsyncClient c;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) { err_seen = e; });

  CHECK(!c.connect("bad..test", kPort));
  CHECK(!dns_pending());
  CHECK_EQ(count("tcp_connect"), (size_t)0);
  CHECK_EQ(live_pcbs(), (size_t)0);

  // The synchronous failure path just returns false; no callback is invoked.
  asynctcp_test_pump();
  CHECK_EQ((int)err_seen, 0);
}

TEST(dns_lookup_errorToString_covers_minus_55) {
  AsyncClient c;
  CHECK_STREQ(c.errorToString(-55), "DNS failed");
  CHECK_STREQ(c.errorToString(ERR_OK), "OK");
  CHECK_STREQ(c.errorToString(ERR_RTE), "Routing problem");
  CHECK_STREQ(c.errorToString(120), "UNKNOWN");
}

TEST(dns_deferred_lookup_survives_client_destruction) {
  // LwIP has no way to cancel an outstanding dns_gethostbyname(), so it still holds
  // the callback argument after the client goes away.  That argument is the
  // reference-counted implementation, which therefore outlives the facade.
  faults().dns_result = ERR_INPROGRESS;

  AsyncClient *c = new AsyncClient();
  CHECK(c->connect("slow.test", kPort));
  CHECK(dns_pending());
  delete c;

  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);

  // Firing the callback would have been a use-after-free before the implementation
  // was reference counted.  It must now be harmless, and must release the reference.
  fire_dns(0x0A000001);
  asynctcp_test_pump();
  CHECK_EQ(count("tcp_connect"), (size_t)0);  // nobody left to connect for
  CHECK_EQ(live_pcbs(), (size_t)0);
}
