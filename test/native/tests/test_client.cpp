// AsyncClient smoke tests.

#include "test_framework.h"

#include <string>

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

// The pcb the client is currently holding.
tcp_pcb *pcb_of(AsyncClient &c) {
  return c.pcb();
}

}  // namespace

// ---------------------------------------------------------------------------

TEST(client_construct_and_destroy_leaks_nothing) {
  {
    AsyncClient c;
    CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);
    CHECK_EQ(live_pcbs(), (size_t)0);
  }
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);
}

TEST(client_connect_allocates_one_pcb_and_registers_callbacks) {
  AsyncClient c;
  CHECK(c.connect(kPeer, kPort));

  CHECK_EQ(live_pcbs(), (size_t)1);
  tcp_pcb *pcb = pcb_of(c);
  CHECK(pcb != nullptr);
  CHECK_EQ((int)pcb->state, (int)SYN_SENT);
  CHECK_EQ((int)pcb->remote_port, (int)kPort);
  CHECK_EQ(pcb->remote_ip.u_addr.ip4.addr, (uint32_t)kPeer);

  // Every callback should be wired up.  The argument is the reference-counted
  // implementation, not the facade, so we can only check that it is set.
  CHECK(pcb->callback_arg != nullptr);
  CHECK(pcb->recv != nullptr);
  CHECK(pcb->sent != nullptr);
  CHECK(pcb->errf != nullptr);
  CHECK(pcb->poll != nullptr);

  CHECK_EQ(count("tcp_connect"), (size_t)1);
  CHECK(asynctcp_test_task_started());
}

TEST(client_connect_then_connected_callback_fires) {
  AsyncClient c;
  int connects = 0;
  AsyncClient *seen = nullptr;
  c.onConnect([&](void *, AsyncClient *cl) {
    connects++;
    seen = cl;
  });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);

  // lwIP completes the handshake...
  CHECK_EQ((int)fire_connected(pcb), (int)ERR_OK);
  // ...but nothing reaches the app until the async task runs.
  CHECK_EQ(connects, 0);

  CHECK_EQ(asynctcp_test_pump(), (size_t)1);
  CHECK_EQ(connects, 1);
  CHECK(seen == &c);
  CHECK(c.connected());
  CHECK_EQ((int)c.state(), (int)ESTABLISHED);

  c.close();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(client_connect_fails_when_tcp_connect_errors) {
  faults().connect_result = ERR_RTE;

  AsyncClient *c = new AsyncClient();
  CHECK(!c->connect(kPeer, kPort));
  CHECK_EQ(count("tcp_connect"), (size_t)1);

  // lwIP neither frees nor registers the pcb on a failed connect, so AsyncClient
  // disposes of it before returning rather than leaving it attached.
  CHECK_EQ(c->pcb(), (tcp_pcb *)nullptr);
  CHECK_EQ(live_pcbs(), (size_t)0);

  delete c;
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(bound_ports().size(), (size_t)0);
  CHECK(count("tcp_close") + count("tcp_abort") > 0);
}

TEST(client_connect_fails_when_pcb_allocation_fails) {
  faults().fail_tcp_new = 1;

  AsyncClient c;
  CHECK(!c.connect(kPeer, kPort));
  CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(count("tcp_connect"), (size_t)0);
}

TEST(client_data_reaches_onData_and_is_acked) {
  AsyncClient c;
  std::string got;
  c.onData([&](void *, AsyncClient *, void *data, size_t len) { got.assign((const char *)data, len); });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  const char payload[] = "hello world";
  const size_t n = sizeof(payload) - 1;
  fire_recv(pcb, payload, n);
  CHECK_EQ(got, std::string());  // still queued

  CHECK_EQ(asynctcp_test_pump(), (size_t)1);
  CHECK_EQ(got, std::string(payload));

  // The default (no ackLater) path acks immediately.
  CHECK(saw("tcp_recved", pcb, (long)n));
  // The pbuf must have been released by the library.
  CHECK_EQ(live_pbufs(), (size_t)0);

  c.close();
}

TEST(client_ackLater_defers_the_ack) {
  AsyncClient c;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) { cl->ackLater(); });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  fire_recv(pcb, "0123456789", 10);
  asynctcp_test_pump();
  CHECK(!saw("tcp_recved", pcb, 10));

  CHECK_EQ(c.ack(10), (size_t)10);
  CHECK(saw("tcp_recved", pcb, 10));

  c.close();
}

TEST(client_error_runs_onError_then_onDisconnect) {
  AsyncClient c;
  int order = 0, err_order = 0, disc_order = 0;
  int8_t err_seen = 0;
  c.onError([&](void *, AsyncClient *, int8_t e) {
    err_seen = e;
    err_order = ++order;
  });
  c.onDisconnect([&](void *, AsyncClient *) { disc_order = ++order; });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  // A fatal error: lwIP frees the pcb, then calls the error callback.
  fire_error(pcb, ERR_RST);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);  // library nulled it on the lwIP side
  CHECK_EQ(err_order, 0);                 // not delivered yet

  asynctcp_test_pump();
  CHECK_EQ((int)err_seen, (int)ERR_RST);
  CHECK_EQ(err_order, 1);
  CHECK_EQ(disc_order, 2);
  CHECK(c.disconnected());
}

TEST(client_fin_closes_and_runs_onDisconnect) {
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) { disconnects++; });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  fire_fin(pcb);
  asynctcp_test_pump();

  CHECK_EQ(disconnects, 1);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);
}

TEST(client_sent_ack_runs_onAck_with_elapsed_time) {
  AsyncClient c;
  size_t acked = 0;
  uint32_t elapsed = 0xFFFFFFFF;
  c.onAck([&](void *, AsyncClient *, size_t len, uint32_t t) {
    acked = len;
    elapsed = t;
  });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  CHECK_EQ(c.write("abcd", 4), (size_t)4);
  CHECK_EQ(written(pcb), std::string("abcd"));
  CHECK_EQ(count("tcp_output", pcb), (size_t)1);

  mockclock::advance(30);
  fire_sent(pcb, 4);
  asynctcp_test_pump();

  CHECK_EQ(acked, (size_t)4);
  CHECK_EQ(elapsed, (uint32_t)30);

  c.close();
}

TEST(client_poll_runs_onPoll) {
  AsyncClient c;
  int polls = 0;
  c.onPoll([&](void *, AsyncClient *) { polls++; });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  // Consecutive polls for the same client are deliberately coalesced, so pump
  // between them to see both.
  fire_poll(pcb);
  CHECK_EQ(asynctcp_test_pump(), (size_t)1);
  fire_poll(pcb);
  CHECK_EQ(asynctcp_test_pump(), (size_t)1);
  CHECK_EQ(polls, 2);

  c.close();
}

TEST(client_rx_timeout_closes_the_connection) {
  AsyncClient c;
  int disconnects = 0;
  c.onDisconnect([&](void *, AsyncClient *) { disconnects++; });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  c.setRxTimeout(2);  // seconds

  mockclock::advance(1000);
  fire_poll(pcb);
  asynctcp_test_pump();
  CHECK_EQ(disconnects, 0);
  CHECK(is_live(pcb));

  mockclock::advance(1500);
  fire_poll(pcb);
  asynctcp_test_pump();
  CHECK_EQ(disconnects, 1);
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(client_ack_timeout_runs_onTimeout) {
  // Start away from t=0: _poll()'s "last tx is after last ack" guard compares
  // _rx_last_ack (0 until the first ack) against _tx_last_packet, so at
  // millis()==0 the two are equal and the ack timeout is suppressed.
  mockclock::set_millis(1000);

  AsyncClient c;
  uint32_t timeout_ms = 0;
  c.onTimeout([&](void *, AsyncClient *, uint32_t t) { timeout_ms = t; });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  c.setAckTimeout(100);
  c.write("x", 1);

  mockclock::advance(250);
  fire_poll(pcb);
  asynctcp_test_pump();
  CHECK_EQ(timeout_ms, (uint32_t)250);

  c.close();
}

TEST(client_setNoDelay_toggles_nagle) {
  AsyncClient c;
  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);

  CHECK(!c.getNoDelay());
  c.setNoDelay(true);
  CHECK(c.getNoDelay());
  CHECK(tcp_nagle_disabled(pcb));
  c.setNoDelay(false);
  CHECK(!c.getNoDelay());

  c.close();
}

TEST(client_destructor_closes_a_live_connection) {
  AsyncClient *c = new AsyncClient();
  int disconnects = 0;
  c->onDisconnect([&](void *, AsyncClient *) { disconnects++; });
  CHECK(c->connect(kPeer, kPort));
  tcp_pcb *pcb = c->pcb();
  fire_connected(pcb);
  asynctcp_test_pump();
  CHECK_EQ(live_pcbs(), (size_t)1);

  delete c;
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(bound_ports().size(), (size_t)0);
  CHECK_EQ(disconnects, 1);
}

TEST(client_abort_frees_the_pcb_without_an_error_callback) {
  AsyncClient c;
  int errors = 0;
  c.onError([&](void *, AsyncClient *, int8_t) { errors++; });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  CHECK_EQ((int)c.abort(), (int)ERR_ABRT);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(c.pcb(), (tcp_pcb *)nullptr);

  // abort() deliberately raises ERR_ABRT itself, so that the dispose callback still
  // runs for a connection the application tore down.
  asynctcp_test_pump();
  CHECK_EQ(errors, 1);
}

TEST(client_pump_takes_the_queue_mutex_without_deadlocking) {
  AsyncClient c;
  c.onData([&](void *, AsyncClient *cl, void *, size_t) {
    // Re-entering the library from a callback is the classic deadlock shape.
    cl->close();
  });

  CHECK(c.connect(kPeer, kPort));
  tcp_pcb *pcb = pcb_of(c);
  fire_connected(pcb);
  asynctcp_test_pump();

  fire_recv(pcb, "zz", 2);
  asynctcp_test_pump();

  CHECK_EQ(mockrtos::deadlocks(), 0u);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(live_pbufs(), (size_t)0);
}
