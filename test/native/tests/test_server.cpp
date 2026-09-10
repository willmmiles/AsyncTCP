// AsyncServer smoke tests.

#include "test_framework.h"

#include <vector>

#include "AsyncTCP.h"
#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

extern "C" {
#include "lwip/tcp.h"
}

using namespace mocklwip;

namespace {

const uint16_t kPort = 8080;

tcp_pcb *listen_pcb() {
  for (tcp_pcb *p : pcbs()) {
    if (p->state == LISTEN) {
      return p;
    }
  }
  return nullptr;
}

}  // namespace

// ---------------------------------------------------------------------------

TEST(server_begin_binds_and_listens) {
  AsyncServer s(kPort);
  s.begin();

  CHECK_EQ(count("tcp_bind"), (size_t)1);
  CHECK_EQ(count("tcp_listen_with_backlog"), (size_t)1);
  CHECK(port_is_bound(kPort));

  tcp_pcb *lp = listen_pcb();
  CHECK(lp != nullptr);
  CHECK_EQ((int)s.status(), (int)LISTEN);
  CHECK(lp->accept != nullptr);
  CHECK(lp->callback_arg == &s);

  // tcp_listen_with_backlog swapped the bound pcb for a listen pcb, so exactly
  // one should be alive.
  CHECK_EQ(live_pcbs(), (size_t)1);

  s.end();
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK(!port_is_bound(kPort));
}

TEST(server_destructor_releases_the_port) {
  {
    AsyncServer s(kPort);
    s.begin();
    CHECK(port_is_bound(kPort));
  }
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK(!port_is_bound(kPort));
}

TEST(server_begin_bails_out_when_pcb_allocation_fails) {
  faults().fail_tcp_new = 1;

  AsyncServer s(kPort);
  s.begin();

  CHECK_EQ((int)s.status(), 0);
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ(count("tcp_bind"), (size_t)0);
}

TEST(server_begin_frees_the_pcb_when_bind_fails) {
  faults().bind_result = ERR_USE;

  AsyncServer s(kPort);
  s.begin();

  CHECK_EQ((int)s.status(), 0);
  CHECK_EQ(count("tcp_bind"), (size_t)1);
  CHECK_EQ(count("tcp_listen_with_backlog"), (size_t)0);
  // begin() calls _tcp_close() on the bind failure path.
  CHECK_EQ(count("tcp_close"), (size_t)1);
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(server_bind_conflicts_with_an_already_bound_port) {
  AsyncServer a(kPort);
  a.begin();
  CHECK_EQ((int)a.status(), (int)LISTEN);

  AsyncServer b(kPort);
  b.begin();
  CHECK_EQ((int)b.status(), 0);  // ERR_USE from tcp_bind

  a.end();
  b.end();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

// Known issue: AsyncServer::begin() overwrites _pcb with the NULL returned by
// tcp_listen_with_backlog(), losing the bound pcb it still owns. lwIP does NOT
// free the caller's pcb when it cannot allocate a listen pcb, so both the pcb
// and its port are leaked for the life of the process.
//
// Fixed on the yet-more-safety branch by commit "Close the bound pcb when
// AsyncServer fails to listen". Promote this to TEST() once that lands.
TEST(server_begin_frees_the_bound_pcb_when_listen_fails) {
  faults().listen_returns_null = true;

  {
    AsyncServer s(kPort);
    s.begin();
    CHECK_EQ((int)s.status(), 0);
    CHECK_EQ(count("tcp_listen_with_backlog"), (size_t)1);
  }

  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK(!port_is_bound(kPort));
}

TEST(server_accept_delivers_a_client_to_onClient) {
  AsyncServer s(kPort);
  std::vector<AsyncClient *> accepted;
  s.onClient([&](void *, AsyncClient *c) { accepted.push_back(c); }, nullptr);
  s.begin();

  tcp_pcb *lp = listen_pcb();
  CHECK(lp != nullptr);

  tcp_pcb *conn = fire_accept(lp);
  CHECK(conn != nullptr);
  CHECK_EQ(accepted.size(), (size_t)0);  // queued, not yet delivered

  CHECK_EQ(asynctcp_test_pump(), (size_t)1);
  CHECK_EQ(accepted.size(), (size_t)1);

  AsyncClient *c = accepted[0];
  CHECK(c->pcb() == conn);
  CHECK(c->connected());
  CHECK_EQ((int)c->remotePort(), 40000);

  // AsyncServer hands ownership of the client to the application.
  delete c;
  CHECK(!is_live(conn));

  s.end();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(server_accept_without_a_handler_closes_the_connection) {
  AsyncServer s(kPort);
  s.begin();  // no onClient()

  tcp_pcb *lp = listen_pcb();
  tcp_pcb *conn = fire_accept(lp);
  CHECK(conn != nullptr);
  CHECK(!is_live(conn));  // _accept() closed it straight away
  CHECK_EQ(asynctcp_test_pump(), (size_t)0);

  s.end();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(server_setNoDelay_propagates_to_accepted_clients) {
  AsyncServer s(kPort);
  s.setNoDelay(true);
  CHECK(s.getNoDelay());

  AsyncClient *client = nullptr;
  s.onClient([&](void *, AsyncClient *c) { client = c; }, nullptr);
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();

  CHECK(client != nullptr);
  CHECK(client->getNoDelay());
  CHECK(tcp_nagle_disabled(conn));

  delete client;
  s.end();
}

TEST(server_accepted_client_receives_data) {
  AsyncServer s(kPort);
  AsyncClient *client = nullptr;
  std::string got;
  s.onClient(
    [&](void *, AsyncClient *c) {
      client = c;
      c->onData([&](void *, AsyncClient *, void *d, size_t n) { got.assign((const char *)d, n); });
    },
    nullptr);
  s.begin();

  tcp_pcb *conn = fire_accept(listen_pcb());
  asynctcp_test_pump();
  CHECK(client != nullptr);

  fire_recv(conn, "GET /", 5);
  asynctcp_test_pump();
  CHECK_EQ(got, std::string("GET /"));
  CHECK(saw("tcp_recved", conn, 5));
  CHECK_EQ(live_pbufs(), (size_t)0);

  delete client;
  s.end();
  CHECK_EQ(live_pcbs(), (size_t)0);
}

TEST(server_end_is_idempotent) {
  AsyncServer s(kPort);
  s.begin();
  s.end();
  s.end();
  CHECK_EQ(live_pcbs(), (size_t)0);
  CHECK_EQ((int)s.status(), 0);
}

TEST(server_begin_twice_does_not_double_bind) {
  AsyncServer s(kPort);
  s.begin();
  s.begin();  // second call must be a no-op, _pcb is already set
  CHECK_EQ(count("tcp_bind"), (size_t)1);
  CHECK_EQ(live_pcbs(), (size_t)1);
  s.end();
}
