// Self-checking lifetime tests for AsyncTCP.
//
// These exercise the object-lifetime paths that are hard to reach from ordinary use:
// destroying a client from inside its own callbacks, abandoning a name lookup, and
// connections that fail.  Each test finishes by waiting for its LiveProbe to report
// the client's implementation released, which is what catches a leaked reference.
//
// Everything past the first test needs the TCP/IP stack running - connect() takes the
// LwIP core lock, which does not exist until then - and the peer for most of them is a
// server on this same board, so WiFi credentials are required.
//
// To build: set `src_dir = examples/LifetimeTests` in platformio.ini, then
//   pio run -e arduino-3 -t upload && pio device monitor
// Read the summary at the end.

#include <Arduino.h>
#include <AsyncTCP.h>
#include <WiFi.h>
#include <memory>

/*
  Answers "has this client's implementation been released yet?" without the library
  carrying a counter for it.  The callbacks live in the implementation, so a shared_ptr
  captured by one of them is released at exactly the moment the implementation is, and
  a weak_ptr to it then expires.

  The wait is a member rather than a free function: the .ino preprocessor hoists
  prototypes above this class, so a free function taking a LiveProbe would not compile.

  It rides in onTimeout, which none of these tests use.
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

  // A queued event or an outstanding lookup can still hold a reference, so give it
  // time to drain rather than sampling the moment the client goes out of scope.
  bool waitReleased(uint32_t timeout_ms) const {
    uint32_t start = millis();
    while ((millis() - start) < timeout_ms) {
      if (_weak.expired()) {
        return true;
      }
      delay(10);
    }
    Serial.println("    (implementation still referenced)");
    return false;
  }

private:
  std::weak_ptr<int> _weak;
};

static const char *WIFI_SSID = "";  // only affects test 6; the peer is loopback
static const char *WIFI_PASS = "";
static const uint16_t TEST_PORT = 8099;
static const uint16_t DEAD_PORT = 8100;  // nothing ever listens here

// The peer for every networked test is a server on this same board.  Packets addressed
// to our own station address are not looped back by default, so use the dedicated
// loopback interface instead.
static const IPAddress kPeer(127, 0, 0, 1);

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, bool ok) {
  Serial.printf("%-56s %s\n", name, ok ? "PASS" : "FAIL");
  ok ? ++g_pass : ++g_fail;
}

static bool waitFlag(volatile bool &flag, uint32_t timeout_ms) {
  uint32_t start = millis();
  while (!flag && (millis() - start) < timeout_ms) {
    delay(10);
  }
  return flag;
}

static AsyncServer *g_server = nullptr;
static volatile int g_accepts = 0;

// ---------------------------------------------------------------------------

static void test_construct_destroy() {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    probe.attach(c);
  }
  check("1. construct and destroy leaks nothing", probe.waitReleased(1000));
}

// A closed port on our own address gives us a prompt RST, which is a far more
// deterministic error than waiting out a SYN timeout to an unroutable address.
static void test_refused_connect() {
  LiveProbe probe;
  static volatile bool errored = false;
  errored = false;
  {
    AsyncClient c;
    probe.attach(c);
    c.onError([](void *, AsyncClient *, int8_t) {
      errored = true;
    });
    bool started = c.connect(kPeer, DEAD_PORT);
    if (!started) {
      Serial.println("    (connect() returned false - no callback is owed)");
    }
    waitFlag(errored, 10000);
    check("2. refused connect reports an error", started && errored);
  }
  check("3. ...and leaks nothing once it settles", probe.waitReleased(5000));
}

static void test_destroy_inside_onerror() {
  LiveProbe probe;
  static volatile bool errored = false;
  errored = false;
  AsyncClient *c = new AsyncClient();
  probe.attach(*c);
  // The dangerous case: the std::function being executed belongs to this object
  c->onError(
    [](void *arg, AsyncClient *, int8_t) {
      delete static_cast<AsyncClient *>(arg);
      errored = true;
    },
    c
  );
  bool started = c->connect(kPeer, DEAD_PORT);
  if (started) {
    waitFlag(errored, 10000);
  }
  if (!errored) {
    delete c;  // the callback never ran, so it is still ours to release
  }
  check("4. destroying the client inside onError survives", started && errored);
  check("5. ...and leaks nothing once it settles", probe.waitReleased(5000));
}

static void test_abandoned_lookup() {
  LiveProbe probe;
  {
    AsyncClient c;
    probe.attach(c);
    bool started = c.connect("test-host-that-does-not-exist.invalid", 80);
    Serial.printf("    (lookup started: %s)\n", started ? "yes" : "no");
    c.close();  // abandon it while it may still be in flight
  }
  // LwIP cannot cancel a lookup, so the reference lives until its timeout fires
  check("6. closing during a lookup leaks nothing (slow: DNS timeout)", probe.waitReleased(45000));
}

// ---------------------------------------------------------------------------

static bool startServer() {
  g_server = new AsyncServer(TEST_PORT);
  g_server->onClient(
    [](void *, AsyncClient *c) {
      g_accepts++;
      c->onDisconnect([](void *, AsyncClient *client) {
        delete client;
      });
      c->onData([](void *, AsyncClient *client, void *data, size_t len) {
        client->write((const char *)data, len);
      });
    },
    nullptr
  );
  g_server->begin();
  return g_server->status() != 0;
}

static void test_echo() {
  LiveProbe probe;
  static volatile bool got = false;
  static volatile bool connected = false;
  got = connected = false;
  const int accepts_before = g_accepts;
  {
    AsyncClient c;
    probe.attach(c);
    c.onConnect([](void *, AsyncClient *client) {
      connected = true;
      client->write("ping");
    });
    c.onData([](void *, AsyncClient *, void *, size_t) {
      got = true;
    });
    c.onError([](void *, AsyncClient *, int8_t e) {
      Serial.printf("    (client onError %d)\n", (int)e);
    });
    if (!c.connect(kPeer, TEST_PORT)) {
      Serial.println("    (connect() returned false)");
    }
    waitFlag(got, 10000);
    if (!got) {
      Serial.printf("    (connected=%d accepted=%d)\n", (int)connected, g_accepts - accepts_before);
    }
    check("7. echo round trip", got);
    c.close();
    delay(200);
  }
  check("8. echo client leaks nothing", probe.waitReleased(5000));
}

static void test_close_inside_ondata() {
  LiveProbe probe;
  static volatile bool closed = false;
  closed = false;
  {
    AsyncClient c;
    probe.attach(c);
    c.onConnect([](void *, AsyncClient *client) {
      client->write("ping");
    });
    c.onData([](void *, AsyncClient *client, void *, size_t) {
      client->close();  // must ack the packet first, or the peer sees an RST
      closed = true;
    });
    c.connect(kPeer, TEST_PORT);
    waitFlag(closed, 10000);
  }
  check("9. closing inside onData survives", closed);
  check("10. ...and leaks nothing once it settles", probe.waitReleased(5000));
}

static void test_destroy_inside_ondata() {
  LiveProbe probe;
  static volatile bool destroyed = false;
  destroyed = false;
  AsyncClient *c = new AsyncClient();
  probe.attach(*c);
  c->onConnect([](void *, AsyncClient *client) {
    client->write("ping");
  });
  c->onData(
    [](void *arg, AsyncClient *, void *, size_t) {
      delete static_cast<AsyncClient *>(arg);
      destroyed = true;
    },
    c
  );
  c->connect(kPeer, TEST_PORT);
  waitFlag(destroyed, 10000);
  if (!destroyed) {
    delete c;
  }
  check("11. destroying the client inside onData survives", destroyed);
  check("12. ...and leaks nothing once it settles", probe.waitReleased(5000));
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n\nAsyncTCP lifetime tests\n");

  test_construct_destroy();  // before LwIP is up: construction alone must not need it

  // The peer is loopback, so no association is needed - but the stack still has to be
  // running, or connect() asserts inside LOCK_TCPIP_CORE().  Credentials only affect
  // whether the name lookup in test 6 reaches a real resolver.
  WiFi.mode(WIFI_STA);
  if (WIFI_SSID[0] != '\0') {
    Serial.printf("\nconnecting to %s ...\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start) < 20000) {
      delay(250);
    }
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("ip: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\nnot associated - running against loopback anyway");
  }
  delay(500);

  if (!startServer()) {
    Serial.println("server failed to start - skipping the rest");
    Serial.printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return;
  }
  delay(500);

  test_refused_connect();
  test_destroy_inside_onerror();
  test_abandoned_lookup();
  test_echo();
  test_close_inside_ondata();
  test_destroy_inside_ondata();

  Serial.printf("\n%d passed, %d failed\n", g_pass, g_fail);
}

void loop() {
  delay(1000);
}
