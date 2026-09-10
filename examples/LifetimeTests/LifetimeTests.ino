// Self-checking lifetime tests for AsyncTCP.
//
// These exercise the object-lifetime paths that are hard to reach from ordinary use:
// destroying a client from inside its own callbacks, abandoning a name lookup, and
// failed connects.  Each test finishes by waiting for asyncTcpLiveClientCount() to
// settle back to its baseline, which is what catches a leaked reference.
//
// Tests 1-6 need no network.  Tests 7-10 connect the board to a server running on
// itself, so they need WiFi; set the credentials below or they will be skipped.
//
// To build: set `src_dir = examples/LifetimeTests` in platformio.ini, then
//   pio run -e arduino-3 -t upload && pio device monitor
// Read the summary at the end.

#include <Arduino.h>
#include <AsyncTCP.h>
#include <WiFi.h>

static const char *WIFI_SSID = "";  // leave empty to skip the networked tests
static const char *WIFI_PASS = "";
static const uint16_t TEST_PORT = 8099;

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

// The count only settles once every queued event referencing a destroyed client has
// drained, so give it a moment rather than sampling immediately.
static bool waitClients(size_t expected, uint32_t timeout_ms) {
  uint32_t start = millis();
  while ((millis() - start) < timeout_ms) {
    if (asyncTcpLiveClientCount() == expected) {
      return true;
    }
    delay(10);
  }
  Serial.printf("    (live clients: %u, expected %u)\n", (unsigned)asyncTcpLiveClientCount(), (unsigned)expected);
  return false;
}

// ---------------------------------------------------------------- no network needed

static void test_construct_destroy(size_t base) {
  { AsyncClient c; }
  check("1. construct and destroy leaks nothing", waitClients(base, 1000));
}

static void test_connect_unroutable(size_t base) {
  static volatile bool errored = false;
  errored = false;
  {
    AsyncClient c;
    c.onError([](void *, AsyncClient *, int8_t) {
      errored = true;
    });
    // 192.0.2.0/24 is reserved for documentation and should never route
    IPAddress unroutable(192, 0, 2, 1);
    c.connect(unroutable, 80);
    waitFlag(errored, 15000);
  }
  check("2. unroutable connect reports an error", errored);
  check("3. ...and leaks nothing once it settles", waitClients(base, 5000));
}

static void test_destroy_inside_onerror(size_t base) {
  static volatile bool errored = false;
  errored = false;
  AsyncClient *c = new AsyncClient();
  // The dangerous case: the std::function being executed belongs to this object
  c->onError(
    [](void *arg, AsyncClient *, int8_t) {
      delete static_cast<AsyncClient *>(arg);
      errored = true;
    },
    c
  );
  IPAddress unroutable(192, 0, 2, 2);
  c->connect(unroutable, 80);
  waitFlag(errored, 15000);
  check("4. destroying the client inside onError survives", errored);
  check("5. ...and leaks nothing once it settles", waitClients(base, 5000));
}

static void test_abandoned_lookup(size_t base) {
  {
    AsyncClient c;
    // No DNS server configured yet, so this either fails immediately or stays pending
    c.connect("test-host-that-does-not-exist.invalid", 80);
    c.close();  // abandon it while it may still be in flight
  }
  // LwIP cannot cancel a lookup, so the reference lives until its timeout fires
  check("6. closing during a lookup leaks nothing (slow: DNS timeout)", waitClients(base, 45000));
}

// -------------------------------------------------------------------- needs network

static AsyncServer *g_server = nullptr;
static AsyncClient *g_accepted = nullptr;

static bool startServer() {
  g_server = new AsyncServer(TEST_PORT);
  g_server->onClient(
    [](void *, AsyncClient *c) {
      g_accepted = c;
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

static void test_echo(size_t base) {
  static volatile bool got = false;
  got = false;
  {
    AsyncClient c;
    static volatile bool connected = false;
    connected = false;
    c.onConnect([](void *, AsyncClient *client) {
      connected = true;
      client->write("ping");
    });
    c.onData([](void *, AsyncClient *, void *, size_t) {
      got = true;
    });
    c.connect(WiFi.localIP(), TEST_PORT);
    waitFlag(got, 10000);
    check("7. echo round trip", got);
    c.close();
    delay(200);
  }
  check("8. echo client leaks nothing", waitClients(base, 5000));
}

static void test_close_inside_ondata(size_t base) {
  static volatile bool closed = false;
  closed = false;
  {
    AsyncClient c;
    c.onConnect([](void *, AsyncClient *client) {
      client->write("ping");
    });
    c.onData([](void *, AsyncClient *client, void *, size_t) {
      client->close();  // must ack the packet first, or the peer sees an RST
      closed = true;
    });
    c.connect(WiFi.localIP(), TEST_PORT);
    waitFlag(closed, 10000);
  }
  check("9. closing inside onData survives", closed);
  check("10. ...and leaks nothing once it settles", waitClients(base, 5000));
}

static void test_destroy_inside_ondata(size_t base) {
  static volatile bool destroyed = false;
  destroyed = false;
  AsyncClient *c = new AsyncClient();
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
  c->connect(WiFi.localIP(), TEST_PORT);
  waitFlag(destroyed, 10000);
  check("11. destroying the client inside onData survives", destroyed);
  check("12. ...and leaks nothing once it settles", waitClients(base, 5000));
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\n\nAsyncTCP lifetime tests\n");

  // Force the async task to exist so the baseline is stable
  { AsyncClient warmup; }
  delay(500);
  const size_t base = asyncTcpLiveClientCount();
  Serial.printf("baseline live clients: %u\n\n", (unsigned)base);

  test_construct_destroy(base);
  test_connect_unroutable(base);
  test_destroy_inside_onerror(base);
  test_abandoned_lookup(base);

  if (WIFI_SSID[0] == '\0') {
    Serial.println("\n(no WiFi credentials set - skipping networked tests)");
  } else {
    Serial.printf("\nconnecting to %s ...\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start) < 20000) {
      delay(250);
    }
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("WiFi failed - skipping networked tests");
    } else {
      Serial.printf("ip: %s\n\n", WiFi.localIP().toString().c_str());
      if (!startServer()) {
        Serial.println("server failed to start - skipping networked tests");
      } else {
        const size_t sbase = asyncTcpLiveClientCount();
        test_echo(sbase);
        test_close_inside_ondata(sbase);
        test_destroy_inside_ondata(sbase);
      }
    }
  }

  Serial.printf("\n%d passed, %d failed\n", g_pass, g_fail);
}

void loop() {
  delay(1000);
}
