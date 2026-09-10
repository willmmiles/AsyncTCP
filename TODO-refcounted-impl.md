# Refcounted implementation object

Status: **planning**. Nothing implemented yet.

## Why

`AsyncClient` is a raw pointer held by three parties with no ownership discipline:
the event queue, LwIP callback arguments, and callback stack frames. Each grew its
own ad-hoc liveness mechanism:

| Holder | Current mechanism | Covers |
|---|---|---|
| Event queue | `_pending_event` back-reference + `remove_events_for_client()` purges | event queued, client destroyed before dispatch |
| LwIP DNS arg | pre-allocated event passed as `arg`, back-reference nulled on detach | lookup in flight, client destroyed |
| Callback frame | `_cb_ctx` chain + `client_is_valid` | client destroyed *during* a user callback |

None of them compose, and two holes remain open that none of them can close:

1. **Pop-then-dispatch.** The async task pops an event into a local and releases the
   queue mutex before invoking the callback. A destruction in that gap dangles. A
   purge structurally cannot reach an event that is no longer in the queue.
2. **`std::function` destroyed mid-call.** Deleting the client inside `onData`
   destroys `_recv_cb` while its `operator()` is on the stack. `_cb_ctx` avoids
   touching `this` afterwards but cannot fix this — it is UB today.

A refcounted impl closes both: the dispatcher holds a strong reference across the
callback, so neither the impl nor the callbacks it owns can be freed underneath it.

## Shape

`AsyncClient` stays a user-owned, deletable facade — this is not negotiable.
ESPAsyncWebServer does `delete _client` in `~AsyncWebServerRequest`, itself reached
from inside the client's own `onDisconnect`. So the shared lifetime lives on an impl
behind the facade, not on `AsyncClient` itself.

```
class AsyncClient {            // public API, unchanged, user-owned
  refptr<AsyncClientImpl> _impl;
};
```

`~AsyncClient` marks the impl detached and drops its reference. In-flight holders
find it detached and do nothing.

### What moves into the impl

- `_pcb`
- all callbacks and their args (16 members) — held alive for the duration of a call
- `_tx_last_packet`, `_rx_ack_len`, `_rx_last_packet`, `_rx_timeout`, `_rx_last_ack`,
  `_ack_timeout`
- `ack_later` / `ack_len` (they only ever needed to outlive the `AsyncClient`)
- `detached` flag — replaces the `_cb_ctx` chain's `client_is_valid` role

`_cb_ctx` itself may still be needed if `ack_len` must nest; see open questions.

### Header surface after

`AsyncTCP.h` should end up with no internals at all:

- **Gone:** every protected data member, `friend class AsyncTCP_detail`, the
  `AsyncClientCallbackContext` and `lwip_tcp_event_packet_t` forward declarations,
  and the private callback methods (`_adopt`, `_connected`, `_error`, `_poll`,
  `_sent`, `_fin`, `_dns_found`, `_resolving`).
- **Gone, but API breaks:** `AsyncClient::pcb()` and `AsyncClient::_recv()` are
  currently *public*. `AsyncClient(tcp_pcb*)` is public too and is how `AsyncServer`
  builds clients — wants to become private + `friend class AsyncServer`.
- **Stays:** `ip_addr_t`, `ip4_addr_t`, `ip6_addr_t`, `pbuf*` — they are in public
  signatures. `freertos/semphr.h` looks unused; check whether it can go.

### `tcp_*_api` calls

The `tcp_pcb **` double indirection exists only so the api call can null the
caller's `_pcb` under the LwIP lock. Pass the impl instead:

```
msg.impl = impl;     // instead of msg.pcb = &client->_pcb
```

and read/write `impl->_pcb` directly inside the call. The union member
`AsyncClient *close` disappears with it — the impl is already the thing being
operated on. No reference counting needed on this path: the call is synchronous and
the caller already holds a reference.

### Refcount

Do **not** reach for `std::shared_ptr` by default. The cost that matters is an
atomic inc/dec per event enqueue and dispatch, on a dual-core part, on a queue that
runs 64 deep under load. Every cross-thread handoff here already passes through the
queue mutex or the LwIP core lock, so an intrusive non-atomic count guarded by the
queue mutex should give the same semantics without the atomics.

Pick **one** lock for all incref/decref. The queue mutex is the natural choice;
binding to a pcb happens under the core lock, and core -> queue is the established
order, so taking it there is fine.

## Open questions

- **Last reference on the wrong thread.** If the impl destructor still needs to close
  a pcb, it makes a `tcpip_api_call` — which deadlocks if the last reference is
  dropped on the LwIP thread. Needs a rule: the impl must be fully detached (pcb
  closed, callbacks reset) before its last reference can go.
- **Does `ack_len` nest?** `_recv` sets it per pbuf; `abort()` inside `onData`
  re-enters `_error`. A single impl-level field may be enough since the nested frame
  never reads it, but check before deleting `_cb_ctx`.
- **DNS holds a reference until timeout.** A detached client's impl would survive
  until LwIP's DNS callback fires. Bounded, but non-obvious — worth a comment.
- **`AsyncServer` is still a raw pointer** in accept events. Same class of problem,
  probably out of scope for v1.
- **Unsynchronized accessors.** `space()`, `canSend()`, `state()`, `connected()`,
  `getMss()` read `_pcb->state` / `tcp_sndbuf(_pcb)` with no lock at all. They are
  fast because they are racy. Decide separately whether this refactor fixes that; if
  it does, the extra indirection disappears into the lock cost anyway.
- **Downstream testing.** ESPAsyncWebServer already uses `shared_ptr` for its own
  request lifetime and is the main consumer of the API being changed.

## Sequencing

`close-in-callback-safety` and `yet-more-safety` are **superseded, not landed**. The
whole point is to skip the commits that solve problems refcounting solves anyway.
What matters is that the fixes they contain are not discarded along with the
mechanisms.

### Re-land from `main` as an independent series

Orthogonal to ownership — nothing to do with refcounting, and worth shipping without
waiting for this refactor.

| Commit | Note |
|---|---|
| `681d3d3` remove unreferenced function | clean pick |
| `c214858` null-guard setKeepAlive | clean pick |
| `51e38dd` close bound pcb on listen failure | clean pick |
| `c7911e7` drop queued accept events on end | clean pick |
| `46a102a` accept path cleanup | clean pick |
| `fcddcb7` reset per-connection state on adopt | adapt — its ack flush walks `_cb_ctx`, which will not exist |
| `ac36acd` DNS fixes | adapt — keep the bug fixes, drop the pending-event mechanism |

### Superseded — do not port

| Commit | Replaced by |
|---|---|
| `6ebddca` ensure callbacks handle destruction | dispatcher holds a reference; `detached` flag |
| `6439d9d` warning disable generates warnings | the `-Wdangling-pointer` pragma exists only for `_cb_ctx` |
| `88c11a7` ack final pbuf (mechanism only) | `ack_len` moves into the impl |
| `7c6d728` pending error event | queue holds a reference |
| `31a8859` test pending event in close/abort | ditto |
| `d6cd4b5` pre-commit fixes | formatting on the above |

### Behavior that must survive

Dropping the commits must not drop the bugs they found. There are no unit tests in
this repo, so this list is the only record. Each was a real, reproduced defect:

- Closing inside `onData` must ack the final pbuf, or the peer gets RST not FIN (`88c11a7`)
- Destroying a client inside any user callback must be safe (`6ebddca`)
- A failed DNS lookup must raise `-55`, not connect to `0.0.0.0` (`ac36acd`)
- `connect(host, port)` returning true must end in exactly one `onConnect` or `onError` (`ac36acd`)
- A second `connect()` during an outstanding lookup is swallowed and returns true (`ac36acd`)
- `tcp_error` for a client that does not own the failed pcb must not queue an event (`7c6d728`)
- `tcp_connect()` failure must dispose of the pcb, clearing `local_port` first unless we were handed a bound one (`fcddcb7`)
- Poll processing must be skipped while still connecting (`fcddcb7`)
- A stale `_rx_ack_len` must not survive into a reconnect (`fcddcb7`)
- `AsyncServer::begin()` must close the bound pcb when listen fails, or the port stays reserved for the boot (`51e38dd`)
- Accept-event allocation failure must reset callbacks before abort *and* destroy the client (`46a102a`)

### Still outstanding either way

**Pre-allocating the terminal event** so `tcp_error` cannot fail to report under
memory pressure. Small, orthogonal, closes a live hole — and with an impl it gets a
better home, allocated once at impl construction rather than at every pcb adoption.
