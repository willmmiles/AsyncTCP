# Refcounted implementation object

Status: **implemented** on this branch, verified by host tests only.
No hardware run yet, and no performance measurement yet - see Remaining.

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

## What landed

Seven fixes re-landed from the abandoned branches, then the migration:

| Commit | |
|---|---|
| `ef69151` | remove unreferenced function |
| `578d0f3` | null-guard `setKeepAlive` |
| `255d16c` | close the bound pcb when listen fails |
| `061354a` | drop queued accept events on `end()` |
| `fe158b5` | accept-path cleanup (reset callbacks *and* destroy the client) |
| `a4e3ac3` | reset per-connection state on adopt; dispose the pcb on failed connect |
| `0a08f66` | report DNS failures instead of connecting to 0.0.0.0 |
| `5113e63` | **the migration** |
| `3a74bbe` | `asyncTcpLiveClientCount()` + on-target lifetime sketch |
| `54238cb` | stop casting pcb pointers to `uint32_t` when logging |
| `1e96560` | host-native harness, 47 tests |

Answers to the questions the plan raised:

- **Refcount**: plain `uint16_t` guarded by `_async_queue_mutex`, no atomics. Holders
  are the facade, each queued event, LwIP's callback argument while a pcb is bound, and
  an outstanding lookup.
- **Last reference on the wrong thread**: solved by construction. A bound pcb holds a
  reference, so the count cannot reach zero while one is attached, and the destructor
  never has to close anything. It logs if that invariant is ever violated.
- **`ack_len` nesting**: `_in_callback_ack_len` is a single field on the implementation.
  A nested frame never reads it, so no chain is needed. `_cb_ctx` is gone entirely.
- **DNS holds a reference until timeout**: yes, and that is now the documented behavior
  rather than a dangling pointer. `close()`/`abort()` mark the answer unwanted.
- **Header leakage**: gone. `AsyncTCP.h` has the public API and an opaque pointer.
- **`tcp_*_api`**: `_tcp_close`/`_tcp_abort` take the implementation.

Two bugs the host tests caught that three green target builds did not:

1. `AsyncClientImpl::ackLater()` declared but never defined - it had been inline in the
   header, so the migration left nothing behind. Nothing in the examples calls it, so it
   linked fine on target.
2. A deadlock: `_free_event()` releases a reference, which takes the queue mutex, and
   `_get_async_event()` was calling it *while holding* that non-recursive mutex. It
   would have hung on the first coalesced poll event under load.

## Remaining

- **Pre-allocate the terminal event.** Still the one hole: if `tcp_error` cannot
  allocate, the client is orphaned with no way to report. With an implementation object
  it can be allocated once at construction. Small, orthogonal, and now the only thing
  keeping that window open.
- **Hardware run.** `examples/LifetimeTests` is a self-checking sketch; tests 1-6 need
  no network, 7-12 run a server on the board and connect to it.
- **Performance.** Compare against the pre-migration branch using the ESPAsyncWebServer
  benchmarks. The refcount adds one guarded increment per event; the pimpl adds one
  indirection per accessor. Neither has been measured.
- **ESPAsyncWebServer compatibility.** It deletes an `AsyncClient` from inside that
  client's own `onDisconnect`, which is precisely the path this refactor changes. Build
  and run it before believing any of this.
- **Public API breaks not yet taken.** `AsyncClient::pcb()` and `_recv()` are still
  public and still work; the `AsyncClient(tcp_pcb*)` constructor is still public. The
  plan was to make them private with a `friend`, which would be a source break for
  anyone using them.
- **Races.** The harness is single-threaded by construction and cannot find them. The
  one known unsynchronized read is `_facade` in the dispatcher, which is the same shape
  as the pre-existing unlocked `_pcb` reads.
