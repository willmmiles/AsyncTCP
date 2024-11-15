/*
  Asynchronous TCP library for Espressif MCUs

  Copyright (c) 2016 Hristo Gochkov. All rights reserved.
  This file is part of the esp8266 core for Arduino environment.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "Arduino.h"

#include "AsyncTCP.h"
extern "C"{
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/inet.h"
#include "lwip/dns.h"
#include "lwip/err.h"
}
#include "esp_task_wdt.h"

#ifdef ASYNC_TCP_DEBUG
#define DEBUG_PRINTF(...) log_d(__VA_ARGS__)
#else
#define DEBUG_PRINTF(...)
#endif

/*
 * TCP/IP Event Task
 * */

typedef enum {
    LWIP_TCP_SENT, LWIP_TCP_RECV, LWIP_TCP_FIN, LWIP_TCP_ERROR, LWIP_TCP_POLL, LWIP_TCP_ACCEPT, LWIP_TCP_CONNECTED, LWIP_TCP_DNS
} lwip_event_t;

struct AsyncClient_event_t {
        AsyncClient_event_t* next;
        lwip_event_t event;
        AsyncClient *client;
#ifdef ASYNCTCP_VALIDATE_PCB
        tcp_pcb* pcb;
#endif                
        union {
                struct {
                        err_t err;
                } connected;
                struct {
                        err_t err;
                } error;
                struct {
                        uint16_t len;
                } sent;
                struct {
                        pbuf * pb;
                        err_t err;
                } recv;
                struct {
                        err_t err;
                } fin;
                struct {
                    AsyncServer* server;
                } accept;
                struct {
                        const char * name;
                        ip_addr_t addr;
                } dns;
        };
};

// Forward declarations for TCP event callbacks
static int8_t _tcp_recv(void * arg, struct tcp_pcb * pcb, struct pbuf *pb, err_t err);
static int8_t _tcp_sent(void * arg, struct tcp_pcb * pcb, uint16_t len);
static void _tcp_error(void * arg, err_t err);
static int8_t _tcp_poll(void * arg, struct tcp_pcb * pcb);

// helper function
static AsyncClient_event_t* _alloc_event(lwip_event_t event, AsyncClient* client, tcp_pcb* pcb) {
    // Validation check
    if (pcb && (client->pcb() != pcb)) {
        // Client structure is corrupt?
        log_e("Client mismatch allocating event for 0x%08x 0x%08x vs 0x%08x",(intptr_t)client, (intptr_t)pcb,client->pcb());
        tcp_abort(pcb);
        _tcp_error(client, ERR_ARG);
        return nullptr;
    }

    AsyncClient_event_t * e = (AsyncClient_event_t *)malloc(sizeof(AsyncClient_event_t));

    if (!e) {
        // Allocation fail - abort client and give up
        log_e("OOM allocating event for 0x%08x 0x%08x",(intptr_t)client, (intptr_t)pcb);
        if (pcb) tcp_abort(pcb);
        _tcp_error(client, ERR_MEM);
        return nullptr;
    }
    
    e->next = nullptr;
    e->event = event;
    e->client = client;
#ifdef ASYNCTCP_VALIDATE_PCB
    e->pcb = pcb;
#endif
    DEBUG_PRINTF("_AE: 0x%08x -> %d 0x%08x 0x%08x",(intptr_t) e, (int)event, (intptr_t)client, (intptr_t)pcb);
    return e;
}

static void _free_event(AsyncClient_event_t* evpkt) {
    DEBUG_PRINTF("_FE: 0x%08x -> %d 0x%08x [0x%08x]",(intptr_t) evpkt, (int)evpkt->event, (intptr_t)evpkt->client, (intptr_t) evpkt->next);
    if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pb != nullptr)) {
        // We must free the packet buffer
        pbuf_free(evpkt->recv.pb);
    }
    free(evpkt);
}


// Global variables
static SemaphoreHandle_t _async_queue_mutex = nullptr;
static AsyncClient_event_t* _async_queue_head = nullptr, *_async_queue_tail = nullptr;
static TaskHandle_t _async_service_task_handle = NULL;

namespace {
    class queue_mutex_guard {
        bool holds_mutex;
        public:            
            inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)) {};
            inline ~queue_mutex_guard() { if (holds_mutex) xSemaphoreGive(_async_queue_mutex); };
            inline explicit operator bool() const { return holds_mutex; };
    };
}

static inline bool _init_async_event_queue(){
    if(!_async_queue_mutex){
        _async_queue_mutex = xSemaphoreCreateMutex();
        if(!_async_queue_mutex){
            return false;
        }
    }
    return true;
}

static inline bool _send_async_event(AsyncClient_event_t * e){
    queue_mutex_guard guard;
    if (guard) {
        if (_async_queue_tail) {
            _async_queue_tail->next = e;
        } else {
            _async_queue_head = e;            
        }
        _async_queue_tail = e;
#ifdef ASYNC_TCP_DEBUG        
        uint32_t n;
        xTaskNotifyAndQuery(_async_service_task_handle, 1, eIncrement, &n);
        DEBUG_PRINTF("SAA: 0x%08x -> 0x%08x 0x%08x - %d",(intptr_t) e, (intptr_t)_async_queue_head, (intptr_t)_async_queue_tail,n);
#else
        xTaskNotifyGive(_async_service_task_handle);
#endif
    }
    return (bool) guard;
}

static inline bool _prepend_async_event(AsyncClient_event_t * e) {
    queue_mutex_guard guard;
    if (guard) {
        if (_async_queue_head) {
            e->next = _async_queue_head;
        } else {
            _async_queue_tail = e;            
        }
        _async_queue_head = e;
#ifdef ASYNC_TCP_DEBUG        
        uint32_t n;
        xTaskNotifyAndQuery(_async_service_task_handle, 1, eIncrement, &n);
        DEBUG_PRINTF("PAA: 0x%08x -> 0x%08x 0x%08x - %d",(intptr_t) e, (intptr_t)_async_queue_head, (intptr_t)_async_queue_tail,n);
#else
        xTaskNotifyGive(_async_service_task_handle);
#endif   
    }
    return (bool) guard;
}

static inline AsyncClient_event_t* _get_async_event(){
    queue_mutex_guard guard;
    AsyncClient_event_t *e = nullptr;
    if (guard) {
        e = _async_queue_head;
        if (_async_queue_head) {
            _async_queue_head = _async_queue_head->next;
        }
        if (!_async_queue_head) _async_queue_tail = nullptr;
        DEBUG_PRINTF("GAA: 0x%08x -> 0x%08x 0x%08x",(intptr_t) e, (intptr_t)_async_queue_head, (intptr_t)_async_queue_tail);
    }
    return e;
}

static bool _remove_events_for(AsyncClient* client){
    queue_mutex_guard guard;    
    if (guard) {
        auto count = 0U, total = 0U;
        auto current = _async_queue_head;
        auto prev = decltype(current) {nullptr};
        while(current != nullptr) {
            ++total;
            if (current->client == client) {
                ++count;
                auto last_next = prev ? &prev->next : &_async_queue_head;                
                *last_next = current->next;
                if (_async_queue_tail == current) _async_queue_tail = prev;
                _free_event(current);                
                current = *last_next;
            } else {
                prev = current;
                current = current->next;
            }
        }
        DEBUG_PRINTF("_REF: Removed %d/%d for 0x%08x",count,total,(intptr_t)client);
    };
    return (bool) guard;
};


// Detail class for interacting with AsyncClient internals, but without exposing the API to other parts of the program
class AsyncClient_detail {
    public:
    static inline AsyncClient_event_t* invalidate_pcb(AsyncClient& client) { client._pcb = nullptr; return client._end_event; };
    static void __attribute__((visibility("internal"))) handle_async_event(AsyncClient_event_t* event);
};

static AsyncClient_event_t* _register_pcb(tcp_pcb* pcb, AsyncClient* client){
    // do client-specific setup
    auto end_event = _alloc_event(LWIP_TCP_ERROR, client, pcb);
    if (end_event) {
        tcp_arg(pcb, client);
        tcp_recv(pcb, &_tcp_recv);
        tcp_sent(pcb, &_tcp_sent);
        tcp_err(pcb, &_tcp_error);
        tcp_poll(pcb, &_tcp_poll, 1);
    };
    return end_event;
}

static void _teardown_pcb(tcp_pcb* pcb) {
    assert(pcb);
    // Do teardown
    auto old_arg = pcb->callback_arg;
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_poll(pcb, NULL, 0);    
    if (old_arg)
    {
        _remove_events_for(reinterpret_cast<AsyncClient*>(old_arg));
    } 
}

void AsyncClient_detail::handle_async_event(AsyncClient_event_t * e){
    // Special cases first
    if(e->event == LWIP_TCP_ERROR){
        DEBUG_PRINTF("-E: 0x%08x %d", e->client, e->error.err);
        // Special case: pcb is now invalid, and will have been null'd out by the lwip thread
        if (e->client)
            e->client->_error(e->error.err);
        return;  // do not free this event, it belongs to the client
    } else if (e->event == LWIP_TCP_DNS){   // client has no PCB allocated yet
        DEBUG_PRINTF("-D: 0x%08x %s = %s", e->client, e->dns.name, ipaddr_ntoa(&e->dns.addr));
        e->client->_dns_found(&e->dns.addr);
    }
    // Now check for client pointer    
    else if(e->client->pcb() == NULL){
        // This can only happen if event processing is racing with closing or destruction in a third task.
        // Drop the event and do nothing.
        DEBUG_PRINTF("event client pcb == NULL: 0x%08x", e->client);
    }
#ifdef ASYNCTCP_VALIDATE_PCB
    else if (e->client.pcb() != e->pcb) {
        log_e("event client pcb mismatch: 0x%08x -> 0x%08x vs 0x%08x", e->client,e->client.pcb(),e->pcb);        
    }
#endif
    // OK, process other events
    // TODO: is a switch-case more code efficient?
    else if(e->event == LWIP_TCP_RECV){
        DEBUG_PRINTF("-R: 0x%08x", e->client->_pcb);
        e->client->_recv(e->recv.pb, e->recv.err);
        e->recv.pb = nullptr;   // client has taken responsibility for freeing it
    } else if(e->event == LWIP_TCP_FIN){
        DEBUG_PRINTF("-F: 0x%08x", e->client->_pcb);
        e->client->_fin(e->fin.err);
    } else if(e->event == LWIP_TCP_SENT){
        DEBUG_PRINTF("-S: 0x%08x", e->client->_pcb);
        e->client->_sent(e->sent.len);
    } else if(e->event == LWIP_TCP_POLL){
        DEBUG_PRINTF("-P: 0x%08x", e->client->_pcb);
        e->client->_poll();
    } else if(e->event == LWIP_TCP_CONNECTED){
        DEBUG_PRINTF("-C: 0x%08x 0x%08x %d", e->client, e->client->_pcb, e->connected.err);
        e->client->_connected(e->connected.err);
    } else if(e->event == LWIP_TCP_ACCEPT){
        DEBUG_PRINTF("-A: 0x%08x 0x%08x", e->client, e->accept.server);
        e->accept.server->_accepted(e->client);
    }
    _free_event(e);
}

static void _async_service_task(void *pvParameters){
    for (;;) {
        while (auto packet = _get_async_event()){
#if CONFIG_ASYNC_TCP_USE_WDT
            if(esp_task_wdt_add(NULL) != ESP_OK){
                log_e("Failed to add async task to WDT");
            }
#endif
            AsyncClient_detail::handle_async_event(packet);
#if CONFIG_ASYNC_TCP_USE_WDT
            if(esp_task_wdt_delete(NULL) != ESP_OK){
                log_e("Failed to remove loop task from WDT");
            }
#endif
        }
        // queue is empty
        // DEBUG_PRINTF("Async task waiting 0x%08",(intptr_t)_async_queue_head);
        auto q = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        // DEBUG_PRINTF("Async task woke = %d 0x%08x",q, (intptr_t)_async_queue_head);
    }
    vTaskDelete(NULL);
    _async_service_task_handle = NULL;
}
/*
static void _stop_async_task(){
    if(_async_service_task_handle){
        vTaskDelete(_async_service_task_handle);
        _async_service_task_handle = NULL;
    }
}
*/
static bool _start_async_task(){
    if(!_init_async_event_queue()){
        return false;
    }
    if(!_async_service_task_handle){
        // do not allow stack depth lower than the minimum allowed
        //configSTACK_DEPTH_TYPE stack_depth = CONFIG_ASYNC_TCP_TASK_STACK_SIZE < configMINIMAL_STACK_SIZE : configMINIMAL_STACK_SIZE : CONFIG_ASYNC_TCP_TASK_STACK_SIZE;
        xTaskCreateUniversal(_async_service_task, "async_tcp", CONFIG_ASYNC_TCP_TASK_STACK_SIZE, NULL, CONFIG_ASYNC_TCP_TASK_PRIORITY, &_async_service_task_handle, CONFIG_ASYNC_TCP_RUNNING_CORE);
        if(!_async_service_task_handle){
            return false;
        }
    }
    return true;
}

/*
 * LwIP Callbacks
 * */

static int8_t _tcp_connected(void * arg, tcp_pcb * pcb, int8_t err) {
    DEBUG_PRINTF("+C: 0x%08x", pcb);
    AsyncClient* client = reinterpret_cast<AsyncClient*>(arg);
    AsyncClient_event_t * e = _alloc_event(LWIP_TCP_CONNECTED, client, pcb);    
    if (e) {
        e->connected.err = err;
        _send_async_event(e);
    }
    return ERR_OK;

}

static int8_t _tcp_poll(void * arg, struct tcp_pcb * pcb) {
    DEBUG_PRINTF("+P: 0x%08x", pcb);
    AsyncClient* client = reinterpret_cast<AsyncClient*>(arg);
    AsyncClient_event_t * e = _alloc_event(LWIP_TCP_POLL, client, pcb);
    if (e != nullptr) {
        _send_async_event(e);
    } 
    return ERR_OK;
}

static int8_t _tcp_recv(void * arg, struct tcp_pcb * pcb, struct pbuf *pb, int8_t err) {
    AsyncClient* client = reinterpret_cast<AsyncClient*>(arg);
    AsyncClient_event_t * e = _alloc_event(LWIP_TCP_RECV, client, pcb);
    if (e != nullptr) {
        if(pb){
            DEBUG_PRINTF("+R: 0x%08x", pcb);
            e->recv.pb = pb;
            e->recv.err = err;
        } else {
            DEBUG_PRINTF("+F: 0x%08x -> 0x%08x", pcb, arg);
            e->event = LWIP_TCP_FIN;
            e->fin.err = err;
        }        
        _send_async_event(e);
    } 
    return ERR_OK;
}

static int8_t _tcp_sent(void * arg, struct tcp_pcb * pcb, uint16_t len) {
    DEBUG_PRINTF("+S: 0x%08x", pcb);
    AsyncClient* client = reinterpret_cast<AsyncClient*>(arg);
    AsyncClient_event_t * e = _alloc_event(LWIP_TCP_SENT, client, pcb);
    if (e != nullptr) {
        e->sent.len = len;
        _send_async_event(e);
    }
    return ERR_OK;
}

static void _tcp_error(void * arg, int8_t err) {
    DEBUG_PRINTF("+E: 0x%08x", arg);
    AsyncClient* client = reinterpret_cast<AsyncClient*>(arg);
    assert(client);
    // The associated pcb is now invalid and will soon be deallocated
    // We call on the preallocated end event from the client object
    AsyncClient_event_t * e = AsyncClient_detail::invalidate_pcb(*client);    
    assert(e);
    e->error.err = err;
    _remove_events_for(client); // FUTURE: we could hold the lock the whole time
    _prepend_async_event(e);
}

static void _tcp_dns_found(const char * name, struct ip_addr * ipaddr, void * arg) {
    DEBUG_PRINTF("+DNS: name=%s ipaddr=0x%08x arg=%x", name, ipaddr, arg);
    auto client = reinterpret_cast<AsyncClient*>(arg);
    AsyncClient_event_t * e = _alloc_event(LWIP_TCP_DNS, client, client->pcb());
    if (e != nullptr) {
        e->dns.name = name;
        if (ipaddr) {
            memcpy(&e->dns.addr, ipaddr, sizeof(struct ip_addr));
        } else {
            memset(&e->dns.addr, 0, sizeof(e->dns.addr));
        }
        _send_async_event(e);
    }
}

// Runs on LWIP thread
static int8_t _tcp_accept(AsyncServer* server, AsyncClient * client) {
    AsyncClient_event_t * e = _alloc_event(LWIP_TCP_ACCEPT, client, client->pcb());
    if (e) {
        e->accept.server = server;
        _send_async_event(e);
        return ERR_OK;
    } else {
        return ERR_MEM;
    }    
}

/*
 * TCP/IP API Calls
 * */

#include "lwip/priv/tcpip_priv.h"

typedef struct {
    struct tcpip_api_call_data call;
    tcp_pcb** pcb_ptr;  // double indirection to manage races with client threads
    int8_t err;
    union {
            struct {
                    const char* data;
                    size_t size;
                    uint8_t apiflags;
            } write;
            size_t received;
            struct {
                    ip_addr_t * addr;
                    uint16_t port;
                    tcp_connected_fn cb;
            } connect;
            struct {
                    ip_addr_t * addr;
                    uint16_t port;
            } bind;
            uint8_t backlog;
    };
} tcp_api_call_t;

// Given the multithreaded nature of this code, it's possible that pcb has
// been invalidated by the stack thread, but the client thread doesn't know
// yet.  Before performing any operation on a pcb, check to make sure we
// are still tracking it.
static inline bool pcb_is_active(tcp_api_call_t& p) {
    return (p.pcb_ptr) && (*p.pcb_ptr);
}

static err_t _tcp_output_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        msg->err = tcp_output(*msg->pcb_ptr);
    }
    return msg->err;
}

static err_t _tcp_write_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        msg->err = tcp_write(*msg->pcb_ptr, msg->write.data, msg->write.size, msg->write.apiflags);
    }
    return msg->err;
}

static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        msg->err = 0;
        tcp_recved(*msg->pcb_ptr, msg->received);
    }
    return msg->err;
}

int8_t AsyncClient::_recved(size_t len) {
    if(!_pcb){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = &_pcb;
    msg.received = len;
    tcpip_api_call(_tcp_recved_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

// Sets *pcb_ptr to nullptr
static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {        
        _teardown_pcb(*msg->pcb_ptr);
        msg->err = tcp_close(*msg->pcb_ptr);
        if (msg->err == ERR_OK) 
            *msg->pcb_ptr = nullptr;
    }
    return msg->err;
}

static esp_err_t _tcp_close(tcp_pcb** pcb_ptr) {
    if(!pcb_ptr || !*pcb_ptr){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = pcb_ptr;
    tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        _teardown_pcb(*msg->pcb_ptr);
        tcp_abort(*msg->pcb_ptr);
        *msg->pcb_ptr = nullptr;
    }
    return msg->err;
}

static esp_err_t _tcp_abort(tcp_pcb** pcb_ptr) {
    if(!pcb_ptr || !*pcb_ptr) {
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = pcb_ptr;
    tcpip_api_call(_tcp_abort_api, (struct tcpip_api_call_data*)&msg);
    assert(*pcb_ptr == nullptr);    // must be true
    return msg.err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = tcp_connect(*msg->pcb_ptr, msg->connect.addr, msg->connect.port, msg->connect.cb);
    return msg->err;
}

static err_t _tcp_bind_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = tcp_bind(*msg->pcb_ptr, msg->bind.addr, msg->bind.port);
    return msg->err;
}

static esp_err_t _tcp_bind(tcp_pcb * pcb, ip_addr_t * addr, uint16_t port) {
    if(!pcb){
        return ESP_FAIL;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = &pcb;
    msg.bind.addr = addr;
    msg.bind.port = port;
    tcpip_api_call(_tcp_bind_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_listen_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = 0;
    *msg->pcb_ptr = tcp_listen_with_backlog(*msg->pcb_ptr, msg->backlog);
    return msg->err;
}

static tcp_pcb * _tcp_listen_with_backlog(tcp_pcb * pcb, uint8_t backlog) {
    if(!pcb){
        return NULL;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = &pcb;
    msg.backlog = backlog?backlog:0xFF;
    tcpip_api_call(_tcp_listen_api, (struct tcpip_api_call_data*)&msg);
    return pcb;
}



/*
  Async TCP Client
 */

AsyncClient::AsyncClient(tcp_pcb* pcb)
: _pcb(pcb)
, _end_event(nullptr)
, _connect_cb(0)
, _connect_cb_arg(0)
, _discard_cb(0)
, _discard_cb_arg(0)
, _sent_cb(0)
, _sent_cb_arg(0)
, _error_cb(0)
, _error_cb_arg(0)
, _recv_cb(0)
, _recv_cb_arg(0)
, _pb_cb(0)
, _pb_cb_arg(0)
, _timeout_cb(0)
, _timeout_cb_arg(0)
, _ack_pcb(true)
, _tx_last_packet(0)
, _rx_timeout(0)
, _rx_last_ack(0)
, _ack_timeout(ASYNC_MAX_ACK_TIME)
, _connect_port(0)
{
    if(_pcb){
        _end_event = _register_pcb(_pcb, this);
        _rx_last_packet = millis();
        if (!_end_event) {
            // Out of memory!!
            log_e("Unable to allocate event");
            // Swallow this PCB, producing a null client object
            tcp_abort(_pcb);
            _pcb = nullptr;
        }
    }
    DEBUG_PRINTF("+AC: 0x%08x -> 0x%08x", _pcb, (intptr_t)this);
}

AsyncClient::~AsyncClient(){    
    if(_pcb) {
        _close();
    }
    if (_end_event) _free_event(_end_event);
    DEBUG_PRINTF("-AC: 0x%08x -> 0x%08x", _pcb, (intptr_t)this);
}

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) {
    return _pcb == other._pcb;
}

/*
 * Callback Setters
 * */

void AsyncClient::onConnect(AcConnectHandler cb, void* arg){
    _connect_cb = cb;
    _connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void* arg){
    _discard_cb = cb;
    _discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void* arg){
    _sent_cb = cb;
    _sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void* arg){
    _error_cb = cb;
    _error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void* arg){
    _recv_cb = cb;
    _recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void* arg){
  _pb_cb = cb;
  _pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void* arg){
    _timeout_cb = cb;
    _timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void* arg){
    _poll_cb = cb;
    _poll_cb_arg = arg;
}

/*
 * Main Public Methods
 * */

bool AsyncClient::connect(IPAddress ip, uint16_t port){
    if (_pcb){
        log_w("already connected, state %d", _pcb->state);
        return false;
    }
    if(!_start_async_task()){
        log_e("failed to start task");
        return false;
    }

    ip_addr_t addr;
    addr.type = IPADDR_TYPE_V4;
    addr.u_addr.ip4.addr = ip;

    _pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!_pcb){
        log_e("pcb == NULL");
        return false;
    }
    _end_event = _register_pcb(_pcb, this);
    if (!_end_event) {
        log_e("Unable to allocate event");
        tcp_abort(_pcb);
        _pcb = nullptr;
        return false;
    }

    tcp_api_call_t msg;
    msg.pcb_ptr = &_pcb;
    msg.connect.addr = &addr;
    msg.connect.port = port;
    msg.connect.cb = (tcp_connected_fn)&_tcp_connected;
    tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data*)&msg);
    return msg.err == ESP_OK;
}

bool AsyncClient::connect(const char* host, uint16_t port){
    if (_pcb){
        log_w("already connected, state %d", _pcb->state);
        return false;
    }    
    if(!_start_async_task()){
      log_e("failed to start task");
      return false;
    }
    
    ip_addr_t addr;
    err_t err = dns_gethostbyname(host, &addr, (dns_found_callback)&_tcp_dns_found, this);
    if(err == ERR_OK) {
        return connect(IPAddress(addr.u_addr.ip4.addr), port);
    } else if(err == ERR_INPROGRESS) {
        _connect_port = port;
        return true;
    }
    log_e("error: %d", err);
    return false;
}

void AsyncClient::close(bool now){
    if(_pcb){
        _recved(_rx_ack_len);
    }
    _close();
}

int8_t AsyncClient::abort(){
    if(_pcb) {
        _tcp_abort(&_pcb);
    }
    return ERR_ABRT;
}

size_t AsyncClient::space(){
    if((_pcb != NULL) && (_pcb->state == 4)){
        return tcp_sndbuf(_pcb);
    }
    return 0;
}

size_t AsyncClient::add(const char* data, size_t size, uint8_t apiflags) {
    if(!_pcb || size == 0 || data == NULL) {
        return 0;
    }
    size_t room = space();
    if(!room) {
        return 0;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = &_pcb;
    msg.err = ERR_OK;
    msg.write.data = data;
    msg.write.size = std::min(room, size);
    msg.write.apiflags = apiflags;
    tcpip_api_call(_tcp_write_api, (struct tcpip_api_call_data*)&msg);
    if(msg.err != ERR_OK) {
        return 0;
    }
    return msg.write.size;
}

bool AsyncClient::send() {
    auto backup = _tx_last_packet;
    _tx_last_packet = millis();
    if(!_pcb){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb_ptr = &_pcb;
    tcpip_api_call(_tcp_output_api, (struct tcpip_api_call_data*)&msg);
    if (msg.err == ERR_OK) return true;
    _tx_last_packet = backup;
    return false;
}

size_t AsyncClient::ack(size_t len){
    if(len > _rx_ack_len)
        len = _rx_ack_len;
    if(len){
        _recved(len);
    }
    _rx_ack_len -= len;
    return len;
}

void AsyncClient::ackPacket(struct pbuf * pb){
  if(!pb){
    return;
  }
  _recved(pb->len);
  pbuf_free(pb);
}

/*
 * Main Private Methods
 * */

int8_t AsyncClient::_close(){
    DEBUG_PRINTF("close: 0x%08x", (uint32_t)this);
    int8_t err = ERR_OK;
    if(_pcb) {
        //log_i("");        
        err = _tcp_close(&_pcb);
        if(err != ERR_OK) {
            err = abort();
        }
        if(_discard_cb) {
            _discard_cb(_discard_cb_arg, this);
        }        
    }
    return err;
}

#ifdef CONFIG_ASYNC_TCP_DIAGNOSTICS

UBaseType_t AsyncClient::getStackHighWaterMark(){
    TaskHandle_t async_service_task_handle = _async_service_task_handle;
    if(async_service_task_handle){
        return uxTaskGetStackHighWaterMark(async_service_task_handle);
    } else {
        // task is not allocated, just return the configured size
        return CONFIG_ASYNC_TCP_TASK_STACK_SIZE;
    }
}

#endif

/*
 * Private Callbacks
 * */

int8_t AsyncClient::_connected(int8_t err){
    _rx_last_packet = millis();
    if(_connect_cb) {
        _connect_cb(_connect_cb_arg, this);
    }
    return ERR_OK;
}

void AsyncClient::_error(int8_t err) {    
    if(_error_cb) {
        _error_cb(_error_cb_arg, this, err);
    }
    if(_discard_cb) {
        _discard_cb(_discard_cb_arg, this);
    }
}

//In Async Thread
int8_t AsyncClient::_fin(int8_t err) {
    // WM: This isn't strictly correct -- we should instead pass this to a callback
    // _fin() merely indicates that the remote end is closing, it doesn't require us
    // to close until we're done sending.
    _close();
    return ERR_OK;
}

int8_t AsyncClient::_sent(uint16_t len) {
    _rx_last_packet = _rx_last_ack = millis();
    //log_i("%u", len);
    if(_sent_cb) {
        _sent_cb(_sent_cb_arg, this, len, (_rx_last_packet - _tx_last_packet));
    }
    return ERR_OK;
}

int8_t AsyncClient::_recv(pbuf* pb, int8_t err) {
    while(pb != NULL) {
        _rx_last_packet = millis();
        //we should not ack before we assimilate the data
        _ack_pcb = true;
        pbuf *b = pb;
        pb = b->next;
        b->next = NULL;
        if(_pb_cb){
            _pb_cb(_pb_cb_arg, this, b);
        } else {
            if(_recv_cb) {
                _recv_cb(_recv_cb_arg, this, b->payload, b->len);
            }
            if(!_ack_pcb) {
                _rx_ack_len += b->len;
            } else if(_pcb) {
                _recved(b->len);
            }
            pbuf_free(b);
        }
    }
    return ERR_OK;
}

int8_t AsyncClient::_poll(){
    uint32_t now = millis();

    // ACK Timeout
    if(_ack_timeout){
        const uint32_t one_day = 86400000;
        bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
        if(last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
            log_w("ack timeout %d", _pcb->state);
            if(_timeout_cb)
                _timeout_cb(_timeout_cb_arg, this, (now - _tx_last_packet));
            return ERR_OK;
        }
    }
    // RX Timeout
    if(_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
        log_w("rx timeout %d", _pcb->state);
        _close();
        return ERR_OK;
    }
    // Everything is fine
    if(_poll_cb) {
        _poll_cb(_poll_cb_arg, this);
    }
    return ERR_OK;
}

void AsyncClient::_dns_found(struct ip_addr *ipaddr){
    if(ipaddr && ipaddr->u_addr.ip4.addr){
        connect(IPAddress(ipaddr->u_addr.ip4.addr), _connect_port);
    } else {
        if(_error_cb) {
            _error_cb(_error_cb_arg, this, -55);
        }
        if(_discard_cb) {
            _discard_cb(_discard_cb_arg, this);
        }
    }
}

/*
 * Public Helper Methods
 * */

void AsyncClient::stop() {
    close(false);
}

bool AsyncClient::free(){
    if(!_pcb) {
        return true;
    }
    if(_pcb->state == 0 || _pcb->state > 4) {
        return true;
    }
    return false;
}

size_t AsyncClient::write(const char* data) {
    if(data == NULL) {
        return 0;
    }
    return write(data, strlen(data));
}

size_t AsyncClient::write(const char* data, size_t size, uint8_t apiflags) {
    size_t will_send = add(data, size, apiflags);
    if(!will_send || !send()) {
        return 0;
    }
    return will_send;
}

void AsyncClient::setRxTimeout(uint32_t timeout){
    _rx_timeout = timeout;
}

uint32_t AsyncClient::getRxTimeout(){
    return _rx_timeout;
}

uint32_t AsyncClient::getAckTimeout(){
    return _ack_timeout;
}

void AsyncClient::setAckTimeout(uint32_t timeout){
    _ack_timeout = timeout;
}

void AsyncClient::setNoDelay(bool nodelay){
    if(!_pcb) {
        return;
    }
    if(nodelay) {
        tcp_nagle_disable(_pcb);
    } else {
        tcp_nagle_enable(_pcb);
    }
}

bool AsyncClient::getNoDelay(){
    if(!_pcb) {
        return false;
    }
    return tcp_nagle_disabled(_pcb);
}

uint16_t AsyncClient::getMss(){
    if(!_pcb) {
        return 0;
    }
    return tcp_mss(_pcb);
}

uint32_t AsyncClient::getRemoteAddress() {
    if(!_pcb) {
        return 0;
    }
    return _pcb->remote_ip.u_addr.ip4.addr;
}

uint16_t AsyncClient::getRemotePort() {
    if(!_pcb) {
        return 0;
    }
    return _pcb->remote_port;
}

uint32_t AsyncClient::getLocalAddress() {
    if(!_pcb) {
        return 0;
    }
    return _pcb->local_ip.u_addr.ip4.addr;
}

uint16_t AsyncClient::getLocalPort() {
    if(!_pcb) {
        return 0;
    }
    return _pcb->local_port;
}

IPAddress AsyncClient::remoteIP() {
    return IPAddress(getRemoteAddress());
}

uint16_t AsyncClient::remotePort() {
    return getRemotePort();
}

IPAddress AsyncClient::localIP() {
    return IPAddress(getLocalAddress());
}

uint16_t AsyncClient::localPort() {
    return getLocalPort();
}

uint8_t AsyncClient::state() {
    if(!_pcb) {
        return 0;
    }
    return _pcb->state;
}

bool AsyncClient::connected(){
    if (!_pcb) {
        return false;
    }
    return _pcb->state == 4;
}

bool AsyncClient::connecting(){
    if (!_pcb) {
        return false;
    }
    return _pcb->state > 0 && _pcb->state < 4;
}

bool AsyncClient::disconnecting(){
    if (!_pcb) {
        return false;
    }
    return _pcb->state > 4 && _pcb->state < 10;
}

bool AsyncClient::disconnected(){
    if (!_pcb) {
        return true;
    }
    return _pcb->state == 0 || _pcb->state == 10;
}

bool AsyncClient::freeable(){
    if (!_pcb) {
        return true;
    }
    return _pcb->state == 0 || _pcb->state > 4;
}

bool AsyncClient::canSend(){
    return space() > 0;
}

const char * AsyncClient::errorToString(int8_t error){
    switch(error){
        case ERR_OK: return "OK";
        case ERR_MEM: return "Out of memory error";
        case ERR_BUF: return "Buffer error";
        case ERR_TIMEOUT: return "Timeout";
        case ERR_RTE: return "Routing problem";
        case ERR_INPROGRESS: return "Operation in progress";
        case ERR_VAL: return "Illegal value";
        case ERR_WOULDBLOCK: return "Operation would block";
        case ERR_USE: return "Address in use";
        case ERR_ALREADY: return "Already connected";
        case ERR_CONN: return "Not connected";
        case ERR_IF: return "Low-level netif error";
        case ERR_ABRT: return "Connection aborted";
        case ERR_RST: return "Connection reset";
        case ERR_CLSD: return "Connection closed";
        case ERR_ARG: return "Illegal argument";
        case -55: return "DNS failed";
        default: return "UNKNOWN";
    }
}

const char * AsyncClient::stateToString(){
    switch(state()){
        case 0: return "Closed";
        case 1: return "Listen";
        case 2: return "SYN Sent";
        case 3: return "SYN Received";
        case 4: return "Established";
        case 5: return "FIN Wait 1";
        case 6: return "FIN Wait 2";
        case 7: return "Close Wait";
        case 8: return "Closing";
        case 9: return "Last ACK";
        case 10: return "Time Wait";
        default: return "UNKNOWN";
    }
}

/*
  Async TCP Server
 */

AsyncServer::AsyncServer(IPAddress addr, uint16_t port)
: _port(port)
, _addr(addr)
, _noDelay(false)
, _pcb(0)
, _connect_cb(0)
, _connect_cb_arg(0)
{}

AsyncServer::AsyncServer(uint16_t port)
: _port(port)
, _addr((uint32_t) IPADDR_ANY)
, _noDelay(false)
, _pcb(0)
, _connect_cb(0)
, _connect_cb_arg(0)
{}

AsyncServer::~AsyncServer(){
    end();
}

void AsyncServer::onClient(AcConnectHandler cb, void* arg){
    _connect_cb = cb;
    _connect_cb_arg = arg;
}

void AsyncServer::begin(){
    if(_pcb) {
        return;
    }

    if(!_start_async_task()){
        log_e("failed to start task");
        return;
    }
    int8_t err;
    _pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!_pcb){
        log_e("_pcb == NULL");
        return;
    }

    ip_addr_t local_addr;
    local_addr.type = IPADDR_TYPE_V4;
    local_addr.u_addr.ip4.addr = (uint32_t) _addr;
    err = _tcp_bind(_pcb, &local_addr, _port);

    if (err != ERR_OK) {
        _tcp_close(&_pcb);
        log_e("bind error: %d", err);
        return;
    }

    static uint8_t backlog = 5;
    _pcb = _tcp_listen_with_backlog(_pcb, backlog);
    if (!_pcb) {
        log_e("listen_pcb == NULL");
        return;
    }
    tcp_arg(_pcb, (void*) this);
    tcp_accept(_pcb, &_s_accept);
}

void AsyncServer::end(){
    if(_pcb){
        tcp_arg(_pcb, NULL);
        tcp_accept(_pcb, NULL);
        if(tcp_close(_pcb) != ERR_OK){
            tcp_abort(_pcb);
        }
        _pcb = NULL;
    }
}

//runs on LwIP thread
int8_t AsyncServer::_accept(tcp_pcb* pcb, int8_t err){
    DEBUG_PRINTF("+A: 0x%08x %d", pcb, err);    
    if (pcb) {
        if(_connect_cb){
            AsyncClient *c = new AsyncClient(pcb);
            if (c && c->pcb()) {
                c->setNoDelay(_noDelay);
                if (_tcp_accept(this, c) == ERR_OK) return ERR_OK;  // success
            } 
            if (c->pcb()) {
                // Couldn't allocate accept event
                // We can't let the client object call in to close, as we're on the LWIP thread; it could deadlock trying to RPC to itself
                AsyncClient_detail::invalidate_pcb(*c);
                tcp_abort(pcb);
            }            
            if (c) {
                // Couldn't complete setup
                // pcb has already been aborted
                delete c;
                pcb = nullptr;
            }
        }
        if (pcb) {
            if(tcp_close(pcb) != ERR_OK){
                tcp_abort(pcb);
            }
        }
    }
    log_e("TCP ACCEPT FAIL");
    return ERR_OK;
}

int8_t AsyncServer::_accepted(AsyncClient* client){
    if(_connect_cb){
        _connect_cb(_connect_cb_arg, client);
    }
    return ERR_OK;
}

void AsyncServer::setNoDelay(bool nodelay){
    _noDelay = nodelay;
}

bool AsyncServer::getNoDelay(){
    return _noDelay;
}

uint8_t AsyncServer::status(){
    if (!_pcb) {
        return 0;
    }
    return _pcb->state;
}

int8_t AsyncServer::_s_accept(void * arg, tcp_pcb * pcb, int8_t err){
    return reinterpret_cast<AsyncServer*>(arg)->_accept(pcb, err);
}

int8_t AsyncServer::_s_accepted(void *arg, AsyncClient* client){
    return reinterpret_cast<AsyncServer*>(arg)->_accepted(client);
}
