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

static_assert(__gnu_cxx::__default_lock_policy != __gnu_cxx::_S_single, "shared_ptr is not thread safe - upgrade your toolchain");

/*
 * TCP/IP Event Task
 * */

typedef enum {
    LWIP_TCP_SENT, LWIP_TCP_RECV, LWIP_TCP_FIN, LWIP_TCP_ERROR, LWIP_TCP_POLL, LWIP_TCP_CLEAR, LWIP_TCP_ACCEPT, LWIP_TCP_CONNECTED, LWIP_TCP_DNS
} lwip_event_t;

typedef struct {
        lwip_event_t event;
        void *arg;
        union {
                struct {
                        void * pcb;
                        int8_t err;
                } connected;
                struct {
                        int8_t err;
                } error;
                struct {
                        tcp_pcb * pcb;
                        uint16_t len;
                } sent;
                struct {
                        tcp_pcb * pcb;
                        pbuf * pb;
                        int8_t err;
                } recv;
                struct {
                        tcp_pcb * pcb;
                        int8_t err;
                } fin;
                struct {
                        tcp_pcb * pcb;
                } poll;
                struct {
                        AsyncClient * client;
                } accept;
                struct {
                        const char * name;
                        ip_addr_t addr;
                } dns;
        };
} lwip_event_packet_t;

// Forward declarations for TCP event callbacks
static int8_t _tcp_recv(void * arg, struct tcp_pcb * pcb, struct pbuf *pb, int8_t err);
static int8_t _tcp_sent(void * arg, struct tcp_pcb * pcb, uint16_t len);
static void _tcp_error(void * arg, int8_t err);
static int8_t _tcp_poll(void * arg, struct tcp_pcb * pcb);

// Global variables
static xQueueHandle _async_queue;
static TaskHandle_t _async_service_task_handle = NULL;

static inline bool is_valid(const std::shared_ptr<tcp_pcb*>& ref) { return ref && *ref; }

static void _teardown_pcb(tcp_pcb* pcb) {
    assert(pcb);
    // Do teardown
    tcp_arg(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
}

static void _release_pcb(tcp_pcb** pcb_ptr) {
    if (!pcb_ptr) return;
    if (*pcb_ptr) {
        // do the close thing
        // TODO
    }
    delete pcb_ptr;
}

// Register a PCB in our list of active PCBs.
// Returns the slot number of the newly registered entry.
static std::shared_ptr<tcp_pcb*> _register_pcb(tcp_pcb* pcb, void* arg){
    // do setup
    tcp_arg(pcb, arg);
    tcp_recv(pcb, &_tcp_recv);
    tcp_sent(pcb, &_tcp_sent);
    tcp_err(pcb, &_tcp_error);
    tcp_poll(pcb, &_tcp_poll, 1);
    
    return std::shared_ptr<tcp_pcb*>(new tcp_pcb*(pcb), _release_pcb);
}

static inline bool _init_async_event_queue(){
    if(!_async_queue){
        _async_queue = xQueueCreate(CONFIG_ASYNC_TCP_EVENT_QUEUE_SIZE, sizeof(lwip_event_packet_t *));
        if(!_async_queue){
            return false;
        }
    }
    return true;
}

static inline bool _send_async_event(lwip_event_packet_t ** e){
    return _async_queue && xQueueSend(_async_queue, e, portMAX_DELAY) == pdPASS;
}

static inline bool _prepend_async_event(lwip_event_packet_t ** e){
    return _async_queue && xQueueSendToFront(_async_queue, e, portMAX_DELAY) == pdPASS;
}

static inline bool _get_async_event(lwip_event_packet_t ** e){
    return _async_queue && xQueueReceive(_async_queue, e, portMAX_DELAY) == pdPASS;
}

static void _remove_event(lwip_event_packet_t* evpkt) {
    // used by below to free packets
    if ((evpkt->event == LWIP_TCP_RECV) && (evpkt->recv.pcb != nullptr)) {
        // We must free the packet buffer
        pbuf_free(evpkt->recv.pb);
    }
    free(evpkt);
}

static bool _remove_events_with_arg(void * arg){
    lwip_event_packet_t * first_packet = NULL;
    lwip_event_packet_t * packet = NULL;

    if(!_async_queue){
        return false;
    }
    //figure out which is the first packet so we can keep the order
    while(!first_packet){
        if(xQueueReceive(_async_queue, &first_packet, 0) != pdPASS){
            return false;
        }
        //discard packet if matching
        if((int)first_packet->arg == (int)arg){
            _remove_event(first_packet);
            first_packet = NULL;
        //return first packet to the back of the queue
        } else if(xQueueSend(_async_queue, &first_packet, portMAX_DELAY) != pdPASS){
            // couldn't requeue packet, free it before returning
            _remove_event(first_packet);
            return false;
        }
    }

    while(xQueuePeek(_async_queue, &packet, 0) == pdPASS && packet != first_packet){
        if(xQueueReceive(_async_queue, &packet, 0) != pdPASS){
            return false;
        }
        if((int)packet->arg == (int)arg){
            _remove_event(packet);
            packet = NULL;
        } else if(xQueueSend(_async_queue, &packet, portMAX_DELAY) != pdPASS){
            // couldn't requeue packet, free it before returning
            _remove_event(packet);
            return false;
        }
    }
    return true;
}

static void _handle_async_event(lwip_event_packet_t * e){
    if(e->arg == NULL){
        // do nothing when arg is NULL
        DEBUG_PRINTF("event arg == NULL: 0x%08x\n", e->recv.pcb);
    } else if(e->event == LWIP_TCP_CLEAR){
        DEBUG_PRINTF("-X: 0x%08x %d\n", e->arg);
        _remove_events_with_arg(e->arg);
    } else if(e->event == LWIP_TCP_RECV){
        DEBUG_PRINTF("-R: 0x%08x\n", e->recv.pcb);
        AsyncClient::_s_recv(e->arg, e->recv.pcb, e->recv.pb, e->recv.err);
    } else if(e->event == LWIP_TCP_FIN){
        DEBUG_PRINTF("-F: 0x%08x\n", e->fin.pcb);
        AsyncClient::_s_fin(e->arg, e->fin.pcb, e->fin.err);
    } else if(e->event == LWIP_TCP_SENT){
        DEBUG_PRINTF("-S: 0x%08x\n", e->sent.pcb);
        AsyncClient::_s_sent(e->arg, e->sent.pcb, e->sent.len);
    } else if(e->event == LWIP_TCP_POLL){
        DEBUG_PRINTF("-P: 0x%08x\n", e->poll.pcb);
        AsyncClient::_s_poll(e->arg, e->poll.pcb);
    } else if(e->event == LWIP_TCP_ERROR){
        DEBUG_PRINTF("-E: 0x%08x %d\n", e->arg, e->error.err);
        AsyncClient::_s_error(e->arg, e->error.err);
    } else if(e->event == LWIP_TCP_CONNECTED){
        DEBUG_PRINTF("C: 0x%08x 0x%08x %d\n", e->arg, e->connected.pcb, e->connected.err);
        AsyncClient::_s_connected(e->arg, e->connected.pcb, e->connected.err);
    } else if(e->event == LWIP_TCP_ACCEPT){
        DEBUG_PRINTF("A: 0x%08x 0x%08x\n", e->arg, e->accept.client);
        AsyncServer::_s_accepted(e->arg, e->accept.client);
    } else if(e->event == LWIP_TCP_DNS){
        DEBUG_PRINTF("D: 0x%08x %s = %s\n", e->arg, e->dns.name, ipaddr_ntoa(&e->dns.addr));
        AsyncClient::_s_dns_found(e->dns.name, &e->dns.addr, e->arg);
    }
    free((void*)(e));
}

static void _async_service_task(void *pvParameters){
    lwip_event_packet_t * packet = NULL;
    for (;;) {
        if(_get_async_event(&packet)){
#if CONFIG_ASYNC_TCP_USE_WDT
            if(esp_task_wdt_add(NULL) != ESP_OK){
                log_e("Failed to add async task to WDT");
            }
#endif
            _handle_async_event(packet);
#if CONFIG_ASYNC_TCP_USE_WDT
            if(esp_task_wdt_delete(NULL) != ESP_OK){
                log_e("Failed to remove loop task from WDT");
            }
#endif
        }
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

static int8_t _tcp_clear_events(void * arg) {
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->event = LWIP_TCP_CLEAR;
        e->arg = arg;
        if (!_prepend_async_event(&e)) {
            free((void*)(e));
        }
    }
    return ERR_OK;
}

static int8_t _tcp_connected(void * arg, tcp_pcb * pcb, int8_t err) {
    DEBUG_PRINTF("+C: 0x%08x\n", pcb);
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->event = LWIP_TCP_CONNECTED;
        e->arg = arg;
        e->connected.pcb = pcb;
        e->connected.err = err;
        if (!_prepend_async_event(&e)) {
            // WM: pcb is now leaked .. !
            free((void*)(e));
        }
    }
    return ERR_OK;
}

static int8_t _tcp_poll(void * arg, struct tcp_pcb * pcb) {
    DEBUG_PRINTF("+P: 0x%08x\n", pcb);
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->event = LWIP_TCP_POLL;
        e->arg = arg;
        e->poll.pcb = pcb;
        if (!_send_async_event(&e)) {
            free((void*)(e));
        }
    }
    return ERR_OK;
}

static int8_t _tcp_recv(void * arg, struct tcp_pcb * pcb, struct pbuf *pb, int8_t err) {
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->arg = arg;
        if(pb){
            DEBUG_PRINTF("+R: 0x%08x\n", pcb);
            e->event = LWIP_TCP_RECV;
            e->recv.pcb = pcb;
            e->recv.pb = pb;
            e->recv.err = err;
        } else {
            DEBUG_PRINTF("+F: 0x%08x -> 0x%08x\n", pcb, arg);
            e->event = LWIP_TCP_FIN;
            e->fin.pcb = pcb;
            e->fin.err = err;
        }
        if (!_send_async_event(&e)) {
            free((void*)(e));
        }
    }
    return ERR_OK;
}

static int8_t _tcp_sent(void * arg, struct tcp_pcb * pcb, uint16_t len) {
    DEBUG_PRINTF("+S: 0x%08x\n", pcb);
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->event = LWIP_TCP_SENT;
        e->arg = arg;
        e->sent.pcb = pcb;
        e->sent.len = len;
        if (!_send_async_event(&e)) {
            free((void*)(e));
        }
    }
    return ERR_OK;
}

static void _tcp_error(void * arg, int8_t err) {
    DEBUG_PRINTF("+E: 0x%08x\n", arg);
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->event = LWIP_TCP_ERROR;
        e->arg = arg;
        e->error.err = err;
        if (!_prepend_async_event(&e)) {    // pcb is now invalid
            free((void*)(e));
        }
    }
}

static void _tcp_dns_found(const char * name, struct ip_addr * ipaddr, void * arg) {
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    DEBUG_PRINTF("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
    if (NULL != e) {
        e->event = LWIP_TCP_DNS;
        e->arg = arg;
        e->dns.name = name;
        if (ipaddr) {
            memcpy(&e->dns.addr, ipaddr, sizeof(struct ip_addr));
        } else {
            memset(&e->dns.addr, 0, sizeof(e->dns.addr));
        }
        if (!_send_async_event(&e)) {
            free((void*)(e));
        }
    }
}

//Used to switch out from LwIP thread
static int8_t _tcp_accept(void * arg, AsyncClient * client) {
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if (NULL != e) {
        e->event = LWIP_TCP_ACCEPT;
        e->arg = arg;
        e->accept.client = client;
        if (!_prepend_async_event(&e)) {
            free((void*)(e));
        }
    }
    return ERR_OK;
}

/*
 * TCP/IP API Calls
 * */

#include "lwip/priv/tcpip_priv.h"

typedef struct {
    struct tcpip_api_call_data call;
    std::shared_ptr<tcp_pcb*> pcb;
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
    return is_valid(p.pcb);
}

static err_t _tcp_output_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        msg->err = tcp_output(*msg->pcb);
    }
    return msg->err;
}

static esp_err_t _tcp_output(const std::shared_ptr<tcp_pcb*>& pcb_ref) {
    if(!is_valid(pcb_ref)){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb = pcb_ref;
    tcpip_api_call(_tcp_output_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_write_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        msg->err = tcp_write(*msg->pcb, msg->write.data, msg->write.size, msg->write.apiflags);
    }
    return msg->err;
}

static esp_err_t _tcp_write(const std::shared_ptr<tcp_pcb*>& pcb_ref, const char* data, size_t size, uint8_t apiflags) {
    if(!is_valid(pcb_ref)){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb = pcb_ref;
    msg.write.data = data;
    msg.write.size = size;
    msg.write.apiflags = apiflags;
    tcpip_api_call(_tcp_write_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        msg->err = 0;
        tcp_recved(*msg->pcb, msg->received);
    }
    return msg->err;
}

static esp_err_t _tcp_recved(const std::shared_ptr<tcp_pcb*>& pcb_ref, size_t len) {
    if(!is_valid(pcb_ref)){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb = pcb_ref;
    msg.received = len;
    tcpip_api_call(_tcp_recved_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

// Frees the specified close slot, too.
static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {        
        _teardown_pcb(*msg->pcb);
        msg->err = tcp_close(*msg->pcb);
        if (msg->err == ERR_OK) {
            // pcb will be freed by stack shortly
            *msg->pcb = nullptr;
        }
    }
    return msg->err;
}

static esp_err_t _tcp_close(const std::shared_ptr<tcp_pcb*>& pcb_ref) {
    if(!is_valid(pcb_ref)){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb = pcb_ref;
    tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ERR_CONN;
    if(pcb_is_active(*msg)) {
        _teardown_pcb(*msg->pcb);
        tcp_abort(*msg->pcb);
        *msg->pcb = nullptr; // pcb will be freed by stack shortly
    }
    return msg->err;
}

static esp_err_t _tcp_abort(const std::shared_ptr<tcp_pcb*>& pcb_ref) {
    if(!is_valid(pcb_ref)){
        return ERR_CONN;
    }
    tcp_api_call_t msg;
    msg.pcb = pcb_ref;
    tcpip_api_call(_tcp_abort_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    if (is_valid(msg->pcb)) {
        msg->err = tcp_connect(*msg->pcb, msg->connect.addr, msg->connect.port, msg->connect.cb);
    } else {
        msg->err = ESP_FAIL;
    }
    return msg->err;
}

static esp_err_t _tcp_connect(const std::shared_ptr<tcp_pcb*>& pcb_ref, ip_addr_t * addr, uint16_t port, tcp_connected_fn cb) {
    if(!is_valid(pcb_ref)){
        return ESP_FAIL;
    }
    tcp_api_call_t msg;
    msg.pcb = pcb_ref;
    msg.connect.addr = addr;
    msg.connect.port = port;
    msg.connect.cb = cb;
    tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_bind_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = ESP_FAIL;
    if(pcb_is_active(*msg)) {
        msg->err = tcp_bind(*msg->pcb, msg->bind.addr, msg->bind.port);
    }
    return msg->err;
}

static esp_err_t _tcp_bind(tcp_pcb* pcb, ip_addr_t * addr, uint16_t port) {
    if(!pcb){
        return ESP_FAIL;
    }
    tcp_api_call_t msg;
    msg.pcb = std::make_shared<tcp_pcb*>(pcb);
    msg.bind.addr = addr;
    msg.bind.port = port;
    tcpip_api_call(_tcp_bind_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _tcp_listen_api(struct tcpip_api_call_data *api_call_msg){
    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;
    msg->err = 0;
    *msg->pcb = tcp_listen_with_backlog(*msg->pcb, msg->backlog);
    return msg->err;
}

static tcp_pcb * _tcp_listen_with_backlog(tcp_pcb* pcb, uint8_t backlog) {
    if(!pcb) {
        return NULL;
    }
    tcp_api_call_t msg;
    msg.pcb = std::make_shared<tcp_pcb*>(pcb);
    msg.backlog = backlog?backlog:0xFF;
    tcpip_api_call(_tcp_listen_api, (struct tcpip_api_call_data*)&msg);
    return *msg.pcb;
}



/*
  Async TCP Client
 */

AsyncClient::AsyncClient(tcp_pcb* pcb)
: _connect_cb(0)
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
    if(pcb){
        _pcb_ref = _register_pcb(pcb, this);
        _rx_last_packet = millis();
    }
    DEBUG_PRINTF("+AC: 0x%08x -> 0x%08x\n", _pcb, (intptr_t)this);
}

AsyncClient::~AsyncClient(){
    DEBUG_PRINTF("-AC: 0x%08x -> 0x%08x\n", _pcb, (intptr_t)this);
}

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) {
    return _pcb_ref == other._pcb_ref;
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
    if (is_valid(_pcb_ref)) {
        log_w("already connected, state %d", *_pcb_ref->state);
        return false;
    }
    if(!_start_async_task()){
        log_e("failed to start task");
        return false;
    }

    ip_addr_t addr;
    addr.type = IPADDR_TYPE_V4;
    addr.u_addr.ip4.addr = ip;

    tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!pcb){
        log_e("pcb == NULL");
        return false;
    }
    _pcb_ref = _register_pcb(pcb, this);

    //_tcp_connect(pcb, &addr, port,(tcp_connected_fn)&_s_connected);
    if (ESP_OK != _tcp_connect(_pcb_ref, &addr, port,(tcp_connected_fn)&_tcp_connected)){
        _pcb_ref.reset();   // release allocation
        return false;
    }
    return true;
}

bool AsyncClient::connect(const char* host, uint16_t port){
    ip_addr_t addr;
    
    if(!_start_async_task()){
      log_e("failed to start task");
      return false;
    }
    
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
    if(is_valid(_pcb_ref)){
        _tcp_recved(_pcb_ref, _rx_ack_len);
    }
    _close();
}

int8_t AsyncClient::abort(){
    if(is_valid(_pcb_ref)) {
        _tcp_abort(_pcb_ref);
    }
    return ERR_ABRT;
}

size_t AsyncClient::space(){
    if(is_valid(_pcb_ref) && ((*_pcb_ref)->state == 4)){
        return tcp_sndbuf(*_pcb_ref);
    }
    return 0;
}

size_t AsyncClient::add(const char* data, size_t size, uint8_t apiflags) {
    if(!is_valid(_pcb_ref) || size == 0 || data == NULL) {
        return 0;
    }
    size_t room = space();
    if(!room) {
        return 0;
    }
    size_t will_send = (room < size) ? room : size;
    int8_t err = ERR_OK;
    err = _tcp_write(_pcb_ref, data, will_send, apiflags);
    if(err != ERR_OK) {
        return 0;
    }
    return will_send;
}

bool AsyncClient::send(){
    auto backup = _tx_last_packet;
    _tx_last_packet = millis();
    if (_tcp_output(_pcb_ref) == ERR_OK) {
        return true;
    }
    _tx_last_packet = backup;
    return false;
}

size_t AsyncClient::ack(size_t len){
    if(len > _rx_ack_len)
        len = _rx_ack_len;
    if(len) {
        _tcp_recved(_pcb_ref, len);
    }
    _rx_ack_len -= len;
    return len;
}

void AsyncClient::ackPacket(struct pbuf * pb){
  if(!pb){
    return;
  }
  _tcp_recved(_pcb_ref, pb->len);
  pbuf_free(pb);
}

/*
 * Main Private Methods
 * */

int8_t AsyncClient::_close(){
    DEBUG_PRINTF("close: 0x%08x\n", (uint32_t)this);
    int8_t err = ERR_OK;
    if(is_valid(_pcb_ref)) {
        //log_i("");        
        err = _tcp_close(_pcb_ref);
        _tcp_clear_events(this);
        if(err != ERR_OK) {
            err = abort();
        }
        _pcb_ref.reset();
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

int8_t AsyncClient::_connected(void* pcb, int8_t err){    
    if(pcb){
        assert(pcb == *_pcb_ref);
        _rx_last_packet = millis();
    }
    if(_connect_cb) {
        _connect_cb(_connect_cb_arg, this);
    }
    return ERR_OK;
}

void AsyncClient::_error(int8_t err) {
    if(is_valid(_pcb_ref)){
        // The pcb has already been deallocated by the lwip stack and is no longer valid
        *_pcb_ref = nullptr;        
    }
    _tcp_clear_events(this);
    if(_error_cb) {
        _error_cb(_error_cb_arg, this, err);
    }
    if(_discard_cb) {
        _discard_cb(_discard_cb_arg, this);
    }
}

//In Async Thread
int8_t AsyncClient::_fin(tcp_pcb* pcb, int8_t err) {
    // WM: This isn't strictly correct - the client is permitted to continue sending
    // Behaviour is carried forward for now
    _close();
    return ERR_OK;
}

int8_t AsyncClient::_sent(tcp_pcb* pcb, uint16_t len) {
    _rx_last_packet = _rx_last_ack = millis();
    //log_i("%u", len);
    if(_sent_cb) {
        _sent_cb(_sent_cb_arg, this, len, (_rx_last_packet - _tx_last_packet));
    }
    return ERR_OK;
}

int8_t AsyncClient::_recv(tcp_pcb* pcb, pbuf* pb, int8_t err) {
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
            } else if(is_valid(_pcb_ref)) {
                _tcp_recved(_pcb_ref, b->len);
            }
            pbuf_free(b);
        }
    }
    return ERR_OK;
}

int8_t AsyncClient::_poll(tcp_pcb* pcb){
    if(!is_valid(_pcb_ref)){
        log_w("pcb is NULL");
        return ERR_OK;
    }
    if(pcb != *_pcb_ref){
        // something has gone horribly wrong
        log_e("0x%08x != 0x%08x", (uint32_t)pcb, (uint32_t)*pcb_ref);
        return ERR_OK;
    }

    uint32_t now = millis();

    // ACK Timeout
    if(_ack_timeout){
        const uint32_t one_day = 86400000;
        bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
        if(last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
            log_w("ack timeout %d", pcb->state);
            if(_timeout_cb)
                _timeout_cb(_timeout_cb_arg, this, (now - _tx_last_packet));
            return ERR_OK;
        }
    }
    // RX Timeout
    if(_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
        log_w("rx timeout %d", pcb->state);
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
    if(!is_valid(_pcb_ref)) {
        return true;
    }
    if((*_pcb_ref)->state == 0 || (*_pcb_ref)->state > 4) {
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
    if(!is_valid(_pcb_ref)) {
        return;
    }
    if(nodelay) {
        tcp_nagle_disable((*_pcb_ref));
    } else {
        tcp_nagle_enable((*_pcb_ref));
    }
}

bool AsyncClient::getNoDelay(){
    if(!is_valid(_pcb_ref)) {
        return false;
    }
    return tcp_nagle_disabled((*_pcb_ref));
}

uint16_t AsyncClient::getMss(){
    if(!is_valid(_pcb_ref)) {
        return 0;
    }
    return tcp_mss((*_pcb_ref));
}

uint32_t AsyncClient::getRemoteAddress() {
    if(!is_valid(_pcb_ref)) {
        return 0;
    }
    return (*_pcb_ref)->remote_ip.u_addr.ip4.addr;
}

uint16_t AsyncClient::getRemotePort() {
    if(!is_valid(_pcb_ref)) {
        return 0;
    }
    return (*_pcb_ref)->remote_port;
}

uint32_t AsyncClient::getLocalAddress() {
    if(!is_valid(_pcb_ref)) {
        return 0;
    }
    return (*_pcb_ref)->local_ip.u_addr.ip4.addr;
}

uint16_t AsyncClient::getLocalPort() {
    if(!is_valid(_pcb_ref)) {
        return 0;
    }
    return (*_pcb_ref)->local_port;
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
    if(!is_valid(_pcb_ref)) {
        return 0;
    }
    return (*_pcb_ref)->state;
}

bool AsyncClient::connected(){
    if (!is_valid(_pcb_ref)) {
        return false;
    }
    return (*_pcb_ref)->state == 4;
}

bool AsyncClient::connecting(){
    if (!is_valid(_pcb_ref)) {
        return false;
    }
    return (*_pcb_ref)->state > 0 && (*_pcb_ref)->state < 4;
}

bool AsyncClient::disconnecting(){
    if (!is_valid(_pcb_ref)) {
        return false;
    }
    return (*_pcb_ref)->state > 4 && (*_pcb_ref)->state < 10;
}

bool AsyncClient::disconnected(){
    if (!is_valid(_pcb_ref)) {
        return true;
    }
    return (*_pcb_ref)->state == 0 || (*_pcb_ref)->state == 10;
}

bool AsyncClient::freeable(){
    if (!is_valid(_pcb_ref)) {
        return true;
    }
    return (*_pcb_ref)->state == 0 || (*_pcb_ref)->state > 4;
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
 * Static Callbacks (LwIP C2C++ interconnect)
 * */

void AsyncClient::_s_dns_found(const char * name, struct ip_addr * ipaddr, void * arg){
    reinterpret_cast<AsyncClient*>(arg)->_dns_found(ipaddr);
}

int8_t AsyncClient::_s_poll(void * arg, struct tcp_pcb * pcb) {
    return reinterpret_cast<AsyncClient*>(arg)->_poll(pcb);
}

int8_t AsyncClient::_s_recv(void * arg, struct tcp_pcb * pcb, struct pbuf *pb, int8_t err) {
    return reinterpret_cast<AsyncClient*>(arg)->_recv(pcb, pb, err);
}

int8_t AsyncClient::_s_fin(void * arg, struct tcp_pcb * pcb, int8_t err) {
    return reinterpret_cast<AsyncClient*>(arg)->_fin(pcb, err);
}

int8_t AsyncClient::_s_sent(void * arg, struct tcp_pcb * pcb, uint16_t len) {
    return reinterpret_cast<AsyncClient*>(arg)->_sent(pcb, len);
}

void AsyncClient::_s_error(void * arg, int8_t err) {
    reinterpret_cast<AsyncClient*>(arg)->_error(err);
}

int8_t AsyncClient::_s_connected(void * arg, void * pcb, int8_t err){
    return reinterpret_cast<AsyncClient*>(arg)->_connected(pcb, err);
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
    if (_pcb == NULL){
        log_e("_pcb == NULL");
        return;
    }

    ip_addr_t local_addr;
    local_addr.type = IPADDR_TYPE_V4;
    local_addr.u_addr.ip4.addr = (uint32_t) _addr;
    err = _tcp_bind(_pcb, &local_addr, _port);

    if (err != ERR_OK) {
        _tcp_close(std::make_shared<tcp_pcb*>(_pcb));
        log_e("bind error: %d", err);
        return;
    }

    tcp_arg(_pcb, (void*) this);
    tcp_accept(_pcb, &_s_accept);

    static uint8_t backlog = 5;
    _pcb = _tcp_listen_with_backlog(_pcb, backlog);
    if (_pcb == NULL) {
        log_e("listen_pcb == NULL");
        return;
    }
}

void AsyncServer::end(){
    if(_pcb){
        tcp_arg(_pcb, NULL);
        tcp_accept(_pcb, NULL);        
        std::shared_ptr<tcp_pcb*> spcb = std::make_shared<tcp_pcb*>(_pcb);
        if(_tcp_close(spcb) != ERR_OK){
            _tcp_abort(spcb);
        }
        _pcb = NULL;
    }
}

//runs on LwIP thread
int8_t AsyncServer::_accept(tcp_pcb* pcb, int8_t err){
    DEBUG_PRINTF("+A: 0x%08x %d\n", pcb, err);    
    if (pcb) {
        if(_connect_cb){
            AsyncClient *c = new AsyncClient(pcb);
            if(c){
                c->setNoDelay(_noDelay);
                return _tcp_accept(this, c);
            }
        }        
        if(tcp_close(pcb) != ERR_OK){
            tcp_abort(pcb);
        }
    }
    log_e("FAIL");
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
