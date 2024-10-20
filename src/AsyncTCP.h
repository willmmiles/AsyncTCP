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

#ifndef ASYNCTCP_H_
#define ASYNCTCP_H_

#include "IPAddress.h"
#include "sdkconfig.h"
#include <functional>
extern "C" {
    #include "freertos/semphr.h"
    #include "lwip/pbuf.h"
}


//CONFIG_ASYNC_TCP_DIAGNOSTICS
//#define CONFIG_ASYNC_TCP_DIAGNOSTICS 1

//If core is not defined, then we are running in Arduino or PIO
#ifndef CONFIG_ASYNC_TCP_RUNNING_CORE
#define CONFIG_ASYNC_TCP_RUNNING_CORE -1 //any available core
#endif

//Watchdog Timer is not dependent on the running core
#ifndef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 1 //if enabled, adds between 33us and 200us per event
#endif

//the number of words (esp32 1 word = 4 bytes) of stack space to allocate
#ifndef CONFIG_ASYNC_TCP_TASK_STACK_SIZE
#define CONFIG_ASYNC_TCP_TASK_STACK_SIZE (8192)
#endif

#ifndef CONFIG_ASYNC_TCP_TASK_PRIORITY
#define CONFIG_ASYNC_TCP_TASK_PRIORITY 3
#endif


class AsyncClient;

#define ASYNC_MAX_ACK_TIME 5000
#define ASYNC_WRITE_FLAG_COPY 0x01 //will allocate new buffer to hold the data while sending (else will hold reference to the data given)
#define ASYNC_WRITE_FLAG_MORE 0x02 //will not send PSH flag, meaning that there should be more data to be sent before the application should react.

typedef std::function<void(void*, AsyncClient*)> AcConnectHandler;
typedef std::function<void(void*, AsyncClient*, size_t len, uint32_t time)> AcAckHandler;
typedef std::function<void(void*, AsyncClient*, int8_t error)> AcErrorHandler;
typedef std::function<void(void*, AsyncClient*, void *data, size_t len)> AcDataHandler;
typedef std::function<void(void*, AsyncClient*, struct pbuf *pb)> AcPacketHandler;
typedef std::function<void(void*, AsyncClient*, uint32_t time)> AcTimeoutHandler;

struct tcp_pcb;
struct ip_addr;
class AsyncClient_detail;
struct AsyncClient_event_t;

class AsyncClient {
  public:
    AsyncClient(tcp_pcb* pcb = 0);
    ~AsyncClient();

    // Not copyable
    AsyncClient(const AsyncClient&) = delete;
    AsyncClient& operator=(const AsyncClient &other) = delete;
    // Not movable, either
    AsyncClient(AsyncClient&&) = delete;
    AsyncClient& operator=(AsyncClient &&other) = delete;


    bool operator==(const AsyncClient &other);
    bool operator!=(const AsyncClient &other) {
      return !(*this == other);
    }
    bool connect(IPAddress ip, uint16_t port);
    bool connect(const char* host, uint16_t port);
    void close(bool now = false);
    void stop();
    int8_t abort();
    bool free();

    bool canSend();//ack is not pending
    size_t space();//space available in the TCP window
    size_t add(const char* data, size_t size, uint8_t apiflags=ASYNC_WRITE_FLAG_COPY);//add for sending
    bool send();//send all data added with the method above

    //write equals add()+send()
    size_t write(const char* data);
    size_t write(const char* data, size_t size, uint8_t apiflags=ASYNC_WRITE_FLAG_COPY); //only when canSend() == true

    uint8_t state();
    bool connecting();
    bool connected();
    bool disconnecting();
    bool disconnected();
    bool freeable();//disconnected or disconnecting

    uint16_t getMss();

    uint32_t getRxTimeout();
    void setRxTimeout(uint32_t timeout);//no RX data timeout for the connection in seconds

    uint32_t getAckTimeout();
    void setAckTimeout(uint32_t timeout);//no ACK timeout for the last sent packet in milliseconds

    void setNoDelay(bool nodelay);
    bool getNoDelay();

    uint32_t getRemoteAddress();
    uint16_t getRemotePort();
    uint32_t getLocalAddress();
    uint16_t getLocalPort();

    //compatibility
    IPAddress remoteIP();
    uint16_t  remotePort();
    IPAddress localIP();
    uint16_t  localPort();

    void onConnect(AcConnectHandler cb, void* arg = 0);     //on successful connect
    void onDisconnect(AcConnectHandler cb, void* arg = 0);  //disconnected
    void onAck(AcAckHandler cb, void* arg = 0);             //ack received
    void onError(AcErrorHandler cb, void* arg = 0);         //unsuccessful connect or error
    void onData(AcDataHandler cb, void* arg = 0);           //data received (called if onPacket is not used)
    void onPacket(AcPacketHandler cb, void* arg = 0);       //data received
    void onTimeout(AcTimeoutHandler cb, void* arg = 0);     //ack timeout
    void onPoll(AcConnectHandler cb, void* arg = 0);        //every 125ms when connected

    void ackPacket(struct pbuf * pb);//ack pbuf from onPacket
    size_t ack(size_t len); //ack data that you have not acked using the method below
    void ackLater(){ _ack_pcb = false; } //will not ack the current packet. Call from onData

    const char * errorToString(int8_t error);
    const char * stateToString();
  
    #if CONFIG_ASYNC_TCP_DIAGNOSTICS
    // Gets the async_tcp task's minimum amount of remaining stack space that was 
    // available to the task since the task started executing - - that is the amount
    // of stack that remained unused when the task stack was at its greatest (deepest)
    // value. This is what is referred to as the stack 'high water mark'.
    // See https://www.freertos.org/uxTaskGetStackHighWaterMark.html
    static UBaseType_t getStackHighWaterMark();
    #endif

    tcp_pcb * pcb(){ return _pcb; }

  protected:
    tcp_pcb* _pcb;
    AsyncClient_event_t* _end_event;

    AcConnectHandler _connect_cb;
    void* _connect_cb_arg;
    AcConnectHandler _discard_cb;
    void* _discard_cb_arg;
    AcAckHandler _sent_cb;
    void* _sent_cb_arg;
    AcErrorHandler _error_cb;
    void* _error_cb_arg;
    AcDataHandler _recv_cb;
    void* _recv_cb_arg;
    AcPacketHandler _pb_cb;
    void* _pb_cb_arg;
    AcTimeoutHandler _timeout_cb;
    void* _timeout_cb_arg;
    AcConnectHandler _poll_cb;
    void* _poll_cb_arg;

    bool _ack_pcb;
    uint32_t _tx_last_packet;
    uint32_t _rx_ack_len;
    uint32_t _rx_last_packet;
    uint32_t _rx_timeout;
    uint32_t _rx_last_ack;
    uint32_t _ack_timeout;
    uint16_t _connect_port;

    friend class AsyncClient_detail;
    int8_t _close();
    int8_t _connected(int8_t err);
    void _error(int8_t err);
    int8_t _poll();
    int8_t _sent(uint16_t len);
    int8_t _fin(int8_t err);
    int8_t _recv(pbuf* pb, int8_t err);
    void _dns_found(struct ip_addr *ipaddr);
    int8_t _recved(size_t len);
};

class AsyncServer {
  public:
    AsyncServer(IPAddress addr, uint16_t port);
    AsyncServer(uint16_t port);
    ~AsyncServer();
    void onClient(AcConnectHandler cb, void* arg);
    void begin();
    void end();
    void setNoDelay(bool nodelay);
    bool getNoDelay();
    uint8_t status();

    //Do not use any of the functions below!
    static int8_t _s_accept(void *arg, tcp_pcb* newpcb, int8_t err);
    static int8_t _s_accepted(void *arg, AsyncClient* client);

  protected:
    uint16_t _port;
    IPAddress _addr;
    bool _noDelay;
    tcp_pcb* _pcb;
    AcConnectHandler _connect_cb;
    void* _connect_cb_arg;

    friend class AsyncClient_detail;
    int8_t _accept(tcp_pcb* newpcb, int8_t err);
    int8_t _accepted(AsyncClient* client);
};


#endif /* ASYNCTCP_H_ */
