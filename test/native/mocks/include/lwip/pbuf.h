// Host-native mock of lwip/pbuf.h
#ifndef MOCK_LWIP_PBUF_H
#define MOCK_LWIP_PBUF_H

#include "lwip/arch.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PBUF_TRANSPORT,
  PBUF_IP,
  PBUF_LINK,
  PBUF_RAW_TX,
  PBUF_RAW
} pbuf_layer;

typedef enum {
  PBUF_RAM = 0x220,
  PBUF_ROM = 0x001,
  PBUF_REF = 0x041,
  PBUF_POOL = 0x120
} pbuf_type;

struct pbuf {
  struct pbuf *next;
  void *payload;
  u16_t tot_len;
  u16_t len;
  u8_t type_internal;
  u8_t flags;
  u8_t ref;
  u8_t if_idx;
};

struct pbuf *pbuf_alloc(pbuf_layer l, u16_t length, pbuf_type type);
void pbuf_realloc(struct pbuf *p, u16_t size);
u8_t pbuf_free(struct pbuf *p);
void pbuf_ref(struct pbuf *p);
u16_t pbuf_clen(const struct pbuf *p);
void pbuf_cat(struct pbuf *head, struct pbuf *tail);
u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset);

#ifdef __cplusplus
}
#endif

#endif
