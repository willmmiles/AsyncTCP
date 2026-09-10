// Host-native mock of lwip/arch.h -- see test/native/README.md
#ifndef MOCK_LWIP_ARCH_H
#define MOCK_LWIP_ARCH_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uintptr_t mem_ptr_t;

#define LWIP_CONST_CAST(target_type, val) ((target_type)((ptrdiff_t)val))
#define PACK_STRUCT_STRUCT
#define LWIP_UNUSED_ARG(x) (void)x

#endif
