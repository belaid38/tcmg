#ifndef TCMG_LEGACY_SH4_STDATOMIC_H_
#define TCMG_LEGACY_SH4_STDATOMIC_H_

#include <stdint.h>
#include <stddef.h>


typedef enum {
    memory_order_relaxed = 0,
    memory_order_consume = 1,
    memory_order_acquire = 2,
    memory_order_release = 3,
    memory_order_acq_rel = 4,
    memory_order_seq_cst = 5
} memory_order;

typedef volatile int atomic_int;
typedef volatile unsigned int atomic_uint;
typedef volatile long atomic_long;
typedef volatile unsigned long atomic_ulong;
typedef volatile int8_t atomic_int8_t;
typedef volatile uint8_t atomic_uint8_t;
typedef volatile int16_t atomic_int16_t;
typedef volatile uint16_t atomic_uint16_t;
typedef volatile int32_t atomic_int32_t;
typedef volatile uint32_t atomic_uint32_t;
typedef volatile int64_t atomic_int64_t;
typedef volatile uint64_t atomic_uint64_t;

#ifndef _Atomic
#define _Atomic volatile
#endif

extern volatile int32_t tcmg_legacy_atomic64_lock;

static inline void tcmg_legacy_atomic64_lock_acquire(void)
{
    while (__sync_lock_test_and_set(&tcmg_legacy_atomic64_lock, 1)) {
    }
    __sync_synchronize();
}

static inline void tcmg_legacy_atomic64_lock_release(void)
{
    __sync_synchronize();
    __sync_lock_release(&tcmg_legacy_atomic64_lock);
}

static inline uint64_t tcmg_legacy_atomic_load(const volatile void *ptr, size_t size)
{
    if (size == 8) {
        uint64_t v;
        tcmg_legacy_atomic64_lock_acquire();
        v = *(const volatile uint64_t *)ptr;
        tcmg_legacy_atomic64_lock_release();
        return v;
    }
    __sync_synchronize();
    if (size == 4)
        return (uint64_t)__sync_add_and_fetch((volatile uint32_t *)ptr, 0);
    if (size == 2)
        return (uint64_t)__sync_add_and_fetch((volatile uint16_t *)ptr, 0);
    if (size == 1)
        return (uint64_t)__sync_add_and_fetch((volatile uint8_t *)ptr, 0);
    return 0;
}

static inline void tcmg_legacy_atomic_store(volatile void *ptr, size_t size, uint64_t value)
{
    if (size == 8) {
        tcmg_legacy_atomic64_lock_acquire();
        *(volatile uint64_t *)ptr = value;
        tcmg_legacy_atomic64_lock_release();
        return;
    }
    if (size == 4)
        (void)__sync_lock_test_and_set((volatile uint32_t *)ptr, (uint32_t)value);
    else if (size == 2)
        (void)__sync_lock_test_and_set((volatile uint16_t *)ptr, (uint16_t)value);
    else if (size == 1)
        (void)__sync_lock_test_and_set((volatile uint8_t *)ptr, (uint8_t)value);
    __sync_synchronize();
}

static inline uint64_t tcmg_legacy_atomic_exchange(volatile void *ptr, size_t size, uint64_t value)
{
    uint64_t old;
    if (size == 8) {
        tcmg_legacy_atomic64_lock_acquire();
        old = *(volatile uint64_t *)ptr;
        *(volatile uint64_t *)ptr = value;
        tcmg_legacy_atomic64_lock_release();
        return old;
    }
    if (size == 4)
        return (uint64_t)__sync_lock_test_and_set((volatile uint32_t *)ptr, (uint32_t)value);
    if (size == 2)
        return (uint64_t)__sync_lock_test_and_set((volatile uint16_t *)ptr, (uint16_t)value);
    if (size == 1)
        return (uint64_t)__sync_lock_test_and_set((volatile uint8_t *)ptr, (uint8_t)value);
    return 0;
}

static inline uint64_t tcmg_legacy_atomic_fetch_add(volatile void *ptr, size_t size, uint64_t value)
{
    if (size == 8) {
        uint64_t old;
        tcmg_legacy_atomic64_lock_acquire();
        old = *(volatile uint64_t *)ptr;
        *(volatile uint64_t *)ptr = old + value;
        tcmg_legacy_atomic64_lock_release();
        return old;
    }
    if (size == 4)
        return (uint64_t)__sync_fetch_and_add((volatile uint32_t *)ptr, (uint32_t)value);
    if (size == 2)
        return (uint64_t)__sync_fetch_and_add((volatile uint16_t *)ptr, (uint16_t)value);
    if (size == 1)
        return (uint64_t)__sync_fetch_and_add((volatile uint8_t *)ptr, (uint8_t)value);
    return 0;
}

static inline uint64_t tcmg_legacy_atomic_fetch_sub(volatile void *ptr, size_t size, uint64_t value)
{
    if (size == 8) {
        uint64_t old;
        tcmg_legacy_atomic64_lock_acquire();
        old = *(volatile uint64_t *)ptr;
        *(volatile uint64_t *)ptr = old - value;
        tcmg_legacy_atomic64_lock_release();
        return old;
    }
    if (size == 4)
        return (uint64_t)__sync_fetch_and_sub((volatile uint32_t *)ptr, (uint32_t)value);
    if (size == 2)
        return (uint64_t)__sync_fetch_and_sub((volatile uint16_t *)ptr, (uint16_t)value);
    if (size == 1)
        return (uint64_t)__sync_fetch_and_sub((volatile uint8_t *)ptr, (uint8_t)value);
    return 0;
}

#define atomic_init(ptr, value) \
    tcmg_legacy_atomic_store((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_load(ptr) \
    tcmg_legacy_atomic_load((const volatile void *)(ptr), sizeof(*(ptr)))
#define atomic_load_explicit(ptr, order) \
    tcmg_legacy_atomic_load((const volatile void *)(ptr), sizeof(*(ptr)))
#define atomic_store(ptr, value) \
    tcmg_legacy_atomic_store((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_store_explicit(ptr, value, order) \
    tcmg_legacy_atomic_store((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_exchange(ptr, value) \
    tcmg_legacy_atomic_exchange((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_exchange_explicit(ptr, value, order) \
    tcmg_legacy_atomic_exchange((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_fetch_add(ptr, value) \
    tcmg_legacy_atomic_fetch_add((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_fetch_add_explicit(ptr, value, order) \
    tcmg_legacy_atomic_fetch_add((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_fetch_sub(ptr, value) \
    tcmg_legacy_atomic_fetch_sub((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))
#define atomic_fetch_sub_explicit(ptr, value, order) \
    tcmg_legacy_atomic_fetch_sub((volatile void *)(ptr), sizeof(*(ptr)), (uint64_t)(value))

#endif
