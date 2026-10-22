#include <openssl/crypto.h>
#include <psp2/kernel/threadmgr/lw_mutex.h>
#include <stdlib.h>

/* VitaSDK's pthread rwlock uses several kernel semaphores per OpenSSL lock, and a full CA
 * bundle runs out of them
 * So reads and writes share one lightweight native mutex instead
 * OpenSSL's lock type is opaque, so every lock function must go through this adapter */
typedef struct CryptoLock {
    SceKernelLwMutexWork work;
} CryptoLock;

CRYPTO_RWLOCK *__wrap_CRYPTO_THREAD_lock_new(void) {
    CryptoLock *lock = calloc(1, sizeof(*lock));
    if (lock == NULL) return NULL;
    if (sceKernelCreateLwMutex(&lock->work, "vitals crypto",
            SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL) < 0) {
        free(lock);
        return NULL;
    }
    return (CRYPTO_RWLOCK *)lock;
}

int __wrap_CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *opaque) {
    CryptoLock *lock = (CryptoLock *)opaque;
    return lock != NULL && sceKernelLockLwMutex(&lock->work, 1, NULL) >= 0;
}

int __wrap_CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *opaque) {
    return __wrap_CRYPTO_THREAD_read_lock(opaque);
}

int __wrap_CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *opaque) {
    CryptoLock *lock = (CryptoLock *)opaque;
    return lock != NULL && sceKernelUnlockLwMutex(&lock->work, 1) >= 0;
}

void __wrap_CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *opaque) {
    CryptoLock *lock = (CryptoLock *)opaque;
    if (lock == NULL) return;
    /* Retain native work storage if a live mutex cannot be deleted */
    if (sceKernelDeleteLwMutex(&lock->work) >= 0) free(lock);
}

int __wrap_CRYPTO_atomic_add(int *value, int amount, int *result, CRYPTO_RWLOCK *lock) {
    (void)lock;
    if (value == NULL || result == NULL) return 0;
    *result = __atomic_add_fetch(value, amount, __ATOMIC_SEQ_CST);
    return 1;
}
