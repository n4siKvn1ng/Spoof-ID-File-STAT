#include "spoof_cache.h"
#include <linux/slab.h>
#include <ksyms.h>
#include <kputils.h>

// Function pointers for dynamic resolution
// Some function we can not use despite the includes, so we can dynamically resolve them
static void* (*__kmalloc_fn)(size_t size, gfp_t flags) = NULL;
static void (*kfree_fn)(const void *objp) = NULL;
static unsigned long (*_raw_spin_lock_irqsave_fn)(raw_spinlock_t *lock) = NULL;
static void (*_raw_spin_unlock_irqrestore_fn)(raw_spinlock_t *lock, unsigned long flags) = NULL;

// Cache state
static struct spoof_data *cache_head = NULL;
static spinlock_t cache_lock = __SPIN_LOCK_UNLOCKED();

#define __GFP_ZERO      0x8000u
#define __GFP_ATOMIC    0x80u

static int init_kernel_functions(void) {
    __kmalloc_fn = (void* (*)(size_t, gfp_t))kallsyms_lookup_name("__kmalloc");
    if (!__kmalloc_fn) {
        pr_err("[Obbed] Failed to find __kmalloc\n");
        return -1;
    }

    pr_info("[Obbed] kallsyms(__kmalloc)=%p\n", __kmalloc_fn);

    kfree_fn = (void (*)(const void*))kallsyms_lookup_name("kfree");
    if (!kfree_fn) {
        pr_err("[Obbed] Failed to find kfree\n");
        return -1;
    }

    pr_info("[Obbed] kallsyms(kfree)=%p\n", kfree_fn);

    _raw_spin_lock_irqsave_fn = (unsigned long (*)(raw_spinlock_t*))kallsyms_lookup_name("_raw_spin_lock_irqsave");
    if (!_raw_spin_lock_irqsave_fn) {
        pr_err("[Obbed] Failed to find _raw_spin_lock_irqsave\n");
        return -1;
    }

    pr_info("[Obbed] kallsyms(_raw_spin_lock_irqsave)=%p\n", _raw_spin_lock_irqsave_fn);

    _raw_spin_unlock_irqrestore_fn = (void (*)(raw_spinlock_t*, unsigned long))kallsyms_lookup_name("_raw_spin_unlock_irqrestore");
    if (!_raw_spin_unlock_irqrestore_fn) {
        pr_err("[Obbed] Failed to find _raw_spin_unlock_irqrestore\n");
        return -1;
    }

    pr_info("[Obbed] kallsyms(_raw_spin_unlock_irqrestore)=%p\n", _raw_spin_unlock_irqrestore_fn);

    pr_info("[Obbed] Successfully resolved all required kernel functions\n");
    return 0;
}

void spoof_cache_init(void) {
    cache_head = NULL;
    spin_lock_init(&cache_lock);
    if (init_kernel_functions() != 0) {
        pr_err("[Obbed] Cache initialization failed!\n");
    }
}

void remove_spoof_data(uid_t uid) {
    struct spoof_data *entry, *prev;
    unsigned long flags;

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn || !kfree_fn) {
        pr_err("[Obbed] Required functions not available for removal\n");
        return;
    }

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    
    // Handle case where target is head of list
    if (cache_head && cache_head->uid == uid) {
        entry = cache_head;
        cache_head = cache_head->next;
        kfree_fn(entry);
        _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
        return;
    }

    // Search through rest of list
    prev = cache_head;
    entry = cache_head ? cache_head->next : NULL;
    
    while (entry != NULL) {
        if (entry->uid == uid) {
            prev->next = entry->next;
            kfree_fn(entry);
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
}

struct spoof_data* get_spoof_data(uid_t uid) {
    struct spoof_data *entry, *prev;
    unsigned long flags;

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn || !__kmalloc_fn) {
        pr_err("[Obbed] Required functions not available\n");
        return NULL;
    }

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    
    // ALWAYS remove existing entry for this UID to force fresh random values
    if (cache_head && cache_head->uid == uid) {
        entry = cache_head;
        cache_head = cache_head->next;
        if (kfree_fn) kfree_fn(entry);
    } else {
        prev = cache_head;
        entry = cache_head ? cache_head->next : NULL;
        while (entry != NULL) {
            if (entry->uid == uid) {
                prev->next = entry->next;
                if (kfree_fn) kfree_fn(entry);
                break;
            }
            prev = entry;
            entry = entry->next;
        }
    }

    // Create new entry with fresh random values
    entry = __kmalloc_fn(sizeof(struct spoof_data), __GFP_ATOMIC | __GFP_ZERO);
    if (entry) {
        entry->uid = uid;
        entry->dev_offset = (get_random_u64() % 100);
        entry->inode_offset = (get_random_u64() % 100) + 1;
        entry->days_offset = (get_random_u64() % 30) + 1;
        entry->seconds_offset = (get_random_u64() % 90000);
        entry->nano_offset = (get_random_u64() % 9000);
        entry->next = cache_head;
        cache_head = entry;
    }
    
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
    return entry;
}

void spoof_cache_cleanup(void) {
    struct spoof_data *entry, *next;
    unsigned long flags;

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn || !kfree_fn) {
        pr_err("[Obbed] Required functions not available for cleanup\n");
        return;
    }

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    entry = cache_head;
    while (entry != NULL) {
        next = entry->next;
        kfree_fn(entry);
        entry = next;
    }
    cache_head = NULL;
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
}

void print_spoof_cache(void) {
    struct spoof_data *entry;
    unsigned long flags;

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn) {
        pr_err("[Obbed] Required functions not available for printing\n");
        return;
    }

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    pr_info("[Obbed] Spoof cache contents:\n");
    for (entry = cache_head; entry != NULL; entry = entry->next) {
        pr_info("  UID %d: inode_offset=%lu, days_offset=%lu, seconds_offset=%lu, nanos_offset=%lu, dev_offset=%lu\n",
                entry->uid, entry->inode_offset, entry->days_offset, entry->seconds_offset, entry->nano_offset, entry->dev_offset);
    }
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
}