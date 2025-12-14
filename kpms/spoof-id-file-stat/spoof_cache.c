#include "spoof_cache.h"
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <ksyms.h>
#include <kputils.h>
#include <linux/cred.h>
#include <linux/sched.h>
// #include <linux/workqueue.h> // Missing, so we define manually below

// Ubah menjadi 0 untuk Rilis (Log mati), 1 untuk Debug (Log nyala)
#define DEBUG_MODE 0

#if DEBUG_MODE
    #define LOGD(fmt, ...) pr_info("[Obbed] " fmt, ##__VA_ARGS__)
    #define LOGE(fmt, ...) pr_err("[Obbed] " fmt, ##__VA_ARGS__)
    #define LOGW(fmt, ...) pr_warn("[Obbed] " fmt, ##__VA_ARGS__)
#else
    #define LOGD(fmt, ...) do {} while(0)
    #define LOGE(fmt, ...) do {} while(0)
    #define LOGW(fmt, ...) do {} while(0)
#endif

// =========================================================================
// MANUAL DEFINITIONS FOR WORKQUEUE (Since header is missing)
// =========================================================================

// struct list_head already defined in ktypes.h

// Forward declaration
struct workqueue_struct;

// Define a local work_struct with padding to be safe against size mismatches (e.g. LOCKDEP)
struct my_work_struct {
    unsigned long data;       // atomic_long_t
    struct list_head entry;
    void (*func)(struct my_work_struct *work);
    // Add significant padding to cover potential debug fields (lockdep_map is large)
    unsigned long padding[24]; 
};

// Macros to initialize list and work
#define MY_INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

// WORK_STRUCT_NO_POOL is typically 0 or related atomic init. 
// Starting with 0 is essentially "not queued".
#define MY_INIT_WORK(_work, _func) do { \
    (_work)->data = 0; \
    MY_INIT_LIST_HEAD(&(_work)->entry); \
    (_work)->func = (void (*)(struct my_work_struct *))(_func); \
} while (0)


// =========================================================================
// STANDARD IMPORTS
// =========================================================================

// Function pointers for dynamic resolution
static void* (*__kmalloc_fn)(size_t size, gfp_t flags) = NULL;
static void (*kfree_fn)(const void *objp) = NULL;
static unsigned long (*_raw_spin_lock_irqsave_fn)(raw_spinlock_t *lock) = NULL;
static void (*_raw_spin_unlock_irqrestore_fn)(raw_spinlock_t *lock, unsigned long flags) = NULL;

// Credential function pointers
static struct cred *init_cred_ptr = NULL;
static const struct cred* (*override_creds_fn)(const struct cred *) = NULL;
static void (*revert_creds_fn)(const struct cred *) = NULL;
static struct task_struct* (*find_task_by_vpid_fn)(pid_t nr) = NULL;
static const struct cred* (*get_task_cred_fn)(struct task_struct *task) = NULL;

// File operation function pointers
static struct file* (*filp_open_fn)(const char *, int, umode_t) = NULL;
static int (*filp_close_fn)(struct file *, fl_owner_t) = NULL;
static ssize_t (*kernel_read_fn)(struct file *, void *, size_t, loff_t *) = NULL;
static ssize_t (*kernel_write_fn)(struct file *, const void *, size_t, loff_t *) = NULL;

// Workqueue function pointers
static bool (*queue_work_on_fn)(int cpu, struct workqueue_struct *wq, struct my_work_struct *work) = NULL;
static void (*flush_work_fn)(struct my_work_struct *work) = NULL;
static struct workqueue_struct **system_wq_ptr_ptr = NULL; // Pointer to the kernel variable
static struct workqueue_struct *resolved_system_wq = NULL; // The actual WQ to use

// Constants from workqueue.h (to support queue_work_on)
#define WORK_CPU_UNBOUND    NR_CPUS
// Fallback if NR_CPUS not defined:
#ifndef NR_CPUS
#define NR_CPUS 8 // Safe assumption for ARM64 mobile, or usage of specific value like 4096 in some headers
// Actually, let's look at workqueue.h again. It usually uses a specific large int.
// But wait, queue_work calls queue_work_on(WORK_CPU_UNBOUND, ...).
// Let's rely on queue_work_on finding specific CPU if we pass a random valid CPU.
// Or we can just try to resolve "queue_work" again? No it failed.
#endif

// Operations for workqueue
#define OP_SAVE 1
#define OP_LOAD 2
#define OP_CHECK_DIR 3
#define OP_DELETE 4

struct spoof_work_ctx {
    // Put work_struct FIRST to avoid offset issues if our definition is slightly off
    struct my_work_struct work; 
    
    int op_type;
    char process_name[MAX_PROCESS_NAME];  // Process name as identifier
    uid_t uid;                            // UID for reference
    struct spoof_data *data;     // For SAVE (input) or LOAD (output)
    int result;                  // Return value
};

// Cache state
static struct spoof_data *cache_head = NULL;
static spinlock_t cache_lock = __SPIN_LOCK_UNLOCKED();

#define __GFP_ZERO      0x8000u
#define __GFP_ATOMIC    0x80u

static int init_kernel_functions(void) {
    __kmalloc_fn = (void* (*)(size_t, gfp_t))kallsyms_lookup_name("__kmalloc");
    if (!__kmalloc_fn) {
        LOGE("Failed to find __kmalloc\n");
        return -1;
    }

    kfree_fn = (void (*)(const void*))kallsyms_lookup_name("kfree");
    if (!kfree_fn) {
        LOGE("Failed to find kfree\n");
        return -1;
    }

    _raw_spin_lock_irqsave_fn = (unsigned long (*)(raw_spinlock_t*))kallsyms_lookup_name("_raw_spin_lock_irqsave");
    if (!_raw_spin_lock_irqsave_fn) {
        LOGE("Failed to find _raw_spin_lock_irqsave\n");
        return -1;
    }

    _raw_spin_unlock_irqrestore_fn = (void (*)(raw_spinlock_t*, unsigned long))kallsyms_lookup_name("_raw_spin_unlock_irqrestore");
    if (!_raw_spin_unlock_irqrestore_fn) {
        LOGE("Failed to find _raw_spin_unlock_irqrestore\n");
        return -1;
    }

    // File operation functions
    filp_open_fn = (struct file* (*)(const char *, int, umode_t))kallsyms_lookup_name("filp_open");
    filp_close_fn = (int (*)(struct file *, fl_owner_t))kallsyms_lookup_name("filp_close");
    kernel_read_fn = (ssize_t (*)(struct file *, void *, size_t, loff_t *))kallsyms_lookup_name("kernel_read");
    kernel_write_fn = (ssize_t (*)(struct file *, const void *, size_t, loff_t *))kallsyms_lookup_name("kernel_write");

    if (!filp_open_fn || !filp_close_fn) {
        LOGW("File operations missing - persistence disabled\n");
    }

    // Resolve credential functions
    init_cred_ptr = (struct cred *)kallsyms_lookup_name("init_cred");
    override_creds_fn = (const struct cred* (*)(const struct cred *))kallsyms_lookup_name("override_creds");
    revert_creds_fn = (void (*)(const struct cred *))kallsyms_lookup_name("revert_creds");
    
    // Resolve task finding functions
    find_task_by_vpid_fn = (struct task_struct* (*)(pid_t))kallsyms_lookup_name("find_task_by_vpid");
    if (!find_task_by_vpid_fn) {
        find_task_by_vpid_fn = (struct task_struct* (*)(pid_t))kallsyms_lookup_name("pid_task");
    }
    
    get_task_cred_fn = (const struct cred* (*)(struct task_struct *))kallsyms_lookup_name("get_task_cred");

    // Workqueue symbols - SMART RESOLUTION LEVEL 2
    // queue_work is inline -> calls queue_work_on
    queue_work_on_fn = (bool (*)(int, struct workqueue_struct *, struct my_work_struct *))kallsyms_lookup_name("queue_work_on");
    flush_work_fn = (void (*)(struct my_work_struct *))kallsyms_lookup_name("flush_work");

    // 2. Find the system workqueue to use
    // Try system_percpu_wq first (newer kernels)
    system_wq_ptr_ptr = (struct workqueue_struct **)kallsyms_lookup_name("system_percpu_wq");
    if (system_wq_ptr_ptr) {
        resolved_system_wq = *system_wq_ptr_ptr;
        LOGD("Use system_percpu_wq\n");
    } else {
        // Fallback to system_wq (older kernels)
        system_wq_ptr_ptr = (struct workqueue_struct **)kallsyms_lookup_name("system_wq");
        if (system_wq_ptr_ptr) {
            resolved_system_wq = *system_wq_ptr_ptr;
            LOGD("Use system_wq\n");
        }
    }
    
    if (!queue_work_on_fn || !flush_work_fn || !resolved_system_wq) {
        LOGW("Failed to fully resolve workqueue components: QWON=%p FW=%p WQ=%p\n", 
                queue_work_on_fn, flush_work_fn, resolved_system_wq);
    } else {
        LOGD("Workqueue components resolved successfully (using queue_work_on)\n");
    }

    LOGD("Kernel functions resolved\n");
    return 0;
}

// Helper to switch to root credentials (Used ONLY by Worker Thread)
static const struct cred* spoof_file_op_start(void) {
    if (!override_creds_fn || !revert_creds_fn) return NULL;
    
    const struct cred *new_cred = NULL;
    
    if (find_task_by_vpid_fn && get_task_cred_fn) {
        struct task_struct *init_task = find_task_by_vpid_fn(1);
        if (init_task) {
            new_cred = get_task_cred_fn(init_task);
            LOGD("[WORKER] Stole credentials from Init (PID 1)\n");
        } else {
            LOGW("[WORKER] Failed to find Init task (PID 1)\n");
        }
    }
    
    if (!new_cred && init_cred_ptr) {
        new_cred = init_cred_ptr;
        LOGD("[WORKER] Fallback: Using static init_cred\n");
    }
    
    if (new_cred) {
        return override_creds_fn(new_cred);
    }
    return NULL;
}

// Helper to restore original credentials
static void spoof_file_op_end(const struct cred *old_cred) {
    if (!old_cred || !revert_creds_fn) return;
    revert_creds_fn(old_cred);
}

static void build_spoof_filepath(const char *process_name, char *buf, size_t buflen) {
    int i = 0;
    const char *p;
    
    const char *prefix = SPOOF_FILE_PREFIX;
    while (*prefix && i < buflen - 1) buf[i++] = *prefix++;
    
    // Append process name
    p = process_name;
    while (*p && i < buflen - 1) buf[i++] = *p++;
    
    const char *suffix = SPOOF_FILE_SUFFIX;
    while (*suffix && i < buflen - 1) buf[i++] = *suffix++;
    
    buf[i] = '\0';
}

// Internal File Operations (Run on Worker Thread)
static int do_spoof_ensure_dir(void) {
    struct file *dir;
    const struct cred *old_cred;
    int ret = -1;

    if (!filp_open_fn || !filp_close_fn) return -1;
    
    old_cred = spoof_file_op_start();
    
    dir = filp_open_fn(SPOOF_DIR, O_RDONLY, 0);
    if (!IS_ERR(dir)) {
        filp_close_fn(dir, NULL);
        ret = 0;
    } else {
         LOGE("[WORKER] Failed to open dir %s: err=%ld\n", SPOOF_DIR, PTR_ERR(dir));
    }
    
    spoof_file_op_end(old_cred);
    if (ret != 0) LOGW("Spoof directory not found: %s\n", SPOOF_DIR);
    return ret;
}

static int do_spoof_file_save(const char *process_name, struct spoof_data *data) {
    struct file *f;
    struct spoof_file_data file_data;
    char filepath[128];
    loff_t pos = 0;
    ssize_t written;
    const struct cred *old_cred;
    int i;
    
    if (!filp_open_fn || !filp_close_fn || !kernel_write_fn) return -1;
    
    build_spoof_filepath(process_name, filepath, sizeof(filepath));
    
    file_data.magic = SPOOF_MAGIC;
    // Copy process name
    for (i = 0; i < MAX_PROCESS_NAME - 1 && data->process_name[i]; i++) {
        file_data.process_name[i] = data->process_name[i];
    }
    file_data.process_name[i] = '\0';
    file_data.uid = data->uid;
    file_data.dev_offset = data->dev_offset;
    file_data.inode_offset = data->inode_offset;
    file_data.days_offset = data->days_offset;
    file_data.seconds_offset = data->seconds_offset;
    file_data.nano_offset = data->nano_offset;
    
    old_cred = spoof_file_op_start();
    
    f = filp_open_fn(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(f)) {
        LOGE("[WORKER] Failed to open file %s for writing: err=%ld\n", filepath, PTR_ERR(f));
        spoof_file_op_end(old_cred);
        return -1;
    }
    
    written = kernel_write_fn(f, &file_data, sizeof(file_data), &pos);
    filp_close_fn(f, NULL);
    spoof_file_op_end(old_cred);
    
    if (written != sizeof(file_data)) {
        LOGE("[WORKER] Failed to write full data to %s: wrote %zd/%zu\n", filepath, written, sizeof(file_data));
        return -1;
    }
    
    LOGD("[WORKER] Successfully saved %s (process: %s)\n", filepath, process_name);
    return 0;
}

static int do_spoof_file_load(const char *process_name, struct spoof_data *data) {
    struct file *f;
    struct spoof_file_data file_data;
    char filepath[128];
    loff_t pos = 0;
    ssize_t read_bytes;
    const struct cred *old_cred;
    int i;
    
    if (!filp_open_fn || !filp_close_fn || !kernel_read_fn) return -1;
    
    build_spoof_filepath(process_name, filepath, sizeof(filepath));
    
    old_cred = spoof_file_op_start();
    
    f = filp_open_fn(filepath, O_RDONLY, 0);
    if (IS_ERR(f)) {
        spoof_file_op_end(old_cred);
        return -1;
    }
    
    read_bytes = kernel_read_fn(f, &file_data, sizeof(file_data), &pos);
    filp_close_fn(f, NULL);
    spoof_file_op_end(old_cred);
    
    if (read_bytes != sizeof(file_data)) return -1;
    if (file_data.magic != SPOOF_MAGIC) return -1;
    // Validate process name matches
    for (i = 0; i < MAX_PROCESS_NAME; i++) {
        if (file_data.process_name[i] != process_name[i]) return -1;
        if (file_data.process_name[i] == '\0') break;
    }
    
    // Copy process name to data
    for (i = 0; i < MAX_PROCESS_NAME - 1 && file_data.process_name[i]; i++) {
        data->process_name[i] = file_data.process_name[i];
    }
    data->process_name[i] = '\0';
    data->uid = file_data.uid;
    data->dev_offset = file_data.dev_offset;
    data->inode_offset = file_data.inode_offset;
    data->days_offset = file_data.days_offset;
    data->seconds_offset = file_data.seconds_offset;
    data->nano_offset = file_data.nano_offset;
    data->next = NULL;
    
    return 0;
}

static int do_spoof_file_delete(const char *process_name) {
    struct file *f;
    char filepath[128];
    const struct cred *old_cred;
    
    if (!filp_open_fn) return -1;
    build_spoof_filepath(process_name, filepath, sizeof(filepath));
    
    old_cred = spoof_file_op_start();
    f = filp_open_fn(filepath, O_RDONLY, 0);
    if (IS_ERR(f)) {
        spoof_file_op_end(old_cred);
        return 0; 
    }
    filp_close_fn(f, NULL);
    
    f = filp_open_fn(filepath, O_WRONLY | O_TRUNC, 0);
    if (!IS_ERR(f)) filp_close_fn(f, NULL);
    
    spoof_file_op_end(old_cred);
    LOGD("[WORKER] Deleted file for process: %s\n", process_name);
    return 0;
}

// WORKER HANDLER
static void spoof_worker_handler(struct my_work_struct *work) {
    struct spoof_work_ctx *ctx = container_of(work, struct spoof_work_ctx, work);
    
    switch (ctx->op_type) {
        case OP_SAVE:
            ctx->result = do_spoof_file_save(ctx->process_name, ctx->data);
            break;
        case OP_LOAD:
            ctx->result = do_spoof_file_load(ctx->process_name, ctx->data);
            break;
        case OP_CHECK_DIR:
            ctx->result = do_spoof_ensure_dir();
            break;
        case OP_DELETE:
            ctx->result = do_spoof_file_delete(ctx->process_name);
            break;
        default: break;
    }
}

// DISPATCHER
static int dispatch_spoof_work(int op_type, const char *process_name, struct spoof_data *data) {
    struct spoof_work_ctx *ctx;
    int ret;
    int i;

    // Check if we have the components to execute safely via workqueue
    if (queue_work_on_fn && flush_work_fn && resolved_system_wq) {
        if (!__kmalloc_fn || !kfree_fn) return -1;

        ctx = (struct spoof_work_ctx *)__kmalloc_fn(sizeof(struct spoof_work_ctx), __GFP_ZERO);
        if (!ctx) return -1;

        MY_INIT_WORK(&ctx->work, spoof_worker_handler);
        
        ctx->op_type = op_type;
        // Copy process name
        if (process_name) {
            for (i = 0; i < MAX_PROCESS_NAME - 1 && process_name[i]; i++) {
                ctx->process_name[i] = process_name[i];
            }
            ctx->process_name[i] = '\0';
        } else {
            ctx->process_name[0] = '\0';
        }
        ctx->data = data;
        
        // Manual schedule_work: queue_work_on(WORK_CPU_UNBOUND, system_wq, work)
        queue_work_on_fn(WORK_CPU_UNBOUND, resolved_system_wq, &ctx->work);
        
        // Wait for it
        flush_work_fn(&ctx->work);
        
        ret = ctx->result;
        kfree_fn(ctx);
        return ret;
    }

    // FALLBACK: Only if we REALLY can't find queue_work or system_wq
    static int warned_once = 0;
    if (!warned_once) {
        LOGW("PRE-FLIGHT: Workqueue resolution FAILED! Downgrading to DIRECT execution.\n");
        warned_once = 1;
    }

    switch (op_type) {
        case OP_SAVE:
            return do_spoof_file_save(process_name, data);
        case OP_LOAD:
            return do_spoof_file_load(process_name, data);
        case OP_CHECK_DIR:
            return do_spoof_ensure_dir();
        case OP_DELETE:
            return do_spoof_file_delete(process_name);
        default: return -1;
    }
}

// PUBLIC WRAPPERS

int spoof_ensure_dir(void) {
    return dispatch_spoof_work(OP_CHECK_DIR, NULL, NULL);
}

int spoof_file_save(const char *process_name, struct spoof_data *data) {
    return dispatch_spoof_work(OP_SAVE, process_name, data);
}

int spoof_file_load(const char *process_name, struct spoof_data *data) {
    return dispatch_spoof_work(OP_LOAD, process_name, data);
}

int spoof_file_delete(const char *process_name) {
    return dispatch_spoof_work(OP_DELETE, process_name, NULL);
}

// Delete all spoof files (lock logic remains here, file deletion dispatched)
int spoof_file_delete_all(void) {
    LOGD("Deleting all spoof data...\n");
    
    struct spoof_data *entry;
    unsigned long flags;
    char process_names_to_delete[8][MAX_PROCESS_NAME]; // Max 8 apps for "Reset All"
    int count = 0;
    int i, j;

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn) return -1;

    // 1. Snapshot valid process names
    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    for (entry = cache_head; entry != NULL; entry = entry->next) {
        if (count < 8) {
            for (j = 0; j < MAX_PROCESS_NAME - 1 && entry->process_name[j]; j++) {
                process_names_to_delete[count][j] = entry->process_name[j];
            }
            process_names_to_delete[count][j] = '\0';
            count++;
        }
    }
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);

    // 2. Delete files (Safe without lock)
    for (i = 0; i < count; i++) {
        spoof_file_delete(process_names_to_delete[i]);
    }
    
    LOGD("Spoof file cleanup completed (%d files)\n", count);
    return 0;
}

void spoof_cache_init(void) {
    cache_head = NULL;
    spin_lock_init(&cache_lock);
    if (init_kernel_functions() != 0) {
        LOGE("Cache initialization failed!\n");
    }
    spoof_ensure_dir();
}

// Helper to compare process names
static int process_name_matches(const char *a, const char *b) {
    int i;
    for (i = 0; i < MAX_PROCESS_NAME; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') break;
    }
    return 1;
}

// Safe removal
void remove_spoof_data(const char *process_name) {
    struct spoof_data *entry, *prev;
    unsigned long flags;

    // Dispatch file delete (safe, no lock)
    spoof_file_delete(process_name);

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn || !kfree_fn) return;

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    
    if (cache_head && process_name_matches(cache_head->process_name, process_name)) {
        entry = cache_head;
        cache_head = cache_head->next;
        kfree_fn(entry);
        _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
        return;
    }

    prev = cache_head;
    entry = cache_head ? cache_head->next : NULL;
    while (entry != NULL) {
        if (process_name_matches(entry->process_name, process_name)) {
            prev->next = entry->next;
            kfree_fn(entry);
            break;
        }
        prev = entry;
        entry = entry->next;
    }
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
}

struct spoof_data* get_spoof_data(const char *process_name, uid_t uid) {
    struct spoof_data *entry;
    unsigned long flags;
    int i;

    if (!process_name) return NULL;
    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn || !__kmalloc_fn) return NULL;

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    
    for (entry = cache_head; entry != NULL; entry = entry->next) {
        if (process_name_matches(entry->process_name, process_name)) {
            // Update UID if it changed (reinstall case)
            if (entry->uid != uid) {
                LOGD("UID changed for process %s: %d -> %d (likely reinstall)\n", 
                        process_name, entry->uid, uid);
                entry->uid = uid;
            }
            _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
            return entry;
        }
    }
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);

    entry = __kmalloc_fn(sizeof(struct spoof_data), __GFP_ATOMIC | __GFP_ZERO);
    if (!entry) return NULL;
    
    // LOAD (Safe Workqueue) - Try to load from file
    if (spoof_file_load(process_name, entry) == 0) {
        // Update UID if it changed (reinstall case)
        if (entry->uid != uid) {
            LOGD("UID changed for process %s (from file): %d -> %d (likely reinstall)\n", 
                    process_name, entry->uid, uid);
            entry->uid = uid;
            // Re-save with new UID
            spoof_file_save(process_name, entry);
        }
        flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
        entry->next = cache_head;
        cache_head = entry;
        _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
        LOGD("Loaded persistent spoof data for process %s (UID %d)\n", process_name, uid);
        return entry;
    }
    
    // NEW - Generate random values
    // Copy process name
    for (i = 0; i < MAX_PROCESS_NAME - 1 && process_name[i]; i++) {
        entry->process_name[i] = process_name[i];
    }
    entry->process_name[i] = '\0';
    entry->uid = uid;
    entry->dev_offset = (get_random_u64() % 100);
    entry->inode_offset = (get_random_u64() % 100) + 1;
    entry->days_offset = (get_random_u64() % 30) + 1;
    entry->seconds_offset = (get_random_u64() % 90000);
    entry->nano_offset = (get_random_u64() % 9000);
    
    // SAVE (Safe Workqueue)
    spoof_file_save(process_name, entry);
    
    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    entry->next = cache_head;
    cache_head = entry;
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
    
    LOGD("Generated new random spoof data for process %s (UID %d)\n", process_name, uid);
    return entry;
}

void spoof_cache_cleanup(void) {
    struct spoof_data *entry, *next;
    unsigned long flags;

    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn || !kfree_fn) return;

    // Delete files first
    spoof_file_delete_all();

    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    entry = cache_head;
    while (entry != NULL) {
        next = entry->next;
        kfree_fn(entry);
        entry = next;
    }
    cache_head = NULL;
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
    
    LOGD("Spoof cache cleaned up\n");
}

void print_spoof_cache(void) {
    struct spoof_data *entry;
    unsigned long flags;
    if (!_raw_spin_lock_irqsave_fn || !_raw_spin_unlock_irqrestore_fn) return;
    flags = _raw_spin_lock_irqsave_fn(&cache_lock.rlock);
    LOGD("Spoof cache contents:\n");
    for (entry = cache_head; entry != NULL; entry = entry->next) {
        LOGD("  Process '%s' (UID %d): inode=%lu\n", entry->process_name, entry->uid, entry->inode_offset);
    }
    _raw_spin_unlock_irqrestore_fn(&cache_lock.rlock, flags);
}