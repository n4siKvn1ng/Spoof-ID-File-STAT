/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <ktypes.h>
#include <ksyms.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/ptrace.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <log.h>

#include "runtime.c"
#include "spoof_cache.c"
#include "re_offsets.c"
#include "my_pid_utils.c"

KPM_NAME("Spoof ID File STAT");
KPM_VERSION("2.4.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("obbedcode, n4siKvn1ng");
KPM_DESCRIPTION("Spoof ID when app is get ID from File STAT. ID that receive by the App have spoof after the STAT get value.");

// Ubah menjadi 0 untuk Rilis (Log mati), 1 untuk Debug (Log nyala)
#define DEBUG_MODE 0

#if DEBUG_MODE
    #define LOGD(fmt, ...) pr_info("[Obbed] " fmt, ##__VA_ARGS__)
    #define LOGE(fmt, ...) pr_err("[Obbed] " fmt, ##__VA_ARGS__)
#else
    #define LOGD(fmt, ...) do {} while(0)
    #define LOGE(fmt, ...) do {} while(0)
#endif

const char *margs = 0;
static int paranoid_mode = 0;

struct pid_namespace;
// Simple function pointer without specific parameter details
typedef long (*sys_fstatat_t)(void);
sys_fstatat_t original_fstatat = NULL;
struct spoof_data *spoof = NULL;

// Target process name - hardcoded for now
static const char *target_process_name = TARGET_PROCESS_NAME;

// Target UID - auto-detected from process name, kept for quick filtering
// But the actual identifier for persistence is the process name
static uid_t target_uid = 0;

// Define after hook function for fstatat
void after_fstatat(hook_fargs4_t *args, void *udata)
{
    // pr_info("[Obbed] after_fstatat hook triggered\n");
    // pr_info("[Obbed] args: %lx, %lx, %lx, %lx\n", 
    //         (unsigned long)args->arg0, 
    //         (unsigned long)args->arg1, 
    //         (unsigned long)args->arg2, 
    //         (unsigned long)args->arg3);
    char path_buf[MAX_PATH];
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    struct task_struct *task = current;

    // Safety check removed to fix build error (incomplete task_struct definition)
    // The whitelist filter below is sufficient to prevent bootloops.
    
    int dfd = (int)syscall_argn(args, 0);
    struct stat __user *statbuf = (struct stat __user *)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    args->local.data0 = (uint64_t)task;

    if (!filename || !task) {
        return; // Invalid filename or task - skip silently
    } else if(compat_strncpy_from_user(path_buf, filename, sizeof(path_buf)) <= 0) {
        return; // Failed to copy or empty path - skip silently (normal for AT_EMPTY_PATH)
    }

    pid_t pid = my_get_task_pid(task, PIDTYPE_PID);
    const char* comm = task_comm(current);
    uid_t curr_uid = current_uid();

    // Skip system processes (UID < 10000)
    if (curr_uid < 10000) {
        return;
    }

    // Auto-detect target UID from process name
    // Look for process containing "fpjs" (from d.fpjs_pro_demo)
    if (target_uid == 0 && strstr(comm, "d.fpjs_pro_demo")) {
        target_uid = curr_uid;
        LOGD("TARGET DETECTED! UID=%d COMM='%s' - Will only spoof this UID from now on\n", target_uid, comm);
    }

    // Only proceed if this is our target UID
    // Skip if target not yet detected OR if this is not the target
    if (target_uid == 0 || curr_uid != target_uid) {
        return;
    }

    int is_ashmem = strstr(path_buf, "ashmem") != NULL || strstr(path_buf, "hosts") != NULL;

    // Log target UID activity for debugging
    // pr_info("[Obbed] [SPOOF] UID=%d COMM='%s' PATH='%s' ASHMEM=%d\n", curr_uid, comm, path_buf, is_ashmem);

    // pr_info("[Obbed] ====================================================================\n");
    if (args->ret == 0) {
        struct stat local_stat;
        unsigned long seconds_offset = 0;

        // Only get spoof data if not an ashmem device
        if (!is_ashmem) {
            spoof = get_spoof_data(target_process_name, curr_uid);
            if (!spoof) {
                LOGE("[fstatat] Failed to get spoof data for UID %d\n", curr_uid);
                return;
            }
            seconds_offset = spoof->days_offset * 86400 + spoof->seconds_offset;
            // pr_info("[Obbed] [fstatat] Using Spoof Data for >> stat(%s) for UID(%d) Cached Offset Seconds=%d\n", path_buf, curr_uid, seconds_offset);
        } else {
            // pr_info("[Obbed] [fstatat] Detected ashmem device: %s - will use system default timestamp (1970)\n", path_buf);
        }

        unsigned long cp_res = __arch_copy_from_user_fn(&local_stat, statbuf, sizeof(struct stat));
        
        if (cp_res != 0){
            LOGE("[fstatat] Failed to use [__arch_copy_from_user] Return=%d using Fallback (compat_strncpy_from_user)\n", cp_res);
            
            struct timespec atim = {0}, mtim = {0}, ctim = {0};
            unsigned long inode = 0, dev_id = 0;

            const size_t ino_offset = offsetof(struct stat, st_ino);
            const size_t dev_offset = offsetof(struct stat, st_dev);
            const size_t atim_offset = offsetof(struct stat, st_atim);
            const size_t mtim_offset = offsetof(struct stat, st_mtim);
            const size_t ctim_offset = offsetof(struct stat, st_ctim);

            // pr_info("[Obbed] [fstatat] [timespec] Offsets, Inode=%d Dev=%d Access=%d Modify=%d Change=%d\n", ino_offset, dev_offset, atim_offset, mtim_offset, ctim_offset);

            int c_inode = compat_strncpy_from_user((char *)&inode,  (const char __user *)((char *)statbuf + ino_offset), sizeof(unsigned long));
            int c_dev = compat_strncpy_from_user((char *)&dev_id,  (const char __user *)((char *)statbuf + dev_offset), sizeof(unsigned long));
            int c_access = compat_strncpy_from_user((char *)&atim, (const char __user *)((char *)statbuf + atim_offset),sizeof(struct timespec));
            int c_modify = compat_strncpy_from_user((char *)&mtim, (const char __user *)((char *)statbuf + mtim_offset), sizeof(struct timespec));
            int c_change = compat_strncpy_from_user((char *)&ctim, (const char __user *)((char *)statbuf + ctim_offset),sizeof(struct timespec));

            // pr_info("[Obbed] [fstatat] compat_strncpy_from_user >> Inode Result=%d Dev Result=%d Access Result=%d Modify Result=%d Change Result=%d\n", c_inode, c_dev, c_access, c_modify, c_change);
            if(!(c_inode > 0 && c_dev > 0  && c_access > 0 && c_modify > 0 && c_change > 0)) {
                LOGE("[fstatat] (timespec) Failed, File=%s\n", path_buf);
                return;
            }

            // pr_info("[Obbed] [fstatat] Original Times for %s (Inode=%lu):\n  Dev=%lu:\n  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
            //        path_buf, inode, dev_id,
            //        atim.tv_sec, atim.tv_nsec,
            //        mtim.tv_sec, mtim.tv_nsec,
            //        ctim.tv_sec, ctim.tv_nsec);
            
            if(is_ashmem){
                // Log the original timestamps before modification
                // pr_info("[Obbed] [fstatat] Original Timestamps for ASHMEM:\n"
                //         "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                //         atim.tv_sec, atim.tv_nsec,
                //         mtim.tv_sec, mtim.tv_nsec,
                //         ctim.tv_sec, ctim.tv_nsec);

                // ASHMEM HANDLING: Set all timestamps to 1970-01-01
                atim.tv_sec = 0;  // Explicitly set to Unix epoch
                mtim.tv_sec = 0;
                ctim.tv_sec = 0;

                // Preserve the nanoseconds from the original timestamp
                if (atim.tv_nsec != 0) {
                    atim.tv_nsec = atim.tv_nsec;
                    mtim.tv_nsec = mtim.tv_nsec;
                    ctim.tv_nsec = ctim.tv_nsec;
                }

                // Log the modified timestamps
                // pr_info("[Obbed] [fstatat] Modified Timestamps for ASHMEM:\n"
                //         "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                //         atim.tv_sec, atim.tv_nsec,
                //         mtim.tv_sec, mtim.tv_nsec,
                //         ctim.tv_sec, ctim.tv_nsec);
            } else {
                // Regular file handling with spoof offsets
                inode += spoof->inode_offset;
                dev_id += spoof->dev_offset;
                atim.tv_sec += seconds_offset;
                mtim.tv_sec += seconds_offset;
                ctim.tv_sec += seconds_offset;

                if(atim.tv_nsec > 0) atim.tv_nsec += spoof->nano_offset;
                if(mtim.tv_nsec > 0) mtim.tv_nsec += spoof->nano_offset;
                if(ctim.tv_nsec > 0) ctim.tv_nsec += spoof->nano_offset;
            }

            // Write back modified inode and timestamps
            compat_copy_to_user((char __user *)((char *)statbuf + ino_offset), &inode, sizeof(unsigned long));
            compat_copy_to_user((char __user *)((char *)statbuf + dev_offset), &dev_id, sizeof(unsigned long));
            compat_copy_to_user((char __user *)((char *)statbuf + atim_offset), &atim, sizeof(struct timespec));
            compat_copy_to_user((char __user *)((char *)statbuf + mtim_offset), &mtim, sizeof(struct timespec));
            compat_copy_to_user((char __user *)((char *)statbuf + ctim_offset), &ctim, sizeof(struct timespec));
            
            // pr_info("[Obbed] [fstatat] New Times for %s (Inode=%lu):\n  Dev=%lu\n  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
            //        path_buf, inode, dev_id,
            //        atim.tv_sec, atim.tv_nsec,
            //        mtim.tv_sec, mtim.tv_nsec,
            //        ctim.tv_sec, ctim.tv_nsec);

        } else {
            // pr_info("[Obbed] [fstatat] (__arch_copy_from_user) Times for %s UID: %d  (Inode=%lu)\n (Device=%lu)\nAccess: %ld.%ld\nModify: %ld.%ld\nChange: %ld.%ld\n", 
            //         path_buf,
            //         curr_uid,
            //         local_stat.st_ino,
            //         local_stat.st_dev,
            //         local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
            //         local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec, 
            //         local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);

            if (is_ashmem) {
                // Log the original timestamps before modification
                // pr_info("[Obbed] [fstatat] Original Timestamps for ASHMEM:\n"
                //         "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                //         local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
                //         local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec,
                //         local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);

                // ASHMEM HANDLING: Set all timestamps to 1970-01-01
                local_stat.st_atim.tv_sec = 0;  // Explicitly set to Unix epoch
                local_stat.st_mtim.tv_sec = 0;
                local_stat.st_ctim.tv_sec = 0;

                // Preserve the nanoseconds from the original timestamp
                if (local_stat.st_atim.tv_nsec != 0) {
                    local_stat.st_atim.tv_nsec = local_stat.st_atim.tv_nsec;
                    local_stat.st_mtim.tv_nsec = local_stat.st_mtim.tv_nsec;
                    local_stat.st_ctim.tv_nsec = local_stat.st_ctim.tv_nsec;
                }

                // Log the modified timestamps
                // pr_info("[Obbed] [fstatat] Modified Timestamps for ASHMEM:\n"
                //         "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                //         local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
                //         local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec,
                //         local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);
            } else {
                // Regular file handling with spoof offsets
                local_stat.st_ino += spoof->inode_offset;
                local_stat.st_dev += spoof->dev_offset;
                local_stat.st_atim.tv_sec += seconds_offset;
                local_stat.st_mtim.tv_sec += seconds_offset;
                local_stat.st_ctim.tv_sec += seconds_offset;

                if(local_stat.st_atim.tv_nsec > 0) local_stat.st_atim.tv_nsec += spoof->nano_offset;
                if(local_stat.st_mtim.tv_nsec > 0) local_stat.st_mtim.tv_nsec += spoof->nano_offset;
                if(local_stat.st_ctim.tv_nsec > 0) local_stat.st_ctim.tv_nsec += spoof->nano_offset;
            }

            // pr_info("[Obbed] [fstatat] (__arch_copy_from_user) New Times for %s UID: %d  (Inode=%lu)\n (Device=%lu)\nAccess: %ld.%ld\nModify: %ld.%ld\nChange: %ld.%ld\n", 
            //         path_buf,
            //         curr_uid,
            //         local_stat.st_ino,
            //         local_stat.st_dev,
            //         local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
            //         local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec, 
            //         local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);

            cp_res = compat_copy_to_user((char *)statbuf, &local_stat, sizeof(struct stat));
            if (cp_res <= 0) {
                LOGE("Failed to copy data to user space. Error code: %ld\n", cp_res);
            } else {
                // pr_info("[Obbed] [fstatat] Finished Replacing stat(%s) with Return value=(%d) with new times for UID(%d)\n", path_buf, cp_res, curr_uid);
            }
            
        }
    }
}


static long inline_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    LOGD("Initializing ARM64 inline hook module...\n");

    kmalloc_fn = (typeof(kmalloc_fn))kallsyms_lookup_name("kmalloc");
    if (!kmalloc_fn) {
        LOGD("Failed to resolve kmalloc\n");
    }

    vmalloc_user_fn = (typeof(vmalloc_user_fn))kallsyms_lookup_name("vmalloc_user");
    if (!vmalloc_user_fn) {
        LOGD("Failed to resolve vmalloc_user\n");
    }

    __arch_copy_from_user_fn = (typeof(__arch_copy_from_user_fn))kallsyms_lookup_name("__arch_copy_from_user");
    if (!__arch_copy_from_user_fn) {
        LOGD("Failed to resolve __arch_copy_from_user\n");
    }

    LOGD("Finished resolving Kernel Functions\n");

    init_kernel_functions();
    my_init_kernel_task_pid_nr_ns();

    // Try different possible names for the syscall implementation
    original_fstatat = (sys_fstatat_t)kallsyms_lookup_name("__arm64_sys_newfstatat");
    if (!original_fstatat) {
        original_fstatat = (sys_fstatat_t)kallsyms_lookup_name("__sys_newfstatat");
    }
    if (!original_fstatat) {
        original_fstatat = (sys_fstatat_t)kallsyms_lookup_name("sys_newfstatat");
    }
    if (!original_fstatat) {
        original_fstatat = (sys_fstatat_t)kallsyms_lookup_name("__arm64_compat_sys_fstatat64");
    }
    
    if (!original_fstatat) {
        LOGD("Failed to find fstatat syscall handler\n");
        return -1;
    }
    
    LOGD("Found fstatat syscall handler at %p\n", original_fstatat);
    
    // Install inline hook - using hook_wrap4 with NULL for the before function
    hook_err_t err = hook_wrap4((void *)original_fstatat, NULL, after_fstatat, 0);
    
    if (err != HOOK_NO_ERR) {
        LOGD("Failed to install inline hook for fstatat: %d\n", err);
        return -1;
    }
    
    LOGD("Successfully installed inline hook for fstatat\n");

    return 0;
}

static long inline_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    LOGD("Control called with args: %s\n", args);
    
    if (strstr(args, "stat") != NULL) {
        LOGD("Received 'stat' command - cleaning up all spoof data...\n");
        
        // Reset target UID so we detect fresh on next app launch
        target_uid = 0;
        
        // Clean up cache and files
        spoof_cache_cleanup();
        
        LOGD("========================================\n");
        LOGD("Spoof data cleanup SUCCESS!\n");
        LOGD("- Memory cache cleared\n");
        LOGD("- Persistent files invalidated\n");
        LOGD("- Target UID reset\n");
        LOGD("New fingerprint will be generated on next app launch\n");
        LOGD("========================================\n");
    }

    return 0;
}

static long inline_hook_demo_exit(void *__user reserved)
{
    LOGD("kpm-inline-hook-demo exit ...\n");

    if (original_fstatat) {
        unhook((void *)original_fstatat);
        LOGD("Removed inline hook for fstatat\n");
    }
    
    return 0;
}

KPM_INIT(inline_hook_demo_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_demo_exit);