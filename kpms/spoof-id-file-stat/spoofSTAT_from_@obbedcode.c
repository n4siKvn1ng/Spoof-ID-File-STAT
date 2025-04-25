#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <ktypes.h>
#include <ksyms.h>
#include <asm/current.h>
#include <linux/ptrace.h>
#include <linux/err.h>
#include <linux/vmalloc.h>

#include <kputils.h>
#include "my_pid_utils.c"
#include "re_offsets.c"
#include "spoof_cache.c"
#include "runtime.c"
#include "logger.h"

KPM_NAME("KPM STAT Spoof");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ObbedCode");
KPM_DESCRIPTION("This Random Attributes for STAT");

const char *margs = 0;
static int paranoid_mode = 0;
static int save_cache = 0;
enum hook_type hook_type = NONE;

void after_fstatat_0(hook_fargs4_t *args, void *udata) {
    char path_buf[MAX_PATH];
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    struct task_struct *task = current;
    struct stat local_stat;

    pr_info("[dd]");

    int dfd = (int)syscall_argn(args, 0);
    struct stat __user *statbuf = (struct stat __user *)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    args->local.data0 = (uint64_t)task;

    if (!filename || !task) {
        pr_err("[Obbed] Invalid filename or task in [fstatat] hook\n");
        return;
    }

    pid_t pid = my_get_task_pid(task, PIDTYPE_PID);
    const char* comm = task_comm(current);
    uid_t curr_uid = current_uid();

    if (compat_strncpy_from_user(path_buf, filename, MAX_PATH) <= 0) {
        pr_err("[Obbed] Error Failed to copy path from user [fstatat] Hook\n");
        return;
    }
    // Check if this is an ashmem device
    int is_ashmem = strstr(path_buf, "ashmem") != NULL || strstr(path_buf, "hosts") != NULL;

    if((paranoid_mode == 1) || (is_ashmem || strstr(path_buf, "boot_id") || strstr(path_buf, "/data/misc/keychain") || strstr(path_buf, "hosts"))) {
        if(curr_uid < 10000 && !is_ashmem) {
            pr_info("[Obbed] .. Skipping [fstatat] as request package is a System Package, uid=%d\n", current_uid);
            return;
        }

        struct stat local_stat;
        struct spoof_data *spoof = NULL;
        unsigned long seconds_offset = 0;

        // Only get spoof data if not an ashmem device
        if (!is_ashmem) {
            spoof = get_spoof_data(curr_uid);
            if (!spoof) {
                pr_err("[Obbed] [fstatat] Failed to get spoof data for UID %d\n", curr_uid);
                return;
            }
            seconds_offset = spoof->days_offset * 86400 + spoof->seconds_offset;
            pr_info("[Obbed] [fstatat] Using Spoof Data for >> stat(%s) for UID(%d) Cached Offset Seconds=%d\n", path_buf, curr_uid, seconds_offset);
        } else {
            pr_info("[Obbed] [fstatat] Detected ashmem device: %s - will use system default timestamp (1970)\n", path_buf);
        }

        unsigned long cp_res = __arch_copy_from_user_fn(&local_stat, statbuf, sizeof(struct stat));
        if(cp_res != 0) {
            pr_err("[Obbed] [fstatat] Failed to use [__arch_copy_from_user] Return=%d using Fallback (compat_strncpy_from_user)\n", cp_res);

            struct timespec atim = {0}, mtim = {0}, ctim = {0};
            unsigned long inode = 0;

            const size_t ino_offset = offsetof(struct stat, st_ino);
            const size_t atim_offset = offsetof(struct stat, st_atim);
            const size_t mtim_offset = offsetof(struct stat, st_mtim);
            const size_t ctim_offset = offsetof(struct stat, st_ctim);

            pr_info("[Obbed] [fstatat] [timespec] Offsets, Inode=%d Access=%d Modify=%d Change=%d\n", ino_offset, atim_offset, mtim_offset, ctim_offset);

            int c_inode = compat_strncpy_from_user((char *)&inode,  (const char __user *)((char *)statbuf + ino_offset), sizeof(unsigned long));
            int c_access = compat_strncpy_from_user((char *)&atim, (const char __user *)((char *)statbuf + atim_offset),sizeof(struct timespec));
            int c_modify = compat_strncpy_from_user((char *)&mtim, (const char __user *)((char *)statbuf + mtim_offset), sizeof(struct timespec));
            int c_change = compat_strncpy_from_user((char *)&ctim, (const char __user *)((char *)statbuf + ctim_offset),sizeof(struct timespec));

            pr_info("[Obbed] [fstatat] compat_strncpy_from_user >> Inode Result=%d Access Result=%d Modify Result=%d Change Result=%d\n", c_inode, c_access, c_modify, c_change);

            if(!(c_inode > 0 && c_access > 0 && c_modify > 0 && c_change > 0)) {
                pr_err("[Obbed] [fstatat] (timespec) Failed, File=%s\n", path_buf);
                return;
            }

            pr_info("[Obbed] [fstatat] Original Times for %s (Inode=%lu):\n  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                   path_buf, inode,
                   atim.tv_sec, atim.tv_nsec,
                   mtim.tv_sec, mtim.tv_nsec,
                   ctim.tv_sec, ctim.tv_nsec);

            if (is_ashmem) {
                // Log the original timestamps before modification
                pr_info("[Obbed] [fstatat] Original Timestamps for ASHMEM:\n"
                        "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                        atim.tv_sec, atim.tv_nsec,
                        mtim.tv_sec, mtim.tv_nsec,
                        ctim.tv_sec, ctim.tv_nsec);

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
                pr_info("[Obbed] [fstatat] Modified Timestamps for ASHMEM:\n"
                        "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                        atim.tv_sec, atim.tv_nsec,
                        mtim.tv_sec, mtim.tv_nsec,
                        ctim.tv_sec, ctim.tv_nsec);
            } else {
                // Regular file handling with spoof offsets
                inode += spoof->inode_offset;
                atim.tv_sec += seconds_offset;
                mtim.tv_sec += seconds_offset;
                ctim.tv_sec += seconds_offset;

                if(atim.tv_nsec > 0) atim.tv_nsec += spoof->nano_offset;
                if(mtim.tv_nsec > 0) mtim.tv_nsec += spoof->nano_offset;
                if(ctim.tv_nsec > 0) ctim.tv_nsec += spoof->nano_offset;
            }

            // Write back modified inode and timestamps
            compat_copy_to_user((char __user *)((char *)statbuf + ino_offset), &inode, sizeof(unsigned long));
            compat_copy_to_user((char __user *)((char *)statbuf + atim_offset), &atim, sizeof(struct timespec));
            compat_copy_to_user((char __user *)((char *)statbuf + mtim_offset), &mtim, sizeof(struct timespec));
            compat_copy_to_user((char __user *)((char *)statbuf + ctim_offset), &ctim, sizeof(struct timespec));
            
            pr_info("[Obbed] [fstatat] New Times for %s (Inode=%lu):\n  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                   path_buf, inode,
                   atim.tv_sec, atim.tv_nsec,
                   mtim.tv_sec, mtim.tv_nsec,
                   ctim.tv_sec, ctim.tv_nsec);

        } else {
            pr_info("[Obbed] [fstatat] (__arch_copy_from_user) Times for %s UID: %d  (Inode=%lu) \n Access: %ld.%ld\n Modify: %ld.%ld\n Change: %ld.%ld\n", 
                path_buf,
                curr_uid,
                local_stat.st_ino,
                local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
                local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec, 
                local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);

            if (is_ashmem) {
                // Log the original timestamps before modification
                pr_info("[Obbed] [fstatat] Original Timestamps for ASHMEM:\n"
                        "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                        local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
                        local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec,
                        local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);

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
                pr_info("[Obbed] [fstatat] Modified Timestamps for ASHMEM:\n"
                        "  Access: %ld.%ld\n  Modify: %ld.%ld\n  Change: %ld.%ld\n",
                        local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
                        local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec,
                        local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);
            } else {
                // Regular file handling with spoof offsets
                local_stat.st_ino += spoof->inode_offset;
                local_stat.st_atim.tv_sec += seconds_offset;
                local_stat.st_mtim.tv_sec += seconds_offset;
                local_stat.st_ctim.tv_sec += seconds_offset;

                if(local_stat.st_atim.tv_nsec > 0) local_stat.st_atim.tv_nsec += spoof->nano_offset;
                if(local_stat.st_mtim.tv_nsec > 0) local_stat.st_mtim.tv_nsec += spoof->nano_offset;
                if(local_stat.st_ctim.tv_nsec > 0) local_stat.st_ctim.tv_nsec += spoof->nano_offset;
            }

            pr_info("[Obbed] [fstatat] (__arch_copy_from_user) New Times for %s UID: %d (Inode=%lu) \n Access: %ld.%ld\n Modify: %ld.%ld\n Change: %ld.%ld\n", 
                path_buf,
                curr_uid,
                local_stat.st_ino,
                local_stat.st_atim.tv_sec, local_stat.st_atim.tv_nsec,
                local_stat.st_mtim.tv_sec, local_stat.st_mtim.tv_nsec, 
                local_stat.st_ctim.tv_sec, local_stat.st_ctim.tv_nsec);

            cp_res = compat_copy_to_user((char *)statbuf, &local_stat, sizeof(struct stat));
            pr_info("[Obbed] [fstatat] Finished Replacing stat(%s) with Return value=(%d) with new times for UID(%d)\n", path_buf, cp_res, curr_uid);
        }
    }
}

static long stat_hook_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[Obbed] Initializing module... UBER STAT DATA SCRAMBLER\n");
    for_each_vma
    uint64_t fvm = kallsyms_lookup_name("for_each_vma");
    pr_info("[Obbed] FOR_EACH_VMA=%p", fvm);

    kmalloc_fn = (typeof(kmalloc_fn))kallsyms_lookup_name("kmalloc");
    if (!kmalloc_fn) {
        pr_err("[Obbed] Failed to resolve kmalloc\n");
    }

    vmalloc_user_fn = (typeof(vmalloc_user_fn))kallsyms_lookup_name("vmalloc_user");
    if (!vmalloc_user_fn) {
        pr_err("[Obbed] Failed to resolve vmalloc_user\n");
    }

    __arch_copy_from_user_fn = (typeof(__arch_copy_from_user_fn))kallsyms_lookup_name("__arch_copy_from_user");
    if (!__arch_copy_from_user_fn) {
        pr_err("[Obbed] Failed to resolve __arch_copy_from_user\n");
    }

    pr_info("[Obbed] Finished resolving Kernel Functions\n");

    init_kernel_functions();
    my_init_kernel_task_pid_nr_ns();

    hook_err_t err = HOOK_NO_ERR;
    pr_info("[Obbed] Installing inline hook for [__NR3264_fstatat]...\n");
    
    hook_type = INLINE_CHAIN;

    err = inline_hook_syscalln(__NR3264_fstatat, 3, 0, after_fstatat_0, 0);
    if(err) {
        pr_err("[Obbed] Failed to install hook [fstatat(__NR3264_fstatat)]:after:code=%d %d\n", __NR3264_fstatat, err);
    } else {
        pr_info("[Obbed] Installed hook [fstatat(__NR3264_fstatat)]:after:code=%d\n", __NR3264_fstatat);
    }

    return 0;
}

#define UINT_MAX    0xFFFF  /* max value for uid_t (65535) */
/**
 * Converts a string to uid_t with validation
 * @param str Input string to convert
 * @param result Pointer to store the resulting uid_t
 * @return 0 on success, negative error code on failure
 */
int string_to_uid(const char *str, uid_t *result) {
    size_t len;
    unsigned long val = 0;
    
    if (!str || !result) {
        return -EINVAL;
    }

    // Check string length (0 < len <= 5)
    len = strlen(str);
    if (len == 0 || len > 5) {
        return -EINVAL;
    }

    // Convert string to number manually
    for (size_t i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return -EINVAL;
        }
        
        // Check for overflow before multiplying
        if (val > UINT_MAX / 10) {
            return -ERANGE;
        }
        val *= 10;
        
        // Check for overflow before adding
        if (val > UINT_MAX - (str[i] - '0')) {
            return -ERANGE;
        }
        val += str[i] - '0';
    }

    // Validate range for uid_t (using 65535 as conservative maximum)
    if (val > 65535) {
        return -ERANGE;
    }

    *result = (uid_t)val;
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen) {
    pr_info("[Obbed] Control init");
    int ret;
    uid_t target_uid;

    pr_info("[Obbed] Control call received with args: %s\n", args ? args : "NULL");

    if(args && strlen(args) < 15) {
        if(strstr(args, "all")) {
            pr_info("[Obbed] Clearing all Cache on Stored UID Random Date Offsets\n");
            spoof_cache_cleanup();
            return 0;
        } 

        if(strstr(args, "paranoid")) {
            paranoid_mode = 1;
            pr_info("[Obbed] Set KPM STAT Spoofer to paranoid\n");
            return 0;
        }

        if(strstr(args, "normal")) {
            paranoid_mode = 1;
            pr_info("[Obbed] Set KPM STAT Spoofer to Normal check mode (boot_id & keychain)");
            return 0;
        }

        int len = strlen(args);
        if(len < 1 && len > 5)  {
            pr_err("[Obbed] length of UID string is not valid, make sure its in between (1) and (5)\n");
            return -1;
        }

        if(string_to_uid(args, &target_uid) != 0) {
            pr_err("[Obbed] Failed to parse input as UID!\n");
            return -1;
        }

        pr_info("[Obbed] Removing UID:%d Cache....\n", target_uid);
        remove_spoof_data(target_uid);
    }

    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved) {
    pr_info("[Obbed] Module cleanup starting...\n");
    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscall(__NR3264_fstatat, 0, after_fstatat_0);
        pr_info("[Obbed] Unhooked [fstatat] syscall\n");
    }

    pr_info("[Obbed] Cleaning up (stat:uid) Cache...\n");
    spoof_cache_cleanup();
    pr_info("[Obbed] Module cleanup complete\n");
    return 0;
}

KPM_INIT(stat_hook_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);