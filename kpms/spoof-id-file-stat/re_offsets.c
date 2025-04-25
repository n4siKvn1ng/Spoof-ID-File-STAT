
//#include "re_offsets.h"

//static inline pid_t task_pid(struct task_struct* task, uint64_t pid_offset) {
//    pid_t pid = *(pid_t*)((uintptr_t)task + pid_offset);
//    return pid;
//}


//#include <linux/sched.h>
//#include <linux/cred.h>
//#include <hook.h>
//#include <taskext.h>
//#include <linux/kernel.h>
//#include <linux/printk.h>
//#include <linux/spinlock.h>
//#include <uapi/linux/limits.h>

//static inline uid_t get_current_caller_uid() {
//  struct cred* cred = *(struct cred**)((uintptr_t)current + task_struct_offset.cred_offset);
//  uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
//  return uid;
//}

#include "re_offsets.h"

//This is litterly current uid , as i said... bruh

static inline uid_t current_uid(void) {
    //struct cred *cred = (struct cred *)((uintptr_t)current + task_struct_offset.cred_offset);
    //uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    //return uid;
    return raw_syscall0(__NR_getuid);
}

static inline uid_t task_uid(struct task_struct *task) {
    struct cred *cred = (struct cred *)((uintptr_t)task + task_struct_offset.real_cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    //struct cred *cred = (struct cred *)((uintptr_t)task) + cred_offset.uid_offset;
    //return raw_syscall0(__NR_getuid);
    //This DOES not work very unstable ..... use the syscall it works 100%
    return uid;
}

static inline const char *task_comm(struct task_struct *task)
{
    return (const char *)(((uintptr_t)task) + task_struct_offset.comm_offset);
}