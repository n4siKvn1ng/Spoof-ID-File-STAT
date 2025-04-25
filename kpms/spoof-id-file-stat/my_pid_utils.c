#include "my_pid_utils.h"
#include <ksyms.h>


static inline void my_init_kernel_task_pid_nr_ns(void) {
    __my_task_pid_nr_ns = (typeof(__my_task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns"); // Look up the real function
    if (__my_task_pid_nr_ns == NULL) {
        pr_err("[Obbed] Failed to find __task_pid_nr_ns\n");
    }
}

static inline my_pid_t my_get_task_pid(struct task_struct *task, enum my_pid_type type) {
    return __my_task_pid_nr_ns(task, (enum pid_type) type, 0); // Cast to the kernel's enum
}