#include <ksyms.h>
#include <ktypes.h>
#include <linux/cred.h>

#include "my_types.h"

enum my_pid_type
{
    MPIDTYPE_PID,
    MPIDTYPE_TGID,
    MPIDTYPE_PGID,
    MPIDTYPE_SID,
    MPIDTYPE_MAX,
};

struct pid_namespace;
my_pid_t (*__my_task_pid_nr_ns)(struct task_struct *task, enum my_pid_type type, struct pid_namespace *ns) = 0;

static inline void init_kernel_task_pid_nr_ns() {
    __my_task_pid_nr_ns = (typeof(__my_task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    if(__my_task_pid_nr_ns == NULL) {
        pr_err("[Obbed] Critical error failed to find [__my_task_pid_nr_ns]\n");
    } else{
        pr_info("[Obbed] Found Kernel Function [__my_task_pid_nr_ns] Address=%llx\n", __my_task_pid_nr_ns);
    }
}

static inline my_pid_t get_task_pid(struct task_struct *task, enum my_pid_type type) {
    return __my_task_pid_nr_ns(task, type, 0);
}
