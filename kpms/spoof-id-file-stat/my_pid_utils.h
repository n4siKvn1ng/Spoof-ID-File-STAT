#ifndef MY_PID_UTILS_H
#define MY_PID_UTILS_H
    //types ??
//#include <linux/types.h>
//#include <taskext.h>

#include <ktypes.h>
#include <linux/sched.h>
#include <linux/printk.h>



// Conditional definitions
#ifndef _LINUX_PID_H // Only define if <linux/pid.h> is NOT included

// Renamed types to avoid conflicts
enum my_pid_type {
    MY_PIDTYPE_PID, // Renamed
    MY_PIDTYPE_TGID, // Renamed
    MY_PIDTYPE_PGID, // Renamed
    MY_PIDTYPE_SID, // Renamed
    MY_PIDTYPE_MAX, // Renamed
};

struct my_pid_namespace;  // Renamed


typedef int my_pid_t;

#else

typedef pid_t my_pid_t;

enum my_pid_type{
    MY_PIDTYPE_PID = PIDTYPE_PID, // Renamed
    MY_PIDTYPE_TGID = PIDTYPE_TGID, // Renamed
    MY_PIDTYPE_PGID = PIDTYPE_PGID, // Renamed
    MY_PIDTYPE_SID = PIDTYPE_SID, // Renamed
    MY_PIDTYPE_MAX = PIDTYPE_MAX, // Renamed
};



#endif



// Function declarations using renamed types
my_pid_t (*__my_task_pid_nr_ns)(struct task_struct *task, enum my_pid_type type, struct pid_namespace *ns) = 0;

static inline my_pid_t my_get_task_pid(struct task_struct *task, enum my_pid_type type);
static inline void my_init_kernel_task_pid_nr_ns(void);


#endif // MY_PID_UTILS_H