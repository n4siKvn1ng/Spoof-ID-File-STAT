#ifndef RE_OFFSETS_H
#define RE_OFFSETS_H

#include <taskext.h>
#include <linux/cred.h>
#include <syscall.h>


// ... other includes and declarations

static inline uid_t task_uid(struct task_struct *task);
static inline uid_t current_uid(void); // Declaration
static inline const char *task_comm(struct task_struct *task);



#endif