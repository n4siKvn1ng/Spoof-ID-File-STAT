#ifndef RE_RUNTIME_H
#define RE_RUNTIME_H


#define MAX_PATH 256



#ifndef LOOKUP_PARENT
#define LOOKUP_PARENT 0x0010
#endif

#define O_RDONLY 00000000

#define S_IFCHR 0020000
#define __NR_mknodat 33 //asm-generic/unistd.h

struct timespec {
    __kernel_time_t tv_sec;     /* seconds */
    long            tv_nsec;    /* nanoseconds */
};


// "linux/stat.h"
struct stat {
    unsigned long   st_dev;         /* Device */
    unsigned long   st_ino;         /* File serial number */
    unsigned int    st_mode;        /* File mode */
    unsigned int    st_nlink;       /* Link count */
    unsigned int    st_uid;         /* User ID of the file's owner */
    unsigned int    st_gid;         /* Group ID of the file's group */
    unsigned long   st_rdev;        /* Device number, if device */
    unsigned long   __pad1;
    long           st_size;        /* Size of file, in bytes */
    int            st_blksize;     /* Optimal block size for I/O */
    int            __pad2;
    long           st_blocks;      /* Number 512-byte blocks allocated */
    struct timespec st_atim;       /* Time of last access */
    struct timespec st_mtim;       /* Time of last modification */
    struct timespec st_ctim;       /* Time of last status change */
    unsigned int    __unused4;
    unsigned int    __unused5;
};

static void *(*kmalloc_fn)(size_t size, gfp_t flags);
static void *(*vmalloc_user_fn)(unsigned long size);
static unsigned long (*__arch_copy_from_user_fn)(void *to, const void __user *from, unsigned long n);


static bool is_debug = true;

/*
static void symbol_exists(const char *args) {
    if(args == NULL) {
        pr_info("[Obbed]");
    }
}

*/

static inline int log_i(const char *tag, const char *message);



#endif