#ifndef _SPOOF_CACHE_H_
#define _SPOOF_CACHE_H_

#include <ktypes.h>
#include <linux/spinlock.h>

// Structure to hold spoofed values for a UID
struct spoof_data {
    uid_t uid;                    // User ID
    unsigned long dev_offset;       // dev id
    unsigned long inode_offset;    // Spoofed inode offset
    unsigned long days_offset;     // Spoofed days offset

    unsigned long seconds_offset;
    unsigned long nano_offset;

    struct spoof_data *next;      // Next entry in list
};

void spoof_cache_init(void);
void spoof_cache_cleanup(void);
struct spoof_data* get_spoof_data(uid_t uid);
void print_spoof_cache(void);

#endif // _SPOOF_CACHE_H_