#ifndef _SPOOF_CACHE_H_
#define _SPOOF_CACHE_H_

#include <ktypes.h>
#include <linux/spinlock.h>

// Directory and file path for persistent storage
// Using /data/adb/ directly since it already exists (APatch is installed)
#define SPOOF_DIR "/data/adb"
#define SPOOF_FILE_PREFIX "/data/adb/.spoof_"
#define SPOOF_FILE_SUFFIX ".dat"
#define SPOOF_MAGIC 0x5350304F  // "SP0O" in hex

// Structure to hold spoofed values for a UID
struct spoof_data {
    uid_t uid;                    // User ID
    unsigned long dev_offset;     // dev id offset
    unsigned long inode_offset;   // Spoofed inode offset
    unsigned long days_offset;    // Spoofed days offset
    unsigned long seconds_offset; // Spoofed seconds offset
    unsigned long nano_offset;    // Spoofed nanoseconds offset
    struct spoof_data *next;      // Next entry in list (for memory cache)
};

// Structure for file storage (without linked list pointer)
struct spoof_file_data {
    uint32_t magic;               // Magic number for validation
    uid_t uid;                    // User ID
    unsigned long dev_offset;     // dev id offset
    unsigned long inode_offset;   // Spoofed inode offset
    unsigned long days_offset;    // Spoofed days offset
    unsigned long seconds_offset; // Spoofed seconds offset
    unsigned long nano_offset;    // Spoofed nanoseconds offset
};

// Core functions
void spoof_cache_init(void);
void spoof_cache_cleanup(void);
struct spoof_data* get_spoof_data(uid_t uid);
void print_spoof_cache(void);

// File-based persistence functions
int spoof_file_save(uid_t uid, struct spoof_data *data);
int spoof_file_load(uid_t uid, struct spoof_data *data);
int spoof_file_delete(uid_t uid);
int spoof_file_delete_all(void);
int spoof_ensure_dir(void);

#endif // _SPOOF_CACHE_H_