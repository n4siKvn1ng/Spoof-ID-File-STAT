#ifndef _OBBED_LOGGER_H_
#define _OBBED_LOGGER_H_

#include <linux/printk.h>

// Ubah menjadi 0 untuk Rilis (Log mati), 1 untuk Debug (Log nyala)
#ifndef DEBUG_MODE
#define DEBUG_MODE 1
#endif

// Helper macros for consistent logging
#if DEBUG_MODE
    #define LOGD(fmt, ...) pr_info("[Obbed] " fmt, ##__VA_ARGS__)
    #define LOGE(fmt, ...) pr_err("[Obbed] " fmt, ##__VA_ARGS__)
    #define LOGW(fmt, ...) pr_warn("[Obbed] " fmt, ##__VA_ARGS__)
#else
    #define LOGD(fmt, ...) do {} while(0)
    #define LOGE(fmt, ...) do {} while(0)
    #define LOGW(fmt, ...) do {} while(0)
#endif

#endif // _OBBED_LOGGER_H_