/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_KPMODULE_H_
#define _KP_KPMODULE_H_

#define KPM_INFO(name, info, limit)                                 \
    _Static_assert(sizeof(info) <= limit, "Info string too long");  \
    static const char __kpm_info_##name[] __attribute__((__used__)) \
    __attribute__((section(".kpm.info"), unused, aligned(1))) = #name "=" info

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 12
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024

#define KPM_NAME(x) KPM_INFO(name, x, KPM_NAME_LEN)
#define KPM_VERSION(x) KPM_INFO(version, x, KPM_VERSION_LEN)
#define KPM_LICENSE(x) KPM_INFO(license, x, KPM_LICENSE_LEN)
#define KPM_AUTHOR(x) KPM_INFO(author, x, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(x) KPM_INFO(description, x, KPM_DESCRIPTION_LEN)

#ifndef min_t
#define min_t(type, x, y) ({          \
    type __min1 = (x);                \
    type __min2 = (y);                \
    __min1 < __min2 ? __min1 : __min2;\
})
#endif

typedef long (*mod_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*mod_ctl0call_t)(const char *ctl_args, char *__user out_msg, int outlen);
typedef long (*mod_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*mod_exitcall_t)(void *reserved);

#define KPM_INIT(fn) \
    static mod_initcall_t __kpm_initcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.init"))) = fn

#define KPM_CTL0(fn) \
    static mod_ctl0call_t __kpm_ctlmodule_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.ctl0"))) = fn

#define KPM_CTL1(fn) \
    static mod_ctl1call_t __kpm_ctlmodule_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.ctl1"))) = fn

#define KPM_EXIT(fn) \
    static mod_exitcall_t __kpm_exitcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.exit"))) = fn

#endif