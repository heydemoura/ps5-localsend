/* SPDX-License-Identifier: GPL-3.0-only */
/* Copyright (C) 2026 heydemoura */
#include "assets.h"

/* The embedded image is the unmodified Apache-2.0 LocalSend logo.
 * See THIRD_PARTY_NOTICES.md and THIRD_PARTY_LICENSES/LocalSend-APACHE-2.0.txt. */
__asm__(".section .rodata\n"
        ".global localsend_icon\n"
        ".global localsend_icon_end\n"
        ".align 16\n"
        "localsend_icon:\n"
        ".incbin \"assets/icon0.png\"\n"
        "localsend_icon_end:\n"
        ".previous\n");
