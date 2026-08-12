// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include "json.h"

void json_escape(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return;

    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        unsigned char c = src[i];
        if (j >= dst_size - 6)
            break;
        switch (c) {
        case '"': dst[j++] = '\\'; dst[j++] = '"'; break;
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\b': dst[j++] = '\\'; dst[j++] = 'b'; break;
        case '\f': dst[j++] = '\\'; dst[j++] = 'f'; break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
        case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
        case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
        default:
            if (c < 0x20) {
                if (j + 6 >= dst_size)
                    break;
                int written = snprintf(dst + j, dst_size - j, "\\u%04x", c);
                if (written > 0 && written < (int)(dst_size - j))
                    j += written;
                else
                    break;
            } else {
                dst[j++] = c;
            }
            break;
        }
    }
    dst[j] = '\0';
}
