// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// User database - UID to username resolution with caching

#ifndef __LINMON_USERDB_H
#define __LINMON_USERDB_H

#include <sys/types.h>

#define USERNAME_MAX 32

// Initialize user database
void userdb_init(void);

// Cleanup user database
void userdb_cleanup(void);

// Resolve UID to username (cached)
// Returns username in provided buffer, or "UID_XXXX" if not found
// Thread-safe
void userdb_resolve(uid_t uid, char *buf, size_t buf_size);

#endif /* __LINMON_USERDB_H */
