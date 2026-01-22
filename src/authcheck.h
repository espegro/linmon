// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Espen Grøndahl <espegro@usit.uio.no>
// Authentication integrity monitoring - periodic validation of critical auth files

#ifndef __LINMON_AUTHCHECK_H
#define __LINMON_AUTHCHECK_H

#include <stdbool.h>

// Initialize authentication integrity monitoring
// verify_packages: enable package verification (requires pkgcache)
void authcheck_init(bool verify_packages);

// Perform periodic integrity check of all critical authentication files
// Logs violations to JSON and syslog
// Returns: number of violations detected (0 = all OK)
int authcheck_verify_all(void);

#endif /* __LINMON_AUTHCHECK_H */
