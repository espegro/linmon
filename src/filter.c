// SPDX-License-Identifier: GPL-2.0
// Event filtering and processing implementation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>

#include "filter.h"

static char **ignore_list = NULL;
static int ignore_count = 0;
static char **only_list = NULL;
static int only_count = 0;
static bool redact_enabled = true;

// File path filtering
static char **ignore_file_paths = NULL;
static int ignore_file_path_count = 0;

// Sensitive patterns to redact
static const char *sensitive_patterns[] = {
    "password=",
    "passwd=",
    "pwd=",
    "pass=",
    "token=",
    "api_key=",
    "apikey=",
    "secret=",
    "auth=",
    "key=",
    "-p ", // Common password flag
    "--password",
    NULL
};

// Parse comma-separated list
static char **parse_list(const char *str, int *count)
{
    char **list = NULL;
    char *tmp, *token;
    int n = 0;

    if (!str || strlen(str) == 0) {
        *count = 0;
        return NULL;
    }

    tmp = strdup(str);
    if (!tmp)
        return NULL;

    // Count entries
    char *p = tmp;
    while (*p) {
        if (*p == ',')
            n++;
        p++;
    }
    n++; // One more than commas

    list = calloc(n, sizeof(char *));
    if (!list) {
        free(tmp);
        return NULL;
    }

    // Parse tokens
    n = 0;
    token = strtok(tmp, ",");
    while (token) {
        // Trim whitespace
        while (isspace(*token))
            token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end))
            *end-- = '\0';

        if (strlen(token) > 0) {
            list[n] = strdup(token);
            if (!list[n]) {
                // strdup failed - free everything and abort
                for (int i = 0; i < n; i++)
                    free(list[i]);
                free(list);
                free(tmp);
                *count = 0;
                return NULL;
            }
            n++;
        }
        token = strtok(NULL, ",");
    }

    free(tmp);
    *count = n;
    return list;
}

static void free_list(char **list, int count)
{
    if (!list)
        return;

    for (int i = 0; i < count; i++) {
        if (list[i])
            free(list[i]);
    }
    free(list);
}

void filter_init(const struct linmon_config *config)
{
    // Free old lists before allocating new ones
    free_list(ignore_list, ignore_count);
    ignore_list = NULL;
    ignore_count = 0;

    free_list(only_list, only_count);
    only_list = NULL;
    only_count = 0;

    free_list(ignore_file_paths, ignore_file_path_count);
    ignore_file_paths = NULL;
    ignore_file_path_count = 0;

    // Parse ignore list
    if (config->ignore_processes)
        ignore_list = parse_list(config->ignore_processes, &ignore_count);

    // Parse only list
    if (config->only_processes)
        only_list = parse_list(config->only_processes, &only_count);

    // Parse file path ignore list
    if (config->ignore_file_paths) {
        ignore_file_paths = parse_list(config->ignore_file_paths, &ignore_file_path_count);
        if (ignore_file_path_count > 0) {
            printf("  File path filtering: %d path prefix(es) loaded\n", ignore_file_path_count);
        }
    }

    redact_enabled = config->redact_sensitive;
}

bool filter_should_log_process(const char *comm)
{
    int i;

    // Check whitelist first (if configured)
    if (only_count > 0) {
        for (i = 0; i < only_count; i++) {
            if (strcmp(comm, only_list[i]) == 0)
                return true;
        }
        return false; // Not in whitelist
    }

    // Check blacklist
    if (ignore_count > 0) {
        for (i = 0; i < ignore_count; i++) {
            if (strcmp(comm, ignore_list[i]) == 0)
                return false;
        }
    }

    return true;
}

bool filter_should_log_file(const char *filename)
{
    int i;

    if (!filename || filename[0] == '\0')
        return false;  // Don't log empty filenames

    // Check if filename starts with any ignored path prefix
    if (ignore_file_path_count > 0) {
        for (i = 0; i < ignore_file_path_count; i++) {
            size_t prefix_len = strlen(ignore_file_paths[i]);

            // Check if filename starts with this prefix
            if (strncmp(filename, ignore_file_paths[i], prefix_len) == 0)
                return false;  // Path matches ignored prefix
        }
    }

    return true;  // Not in ignored paths
}

void filter_redact_cmdline(char *cmdline, size_t size)
{
    const char **pattern;
    char *pos, *end;
    size_t len;

    if (!redact_enabled || !cmdline || size == 0)
        return;

    // Look for each sensitive pattern
    for (pattern = sensitive_patterns; *pattern != NULL; pattern++) {
        pos = strstr(cmdline, *pattern);
        if (!pos)
            continue;

        // Find the value part (after the pattern)
        pos += strlen(*pattern);

        // Find the end of the value (space, quote, or end of string)
        end = pos;
        bool in_quotes = (*pos == '"' || *pos == '\'');
        if (in_quotes) {
            char quote = *pos;
            end++;
            while (*end && *end != quote)
                end++;
        } else {
            while (*end && !isspace(*end))
                end++;
        }

        // Redact the value
        len = end - pos;
        if (len > 0 && len < size) {
            memset(pos, '*', len);
        }
    }

    // Also redact anything that looks like a password in common formats
    // -p<password> or --password <password>
    pos = cmdline;
    while ((pos = strstr(pos, "-p")) != NULL) {
        // Check bounds before accessing pos[2]
        if ((pos + 2) < (cmdline + size) && pos[2] != ' ' && pos[2] != '\0') {
            // Format: -pPASSWORD
            end = pos + 2;
            while (*end && !isspace(*end) && (end - cmdline) < (long)size)
                end++;
            len = end - (pos + 2);
            if (len > 0 && (pos + 2 + len - cmdline) <= (long)size)
                memset(pos + 2, '*', len);
        }
        // Advance safely
        if ((pos + 2) < (cmdline + size))
            pos += 2;
        else
            break;
    }
}
