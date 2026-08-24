/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * find_query.h -- Shared read-only metadata search core.
 *
 * Backs the mds-find CLI and the mds-apid HTTP service.  Every operation
 * is read-only: the catalogue is queried with table scans and keyed
 * reads, and nothing here mutates it.
 *
 * NOT a public API header.  Included only by the find query core, the
 * tools built on it, and their unit tests.
 *
 * The pure helpers (parsing, formatting, glob handling) carry no
 * catalogue dependency and are unit-testable on their own; see
 * tests/unit/test_find_query.c.
 */

#ifndef FIND_QUERY_H
#define FIND_QUERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pnfs_mds.h"

struct mds_catalogue;

/** Result cap applied when the caller does not specify one. */
#define FIND_LIMIT_DEFAULT  10000U
/** Largest result cap a caller may request. */
#define FIND_LIMIT_MAX      10000000U

/** Buffer size for a LIKE pre-filter (entry_name is Varbinary(255)). */
#define FIND_LIKE_MAX       512U

/** Rendered permission string: 9 characters plus NUL. */
#define FIND_MODE_STR_LEN   10U

/* -----------------------------------------------------------------------
 * Pure helpers -- no catalogue dependency.
 * ----------------------------------------------------------------------- */

/**
 * Parse a base-10 unsigned 64-bit integer.
 *
 * Rejects empty input, leading signs, trailing garbage, and overflow.
 *
 * @param s    Input string (NULL is rejected).
 * @param out  Receives the parsed value on success (must be non-NULL).
 * @return true on success, false otherwise.
 */
bool find_parse_u64(const char *s, uint64_t *out);

/**
 * Parse a byte size with an optional binary unit suffix.
 *
 * Accepts a bare byte count, or one suffixed with K, M, G, T, or P
 * (case-insensitive, powers of 1024).  Overflow is rejected rather than
 * wrapped, so "16E" fails instead of silently becoming a small number.
 *
 * @param s    Input string (NULL or empty is rejected).
 * @param out  Receives the size in bytes (must be non-NULL).
 * @return true on success, false otherwise.
 */
bool find_parse_size(const char *s, uint64_t *out);

/**
 * Parse a single find-style type character.
 *
 * @param s  One-character string: f, d, l, b, c, p, or s.
 * @return The matching MDS_FTYPE_* value, or -1 when unrecognised.
 */
int find_parse_type_char(const char *s);

/**
 * Map a file type to its ls-style type character.
 *
 * @param type  MDS_FTYPE_* value.
 * @return '-', 'd', 'l', 'b', 'c', 'p', 's', or '?' when unknown.
 */
char find_type_char(uint8_t type);

/**
 * Render a 9-character rwx permission string.
 *
 * Honours setuid, setgid, and the sticky bit in the usual ls positions.
 *
 * @param mode  POSIX mode bits.
 * @param out   Buffer of at least FIND_MODE_STR_LEN bytes.
 */
void find_format_mode(uint32_t mode, char *out);

/**
 * Build a LIKE pre-filter pattern from a shell glob.
 *
 * The result is deliberately a SUPERSET of the glob's true match set and
 * is only ever used to cut wire traffic; exact matching is always done
 * by find_name_matches() on the rows that come back.  Correctness
 * therefore never depends on this pattern, only performance does.
 *
 * '*' maps to '%' and '?' maps to '_', matching the backend's wildcards
 * (NdbSqlUtil uses the standard SQL set: '%' any run, '_' any one
 * character, '\\' escape).  Literal '%' and '_' in the glob are passed
 * through unescaped, so the backend reads them as wildcards -- that only
 * widens the pattern, which is safe.  A glob containing a backslash or a
 * '[...]' character class has no safe LIKE equivalent and is rejected so
 * the caller pushes no filter at all; matching it literally would make
 * the pattern narrower and silently drop real matches.
 *
 * @param glob  Shell glob (NULL or empty yields no pattern).
 * @param out   Output buffer.
 * @param cap   Capacity of @p out including the NUL terminator.
 * @return Number of bytes written (excluding NUL) when a useful pattern
 *         was produced; 0 when no pattern is worth pushing (the glob
 *         matches everything); -1 when no filter may be pushed safely.
 *         In both the 0 and -1 cases the caller must pass NULL to the
 *         backend rather than a pattern.
 */
int find_glob_to_like(const char *glob, char *out, size_t cap);

/**
 * Exact shell-glob match against an entry name.
 *
 * This is the authority for the -name predicate.  Semantics match
 * find(1): fnmatch(3) with no flags, so '*' also matches a leading dot.
 *
 * @param glob  Shell glob; NULL matches everything.
 * @param name  NUL-terminated entry name.
 * @return true when @p name matches @p glob.
 */
bool find_name_matches(const char *glob, const char *name);

/* -----------------------------------------------------------------------
 * Search filter and results.
 * ----------------------------------------------------------------------- */

/**
 * Search predicates.  All are optional and AND-combined; an inactive
 * predicate means "don't care".
 *
 * Every predicate carries an explicit has_* flag rather than treating
 * zero as unset, so genuinely-zero values (uid 0, size 0, epoch 0) are
 * expressible.
 */
struct find_filter {
    uint64_t    size_min;
    uint64_t    size_max;
    uint64_t    uid;
    uint64_t    gid;
    int64_t     mtime_min;      /**< epoch seconds, inclusive. */
    int64_t     mtime_max;
    int64_t     ctime_min;
    int64_t     ctime_max;
    uint64_t    inum_min;
    uint64_t    inum_max;
    const char *name_glob;      /**< Borrowed; NULL means any name. */
    uint32_t    limit;          /**< 0 selects FIND_LIMIT_DEFAULT. */
    uint8_t     type;           /**< MDS_FTYPE_*, or 0 for any type. */
    bool        has_size_min;
    bool        has_size_max;
    bool        has_uid;
    bool        has_gid;
    bool        has_mtime_min;
    bool        has_mtime_max;
    bool        has_ctime_min;
    bool        has_ctime_max;
    bool        has_inum;       /**< inum_min..inum_max is active. */
};

/** One match. */
struct find_result {
    uint64_t fileid;
    uint64_t parent_fileid;
    uint64_t uid;
    uint64_t gid;
    uint64_t size;
    int64_t  mtime_sec;
    int64_t  ctime_sec;
    uint32_t mode;
    uint32_t nlink;
    uint8_t  type;
    /** Entry name, or "" when it could not be resolved (e.g. the root,
     *  or a dirent removed concurrently with the scan). */
    char     name[MDS_MAX_NAME + 1];
};

/**
 * Per-match callback.
 *
 * @return 0 to continue searching, non-zero to stop early.
 */
typedef int (*find_result_cb)(const struct find_result *r, void *ctx);

/**
 * Run a search against the catalogue.
 *
 * Strategy is chosen from the predicates:
 *   - an exact single fileid is served by one keyed read, never a scan;
 *   - a name-only search scans dirents (the name is already there) and
 *     fills attributes with one keyed read per match, bounded by the
 *     result limit;
 *   - anything with attribute predicates scans inodes with those
 *     predicates pushed to the data nodes, resolving each match's name
 *     afterwards.
 *
 * Matches are delivered in backend scan order, which is not stable
 * across runs.  The scan stops as soon as the limit is reached.
 *
 * @param cat     Catalogue handle.
 * @param filter  Predicates (must be non-NULL).
 * @param cb      Per-match callback (must be non-NULL).
 * @param ctx     Opaque context passed to @p cb.
 * @return MDS_OK on success, MDS_ERR_INVAL on bad arguments,
 *         MDS_ERR_NOSUPPORT when the backend cannot scan, or a backend
 *         error code.
 */
enum mds_status find_query_run(struct mds_catalogue *cat,
                               const struct find_filter *filter,
                               find_result_cb cb, void *ctx);

#endif /* FIND_QUERY_H */
