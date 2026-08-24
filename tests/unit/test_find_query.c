/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * test_find_query.c -- Unit tests for the metadata search core helpers.
 *
 * Covers the pure parts: strict integer and size parsing, type mapping,
 * mode rendering, glob matching, and the LIKE pre-filter construction.
 *
 * The LIKE tests are the important ones.  That pattern is only ever a
 * bandwidth optimisation, so the invariant under test is that it stays a
 * SUPERSET of what fnmatch would accept -- a pattern that is too narrow
 * would silently drop real matches.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "find_query.h"

static int passed = 0;
static int failed = 0;

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stdout, "FAIL (%s:%d: %s)\n", __FILE__, __LINE__, #cond); \
        failed++; return; \
    } \
} while (0)

#define ASSERT_FALSE(cond)  ASSERT_TRUE(!(cond))
#define ASSERT_EQ(a, b)     ASSERT_TRUE((a) == (b))
#define ASSERT_STREQ(a, b)  ASSERT_TRUE(strcmp((a), (b)) == 0)

/* -----------------------------------------------------------------------
 * find_parse_u64
 * ----------------------------------------------------------------------- */

static void test_parse_u64_accepts_valid(void)
{
    uint64_t v = 0U;

    ASSERT_TRUE(find_parse_u64("0", &v));
    ASSERT_EQ(v, 0U);

    ASSERT_TRUE(find_parse_u64("1000", &v));
    ASSERT_EQ(v, 1000U);

    ASSERT_TRUE(find_parse_u64("18446744073709551615", &v));
    ASSERT_TRUE(v == UINT64_MAX);
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_parse_u64_rejects_invalid(void)
{
    uint64_t v = 12345U;

    ASSERT_FALSE(find_parse_u64(NULL, &v));
    ASSERT_FALSE(find_parse_u64("", &v));
    ASSERT_FALSE(find_parse_u64("abc", &v));
    ASSERT_FALSE(find_parse_u64("12abc", &v));
    ASSERT_FALSE(find_parse_u64("12 ", &v));
    ASSERT_FALSE(find_parse_u64(" 12", &v));
    ASSERT_FALSE(find_parse_u64("+12", &v));
    /* A negative must not wrap around to a huge unsigned value. */
    ASSERT_FALSE(find_parse_u64("-1", &v));
    /* One past UINT64_MAX. */
    ASSERT_FALSE(find_parse_u64("18446744073709551616", &v));

    /* Nothing above should have modified the output. */
    ASSERT_EQ(v, 12345U);
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * find_parse_size
 * ----------------------------------------------------------------------- */

static void test_parse_size_suffixes(void)
{
    uint64_t v = 0U;

    ASSERT_TRUE(find_parse_size("512", &v));
    ASSERT_EQ(v, 512U);

    ASSERT_TRUE(find_parse_size("1K", &v));
    ASSERT_EQ(v, 1024U);

    ASSERT_TRUE(find_parse_size("1k", &v));
    ASSERT_EQ(v, 1024U);

    ASSERT_TRUE(find_parse_size("2M", &v));
    ASSERT_EQ(v, 2U * 1024U * 1024U);

    ASSERT_TRUE(find_parse_size("1G", &v));
    ASSERT_EQ(v, 1073741824U);

    ASSERT_TRUE(find_parse_size("1T", &v));
    ASSERT_TRUE(v == 1099511627776ULL);

    ASSERT_TRUE(find_parse_size("0G", &v));
    ASSERT_EQ(v, 0U);
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_parse_size_rejects_overflow_and_garbage(void)
{
    uint64_t v = 7U;

    /* Must reject rather than wrap: a truncated bound would produce a
     * confidently wrong result set. */
    ASSERT_FALSE(find_parse_size("18446744073709551615K", &v));
    ASSERT_FALSE(find_parse_size("99999999999999999999P", &v));
    ASSERT_FALSE(find_parse_size("K", &v));
    ASSERT_FALSE(find_parse_size("", &v));
    ASSERT_FALSE(find_parse_size(NULL, &v));
    ASSERT_FALSE(find_parse_size("1X", &v));
    ASSERT_FALSE(find_parse_size("-1K", &v));
    ASSERT_EQ(v, 7U);
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * Type mapping
 * ----------------------------------------------------------------------- */

static void test_type_char_roundtrip(void)
{
    ASSERT_EQ(find_parse_type_char("f"), MDS_FTYPE_REG);
    ASSERT_EQ(find_parse_type_char("d"), MDS_FTYPE_DIR);
    ASSERT_EQ(find_parse_type_char("l"), MDS_FTYPE_SYMLINK);
    ASSERT_EQ(find_parse_type_char("b"), MDS_FTYPE_BLKDEV);
    ASSERT_EQ(find_parse_type_char("c"), MDS_FTYPE_CHRDEV);
    ASSERT_EQ(find_parse_type_char("p"), MDS_FTYPE_FIFO);
    ASSERT_EQ(find_parse_type_char("s"), MDS_FTYPE_SOCK);

    ASSERT_EQ(find_parse_type_char("x"), -1);
    ASSERT_EQ(find_parse_type_char("ff"), -1);
    ASSERT_EQ(find_parse_type_char(""), -1);
    ASSERT_EQ(find_parse_type_char(NULL), -1);

    /* A regular file prints as '-', matching ls. */
    ASSERT_EQ(find_type_char(MDS_FTYPE_REG), '-');
    ASSERT_EQ(find_type_char(MDS_FTYPE_DIR), 'd');
    ASSERT_EQ(find_type_char(MDS_FTYPE_SYMLINK), 'l');
    ASSERT_EQ(find_type_char(0), '?');
    ASSERT_EQ(find_type_char(200), '?');
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * find_format_mode
 * ----------------------------------------------------------------------- */

static void test_format_mode(void)
{
    char buf[FIND_MODE_STR_LEN];

    find_format_mode(0644U, buf);
    ASSERT_STREQ(buf, "rw-r--r--");

    find_format_mode(0755U, buf);
    ASSERT_STREQ(buf, "rwxr-xr-x");

    find_format_mode(0U, buf);
    ASSERT_STREQ(buf, "---------");

    find_format_mode(0777U, buf);
    ASSERT_STREQ(buf, "rwxrwxrwx");

    /* setuid with execute set shows 's', without it 'S'. */
    find_format_mode(04755U, buf);
    ASSERT_STREQ(buf, "rwsr-xr-x");
    find_format_mode(04644U, buf);
    ASSERT_STREQ(buf, "rwSr--r--");

    /* setgid. */
    find_format_mode(02755U, buf);
    ASSERT_STREQ(buf, "rwxr-sr-x");

    /* sticky bit on a world-writable directory. */
    find_format_mode(01777U, buf);
    ASSERT_STREQ(buf, "rwxrwxrwt");
    find_format_mode(01666U, buf);
    ASSERT_STREQ(buf, "rw-rw-rwT");
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * find_name_matches
 * ----------------------------------------------------------------------- */

static void test_name_matches(void)
{
    /* A NULL glob is "no predicate" and matches anything. */
    ASSERT_TRUE(find_name_matches(NULL, "anything"));

    ASSERT_TRUE(find_name_matches("*.parquet", "big.parquet"));
    ASSERT_FALSE(find_name_matches("*.parquet", "big.parquet.tmp"));

    ASSERT_TRUE(find_name_matches("file?.txt", "file1.txt"));
    ASSERT_FALSE(find_name_matches("file?.txt", "file12.txt"));
    ASSERT_FALSE(find_name_matches("file?.txt", "file.txt"));

    ASSERT_TRUE(find_name_matches("exact", "exact"));
    ASSERT_FALSE(find_name_matches("exact", "Exact"));

    /* find(1) semantics: '*' also matches a leading dot. */
    ASSERT_TRUE(find_name_matches("*", ".hidden"));

    /* Character classes work, as they do in find(1). */
    ASSERT_TRUE(find_name_matches("log[0-9]", "log7"));
    ASSERT_FALSE(find_name_matches("log[0-9]", "logx"));

    ASSERT_FALSE(find_name_matches("*.txt", NULL));
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * find_glob_to_like
 * ----------------------------------------------------------------------- */

static void test_glob_to_like_basic(void)
{
    char out[FIND_LIKE_MAX];

    ASSERT_EQ(find_glob_to_like("*.parquet", out, sizeof(out)), 9);
    ASSERT_STREQ(out, "%.parquet");

    ASSERT_TRUE(find_glob_to_like("data*", out, sizeof(out)) > 0);
    ASSERT_STREQ(out, "data%");

    /* '?' maps to the backend's single-character wildcard. */
    ASSERT_TRUE(find_glob_to_like("file?.txt", out, sizeof(out)) > 0);
    ASSERT_STREQ(out, "file_.txt");

    /* Literal pattern: no wildcards at all. */
    ASSERT_TRUE(find_glob_to_like("report", out, sizeof(out)) > 0);
    ASSERT_STREQ(out, "report");
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_glob_to_like_collapses_wildcards(void)
{
    char out[FIND_LIKE_MAX];

    ASSERT_TRUE(find_glob_to_like("a***b", out, sizeof(out)) > 0);
    ASSERT_STREQ(out, "a%b");

    /* Only runs of '%' collapse; '_' is significant and must survive. */
    ASSERT_TRUE(find_glob_to_like("a*?*b", out, sizeof(out)) > 0);
    ASSERT_STREQ(out, "a%_%b");
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_glob_to_like_declines_when_unsafe(void)
{
    char out[FIND_LIKE_MAX];
    char big[600];

    /* '%' matches everything: no point pushing it. */
    ASSERT_EQ(find_glob_to_like("*", out, sizeof(out)), 0);
    ASSERT_EQ(find_glob_to_like("***", out, sizeof(out)), 0);

    /* '_' constrains length, so it is selective and IS pushed. */
    ASSERT_EQ(find_glob_to_like("?", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "_");
    ASSERT_EQ(find_glob_to_like("???", out, sizeof(out)), 3);
    ASSERT_STREQ(out, "___");

    /* Nothing to push. */
    ASSERT_EQ(find_glob_to_like(NULL, out, sizeof(out)), 0);
    ASSERT_EQ(find_glob_to_like("", out, sizeof(out)), 0);

    /* A backslash cannot be widened safely, so decline entirely. */
    ASSERT_EQ(find_glob_to_like("a\\*b", out, sizeof(out)), -1);

    /* Longer than the entry_name column: decline rather than truncate,
     * because a truncated pattern would be NARROWER, not wider. */
    memset(big, 'a', sizeof(big) - 1U);
    big[sizeof(big) - 1U] = '\0';
    ASSERT_EQ(find_glob_to_like(big, out, sizeof(out)), -1);

    /* Output buffer too small: also declines. */
    ASSERT_EQ(find_glob_to_like("abcdef", out, 3U), -1);
    ASSERT_EQ(find_glob_to_like("abc", NULL, 0U), -1);

    /* A bracket character class has no LIKE equivalent, so the filter
     * is declined rather than emitted as a literal '[' -- which would
     * be narrower than the glob and would drop real matches. */
    ASSERT_EQ(find_glob_to_like("log[0-9]", out, sizeof(out)), -1);
    fprintf(stdout, "PASS\n");
    passed++;
}

/*
 * The core invariant: whenever a LIKE pattern is produced, everything
 * fnmatch would accept must also be accepted by that pattern.  A
 * simplified LIKE matcher ('%' = any run, '_' = any one char) stands in
 * for the backend here.
 */
static bool like_match(const char *pat, const char *s)
{
    if (*pat == '\0') {
        return *s == '\0';
    }
    if (*pat == '%') {
        const char *t = s;

        for (;;) {
            if (like_match(pat + 1, t)) {
                return true;
            }
            if (*t == '\0') {
                return false;
            }
            t++;
        }
    }
    if (*s == '\0') {
        return false;
    }
    if (*pat == '_' || *pat == *s) {
        return like_match(pat + 1, s + 1);
    }
    return false;
}

static void test_glob_to_like_is_a_superset(void)
{
    static const char *globs[] = {
        "*.parquet", "data*", "file?.txt", "report", "a*b*c",
        "log[0-9]", "*_final.*", "x?y?z"
    };
    static const char *names[] = {
        "big.parquet", "data2024", "file1.txt", "report", "aXbYc",
        "log7", "run_final.bin", "x1y2z", ".hidden", "nomatch",
        "data", "file12.txt", "REPORT", "a.parquet"
    };
    char out[FIND_LIKE_MAX];
    size_t g;
    size_t n;

    for (g = 0U; g < sizeof(globs) / sizeof(globs[0]); g++) {
        int rc = find_glob_to_like(globs[g], out, sizeof(out));

        if (rc <= 0) {
            continue;   /* no pattern pushed: nothing to verify */
        }
        for (n = 0U; n < sizeof(names) / sizeof(names[0]); n++) {
            if (find_name_matches(globs[g], names[n])) {
                /* Anything the real predicate accepts must survive the
                 * pre-filter, or the scan would drop a genuine match. */
                ASSERT_TRUE(like_match(out, names[n]));
            }
        }
    }
    fprintf(stdout, "PASS\n");
    passed++;
}

int main(void)
{
    fprintf(stdout, "test_find_query:\n");

    test_parse_u64_accepts_valid();
    test_parse_u64_rejects_invalid();
    test_parse_size_suffixes();
    test_parse_size_rejects_overflow_and_garbage();
    test_type_char_roundtrip();
    test_format_mode();
    test_name_matches();
    test_glob_to_like_basic();
    test_glob_to_like_collapses_wildcards();
    test_glob_to_like_declines_when_unsafe();
    test_glob_to_like_is_a_superset();

    fprintf(stdout, "\n  %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
