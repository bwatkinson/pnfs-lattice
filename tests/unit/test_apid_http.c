/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * test_apid_http.c -- Unit tests for the mds-apid request surface.
 *
 * These cover the parts an unauthenticated caller can reach directly:
 * token comparison, Authorization parsing, percent-decoding, request-line
 * splitting, query validation, and the cleartext bind guard.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apid_http.h"

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
 * apid_secret_equal
 * ----------------------------------------------------------------------- */

static void test_secret_equal(void)
{
    ASSERT_TRUE(apid_secret_equal("s3cret", "s3cret"));
    ASSERT_TRUE(apid_secret_equal("", ""));

    ASSERT_FALSE(apid_secret_equal("s3cret", "s3creT"));
    ASSERT_FALSE(apid_secret_equal("s3cret", "s3cre"));
    ASSERT_FALSE(apid_secret_equal("s3cre", "s3cret"));
    /* A prefix must not be accepted: the length is part of the secret. */
    ASSERT_FALSE(apid_secret_equal("", "s3cret"));
    ASSERT_FALSE(apid_secret_equal("s3cret", ""));

    ASSERT_FALSE(apid_secret_equal(NULL, "s3cret"));
    ASSERT_FALSE(apid_secret_equal("s3cret", NULL));
    ASSERT_FALSE(apid_secret_equal(NULL, NULL));
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * apid_extract_bearer
 * ----------------------------------------------------------------------- */

static void test_extract_bearer_accepts(void)
{
    char tok[APID_TOKEN_MAX];

    ASSERT_TRUE(apid_extract_bearer(
        "\r\nHost: x\r\nAuthorization: Bearer abc123\r\n\r\n",
        tok, sizeof(tok)));
    ASSERT_STREQ(tok, "abc123");

    /* Header names are case-insensitive. */
    ASSERT_TRUE(apid_extract_bearer(
        "\r\nauthorization: bearer abc123\r\n\r\n", tok, sizeof(tok)));
    ASSERT_STREQ(tok, "abc123");

    ASSERT_TRUE(apid_extract_bearer(
        "\r\nAUTHORIZATION:   Bearer   spaced\r\n\r\n",
        tok, sizeof(tok)));
    ASSERT_STREQ(tok, "spaced");

    /* Trailing whitespace is not part of the credential. */
    ASSERT_TRUE(apid_extract_bearer(
        "\r\nAuthorization: Bearer padded   \r\n\r\n",
        tok, sizeof(tok)));
    ASSERT_STREQ(tok, "padded");

    /* Works when other headers come first and last. */
    ASSERT_TRUE(apid_extract_bearer(
        "\r\nAccept: */*\r\nAuthorization: Bearer tok\r\nX-Y: z\r\n\r\n",
        tok, sizeof(tok)));
    ASSERT_STREQ(tok, "tok");
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_extract_bearer_rejects(void)
{
    char tok[APID_TOKEN_MAX];

    /* No Authorization header at all. */
    ASSERT_FALSE(apid_extract_bearer("\r\nHost: x\r\n\r\n",
                                     tok, sizeof(tok)));
    /* Wrong scheme. */
    ASSERT_FALSE(apid_extract_bearer(
        "\r\nAuthorization: Basic dXNlcjpwdw==\r\n\r\n",
        tok, sizeof(tok)));
    /* Scheme with no token. */
    ASSERT_FALSE(apid_extract_bearer(
        "\r\nAuthorization: Bearer \r\n\r\n", tok, sizeof(tok)));
    ASSERT_FALSE(apid_extract_bearer(
        "\r\nAuthorization: Bearer\r\n\r\n", tok, sizeof(tok)));
    /* "Bearerfoo" is a different scheme, not Bearer with token "foo". */
    ASSERT_FALSE(apid_extract_bearer(
        "\r\nAuthorization: Bearerfoo\r\n\r\n", tok, sizeof(tok)));

    ASSERT_FALSE(apid_extract_bearer(NULL, tok, sizeof(tok)));
    ASSERT_FALSE(apid_extract_bearer("\r\nAuthorization: Bearer x\r\n",
                                     NULL, sizeof(tok)));
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * apid_url_decode
 * ----------------------------------------------------------------------- */

static void test_url_decode(void)
{
    char buf[128];

    strcpy(buf, "%2A.parquet");
    ASSERT_TRUE(apid_url_decode(buf));
    ASSERT_STREQ(buf, "*.parquet");

    strcpy(buf, "a+b");
    ASSERT_TRUE(apid_url_decode(buf));
    ASSERT_STREQ(buf, "a b");

    strcpy(buf, "plain");
    ASSERT_TRUE(apid_url_decode(buf));
    ASSERT_STREQ(buf, "plain");

    strcpy(buf, "%2f%3F%3f");
    ASSERT_TRUE(apid_url_decode(buf));
    ASSERT_STREQ(buf, "/??");

    /* Truncated or non-hex escapes must be rejected, not guessed at. */
    strcpy(buf, "abc%");
    ASSERT_FALSE(apid_url_decode(buf));
    strcpy(buf, "abc%2");
    ASSERT_FALSE(apid_url_decode(buf));
    strcpy(buf, "abc%zz");
    ASSERT_FALSE(apid_url_decode(buf));
    strcpy(buf, "abc%2z");
    ASSERT_FALSE(apid_url_decode(buf));

    /* An encoded NUL would silently truncate the value. */
    strcpy(buf, "abc%00def");
    ASSERT_FALSE(apid_url_decode(buf));

    ASSERT_FALSE(apid_url_decode(NULL));
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * apid_split_request_line
 * ----------------------------------------------------------------------- */

static void test_split_request_line(void)
{
    char line[256];
    char *path = NULL;
    char *query = NULL;

    strcpy(line, "GET /healthz HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_OK);
    ASSERT_STREQ(path, "/healthz");
    ASSERT_TRUE((query) == NULL);

    strcpy(line, "GET /api/v1/find?type=f&limit=10 HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_OK);
    ASSERT_STREQ(path, "/api/v1/find");
    ASSERT_STREQ(query, "type=f&limit=10");

    /* Empty query after '?' is valid and yields an empty string. */
    strcpy(line, "GET /api/v1/find? HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_OK);
    ASSERT_STREQ(path, "/api/v1/find");
    ASSERT_STREQ(query, "");

    /* Missing HTTP version still parses; the version is ignored. */
    strcpy(line, "GET /healthz");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_OK);
    ASSERT_STREQ(path, "/healthz");
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_split_request_line_rejects(void)
{
    char line[256];
    char *path = NULL;
    char *query = NULL;

    /* Only GET is served; everything else is 405, not 400. */
    strcpy(line, "POST /api/v1/find HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_BAD_METHOD);

    strcpy(line, "DELETE /api/v1/find HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_BAD_METHOD);

    /* Lowercase method: HTTP methods are case-sensitive. */
    strcpy(line, "get /healthz HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_BAD_METHOD);

    /* A path must be origin-form. */
    strcpy(line, "GET healthz HTTP/1.1");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_MALFORMED);

    strcpy(line, "GARBAGE");
    ASSERT_EQ(apid_split_request_line(line, &path, &query),
                     APID_REQ_BAD_METHOD);

    ASSERT_EQ(apid_split_request_line(NULL, &path, &query),
                     APID_REQ_MALFORMED);
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * apid_parse_query
 * ----------------------------------------------------------------------- */

static void test_parse_query_valid(void)
{
    struct find_filter f;
    char qs[256];
    const char *why = NULL;

    memset(&f, 0, sizeof(f));
    strcpy(qs, "type=f&size_gt=1024&size_lt=4096&uid=1000&gid=100&limit=50");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_EQ(f.type, MDS_FTYPE_REG);
    ASSERT_TRUE(f.has_size_min);
    ASSERT_EQ(f.size_min, 1024U);
    ASSERT_TRUE(f.has_size_max);
    ASSERT_EQ(f.size_max, 4096U);
    ASSERT_TRUE(f.has_uid);
    ASSERT_EQ(f.uid, 1000U);
    ASSERT_TRUE(f.has_gid);
    ASSERT_EQ(f.gid, 100U);
    ASSERT_EQ(f.limit, 50U);

    /* uid 0 is a real value, not "unset". */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "uid=0");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_TRUE(f.has_uid);
    ASSERT_EQ(f.uid, 0U);

    /* Percent-encoded glob. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "name=%2A.parquet");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_STREQ(f.name_glob, "*.parquet");

    /* Times are absolute epoch seconds. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "mtime_after=1750000000&ctime_before=1760000000");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_TRUE(f.has_mtime_min);
    ASSERT_TRUE(f.mtime_min == 1750000000LL);
    ASSERT_TRUE(f.has_ctime_max);
    ASSERT_TRUE(f.ctime_max == 1760000000LL);

    /* No parameters at all is a valid "match everything" query. */
    memset(&f, 0, sizeof(f));
    ASSERT_TRUE(apid_parse_query(NULL, &f, &why));
    memset(&f, 0, sizeof(f));
    strcpy(qs, "");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_parse_query_inum_range(void)
{
    struct find_filter f;
    char qs[128];
    const char *why = NULL;

    /* Exact fileid: min and max collapse to the same value. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "inum=1234");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_TRUE(f.has_inum);
    ASSERT_EQ(f.inum_min, 1234U);
    ASSERT_EQ(f.inum_max, 1234U);

    memset(&f, 0, sizeof(f));
    strcpy(qs, "inum=1000&inum_max=2000");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_EQ(f.inum_min, 1000U);
    ASSERT_EQ(f.inum_max, 2000U);

    /* Order must not matter. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "inum_max=2000&inum=1000");
    ASSERT_TRUE(apid_parse_query(qs, &f, &why));
    ASSERT_EQ(f.inum_min, 1000U);
    ASSERT_EQ(f.inum_max, 2000U);

    /* Inverted range is rejected rather than silently returning nothing. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "inum=2000&inum_max=1000");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));
    ASSERT_TRUE((why) != NULL);
    fprintf(stdout, "PASS\n");
    passed++;
}

static void test_parse_query_rejects(void)
{
    struct find_filter f;
    char qs[256];
    const char *why = NULL;

    /* An unknown parameter must fail loudly: silently ignoring a typo
     * would widen the search without the caller noticing. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "mtime_afetr=123");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    memset(&f, 0, sizeof(f));
    strcpy(qs, "type=f&bogus=1");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    /* Malformed shapes. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "type");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    /* Invalid values. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "type=z");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    memset(&f, 0, sizeof(f));
    strcpy(qs, "size_gt=abc");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    memset(&f, 0, sizeof(f));
    strcpy(qs, "size_gt=-1");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    /* Limit bounds. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "limit=0");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    memset(&f, 0, sizeof(f));
    strcpy(qs, "limit=10000001");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    /* Bad percent-encoding. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "name=%zz");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));

    /* An empty name glob is meaningless. */
    memset(&f, 0, sizeof(f));
    strcpy(qs, "name=");
    ASSERT_FALSE(apid_parse_query(qs, &f, &why));
    fprintf(stdout, "PASS\n");
    passed++;
}

/* -----------------------------------------------------------------------
 * apid_bind_allowed
 * ----------------------------------------------------------------------- */

static void test_bind_guard(void)
{
    /* Loopback in cleartext is fine. */
    ASSERT_TRUE(apid_bind_allowed("127.0.0.1", false, false));
    ASSERT_TRUE(apid_bind_allowed("127.0.0.53", false, false));

    /* Anything routable in cleartext is refused by default -- this is
     * the guard that stops an accidental --bind 0.0.0.0. */
    ASSERT_FALSE(apid_bind_allowed("0.0.0.0", false, false));
    ASSERT_FALSE(apid_bind_allowed("10.0.0.10", false, false));
    ASSERT_FALSE(apid_bind_allowed("192.168.1.5", false, false));

    /* TLS or an explicit opt-in unlocks it. */
    ASSERT_TRUE(apid_bind_allowed("0.0.0.0", true, false));
    ASSERT_TRUE(apid_bind_allowed("10.0.0.10", true, false));
    ASSERT_TRUE(apid_bind_allowed("10.0.0.10", false, true));

    /* A non-literal cannot be judged safe. */
    ASSERT_FALSE(apid_bind_allowed("localhost", false, false));
    ASSERT_FALSE(apid_bind_allowed("::1", false, false));
    ASSERT_FALSE(apid_bind_allowed(NULL, false, false));
    fprintf(stdout, "PASS\n");
    passed++;
}

int main(void)
{
    fprintf(stdout, "test_apid_http:\n");

    test_secret_equal();
    test_extract_bearer_accepts();
    test_extract_bearer_rejects();
    test_url_decode();
    test_split_request_line();
    test_split_request_line_rejects();
    test_parse_query_valid();
    test_parse_query_inum_range();
    test_parse_query_rejects();
    test_bind_guard();

    fprintf(stdout, "\n  %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
