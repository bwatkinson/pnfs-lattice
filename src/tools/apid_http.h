/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * apid_http.h -- Request parsing, authentication, and query mapping for
 * the mds-apid service.
 *
 * These are the security-relevant, pure parts of the service: token
 * comparison, header extraction, percent-decoding, request-line
 * splitting, and query-parameter validation.  They are deliberately kept
 * free of sockets and catalogue state so they can be unit-tested
 * directly; see tests/unit/test_apid_http.c.
 *
 * NOT a public API header.  Included only by mds_apid.c and its tests.
 */

#ifndef APID_HTTP_H
#define APID_HTTP_H

#include <stdbool.h>
#include <stddef.h>

#include "find_query.h"

/** Longest accepted bearer token, including the NUL terminator. */
#define APID_TOKEN_MAX 512U

/** Outcome of parsing a request line. */
enum apid_request_status {
    APID_REQ_OK = 0,        /**< Usable GET request. */
    APID_REQ_MALFORMED,     /**< Answer 400. */
    APID_REQ_BAD_METHOD     /**< Answer 405. */
};

/**
 * Compare two NUL-terminated secrets without leaking length or content
 * through timing.
 *
 * The loop always runs a fixed number of iterations, so the time taken
 * does not depend on where the first differing byte is.
 *
 * @param a  First secret (NULL is treated as no match).
 * @param b  Second secret (NULL is treated as no match).
 * @return true when both are non-NULL and equal.
 */
bool apid_secret_equal(const char *a, const char *b);

/**
 * Extract a bearer token from an HTTP header block.
 *
 * Matching is case-insensitive on the header name, per RFC 7230.
 *
 * @param headers  Header block starting at the CRLF that terminates the
 *                 request line, NUL-terminated.  Must NOT have had NUL
 *                 bytes written into it by request-line splitting.
 * @param out      Receives the token, always NUL-terminated when cap > 0.
 * @param cap      Capacity of @p out.
 * @return true when a non-empty bearer token was found.
 */
bool apid_extract_bearer(const char *headers, char *out, size_t cap);

/**
 * Percent-decode a string in place, also mapping '+' to a space.
 *
 * @param s  String to decode (modified in place; never grows).
 * @return true on success, false on a truncated or non-hex escape, in
 *         which case @p s may be partially decoded and must be discarded.
 */
bool apid_url_decode(char *s);

/**
 * Split a request line in place.
 *
 * @param line   Request line without its trailing CRLF, NUL-terminated.
 *               Modified in place: NULs are written at the path end and
 *               at the '?' separator.
 * @param path   Receives the request path.
 * @param query  Receives the query string, or NULL when there is none.
 * @return APID_REQ_OK, or the status the caller should answer with.
 */
enum apid_request_status apid_split_request_line(char *line, char **path,
                                                 char **query);

/**
 * Map a query string onto a search filter.
 *
 * Unknown parameters are rejected rather than ignored, so a typo such as
 * "mtime_afetr" fails loudly instead of silently widening the search.
 *
 * @param qs   Query string, modified in place (decoded and NUL-split).
 *             The filter borrows pointers into it, so @p qs must outlive
 *             any use of @p f.  May be NULL for "no parameters".
 * @param f    Filter to populate (must be zeroed by the caller).
 * @param why  Receives a short, client-safe reason on failure.
 * @return true when every parameter was recognised and valid.
 */
bool apid_parse_query(char *qs, struct find_filter *f, const char **why);

/**
 * Decide whether a listen address may be served without TLS.
 *
 * Cleartext is allowed on loopback, or anywhere the operator has
 * explicitly opted in.  Anything else is refused so an accidental
 * --bind 0.0.0.0 cannot expose the catalogue to the network.
 *
 * @param bind_addr    IPv4 literal to bind.
 * @param tls_enabled  Whether the service terminates TLS itself.
 * @param insecure     Whether the operator passed --insecure.
 * @return true when the combination is safe to serve.
 */
bool apid_bind_allowed(const char *bind_addr, bool tls_enabled,
                       bool insecure);

#endif /* APID_HTTP_H */
