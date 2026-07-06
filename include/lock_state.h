/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * lock_state.h -- NFSv4.1 byte-range lock manager API.
 *
 * Implements LOCK, LOCKT, LOCKU per RFC 8881 S18.10-18.12.
 * Thread-safe via striped mutexes.
 */

#ifndef LOCK_STATE_H
#define LOCK_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include "compound.h"   /* struct nfs4_stateid */

/* RFC 8881 lock types */
#define READ_LT          1
#define WRITE_LT         2
#define READW_LT         3   /* blocking read (not implemented -- treated as READ_LT) */
#define WRITEW_LT        4   /* blocking write (treated as WRITE_LT) */

#define LOCK_OWNER_MAX  128

/** Information about a conflicting lock (for DENIED response). */
struct lock_conflict {
    uint64_t offset;
    uint64_t length;
    uint32_t lock_type;
    uint64_t clientid;
    uint8_t  owner[LOCK_OWNER_MAX];
    uint32_t owner_len;
};

struct lock_table;  /* Opaque */
struct mds_catalogue;

/**
 * Initialise the lock table.
 * @param mds_id  MDS node ID (for lock stateid generation).
 * @param out     Receives the lock table handle.
 * @return 0 on success, -1 on allocation failure.
 */
int lock_table_init(uint32_t mds_id, struct lock_table **out);

/** Destroy the lock table and free all state. */
void lock_table_destroy(struct lock_table *lt);

/** Attach catalogue for RonDB-backed shared lock state. */
void lock_table_set_cat(struct lock_table *lt,
                        struct mds_catalogue *cat,
                        uint64_t boot_epoch);

/**
 * Acquire a byte-range lock (RFC 8881 S18.10).
 *
 * One lock stateid exists per (fileid, clientid, lock-owner): the
 * first LOCK by an owner (new_lock_owner=true) creates the owner
 * state and mints its stateid; every further LOCK by that owner
 * returns the SAME stateid `other` with seqid incremented.  A lock
 * that overlaps the same owner's existing ranges REPLACES the
 * overlap (POSIX upgrade/downgrade with range splitting).
 *
 * @param lt             Lock table.
 * @param fileid         Target file.
 * @param lock_type      READ_LT or WRITE_LT (blocking variants are
 *                       normalized).
 * @param offset         Lock range start.
 * @param length         Lock range length (0 or UINT64_MAX = to EOF).
 * @param clientid       Owning client.
 * @param owner          Lock owner opaque (new_lock_owner arm only;
 *                       the existing-owner wire arm carries no owner).
 * @param owner_len      Lock owner length.
 * @param open_stateid   Associated open stateid (new lock-owner).
 * @param new_lock_owner Wire locker discriminant: true = open_to_
 *                       lock_owner4 (identify by clientid+owner),
 *                       false = exist_lock_owner4 (identify by the
 *                       presented lock stateid in @p lock_stateid).
 * @param lock_stateid   In: presented lock stateid (existing-owner
 *                       arm; seqid validated).  Out: granted stateid.
 * @param conflict       Out: filled if NFS4ERR_DENIED.
 * @return 0 on success; NFS4ERR_DENIED on conflict;
 *         NFS4ERR_BAD_STATEID / NFS4ERR_OLD_STATEID on stateid
 *         mismatch; NFS4ERR_INVAL on bad args; negative on internal
 *         error.
 */
int lock_acquire(struct lock_table *lt,
                 uint64_t fileid, uint32_t lock_type,
                 uint64_t offset, uint64_t length,
                 uint64_t clientid,
                 const uint8_t *owner, uint32_t owner_len,
                 const struct nfs4_stateid *open_stateid,
                 bool new_lock_owner,
                 struct nfs4_stateid *lock_stateid,
                 struct lock_conflict *conflict);

/**
 * Test whether a lock would succeed (LOCKT).
 * @return 0 if lock would succeed, NFS4ERR_DENIED + conflict info.
 */
int lock_test(struct lock_table *lt,
              uint64_t fileid, uint32_t lock_type,
              uint64_t offset, uint64_t length,
              uint64_t clientid,
              const uint8_t *owner, uint32_t owner_len,
              struct lock_conflict *conflict);

/**
 * Release a byte range (LOCKU, RFC 8881 S18.12).
 *
 * Removes ONLY [offset, offset+length) from the owner state named
 * by @p lock_stateid, splitting held ranges when the unlock punches
 * a hole.  The owner state survives its last range (release it via
 * lock_free_stateid).  The stateid seqid increments on success.
 *
 * @param lt            Lock table.
 * @param lock_stateid  In: presented lock stateid (seqid checked).
 *                      Out: updated stateid (seqid incremented).
 * @param lock_type     Ignored (RFC 8881 S18.12).
 * @param offset        Range start.
 * @param length        Range length (0 or UINT64_MAX = to EOF).
 * @return 0 on success, NFS4ERR_BAD_STATEID / NFS4ERR_OLD_STATEID,
 *         or negative on internal error.
 */
int lock_release(struct lock_table *lt,
                 struct nfs4_stateid *lock_stateid,
                 uint32_t lock_type,
                 uint64_t offset, uint64_t length);

/**
 * Free a lock-owner stateid (FREE_STATEID, RFC 8881 S18.38).
 *
 * @return 0 when the (rangeless) owner state was released;
 *         NFS4ERR_LOCKS_HELD when ranges are still held;
 *         NFS4ERR_BAD_STATEID when the stateid names no owner state.
 */
int lock_free_stateid(struct lock_table *lt,
                      const uint8_t other[NFS4_OTHER_SIZE]);

/**
 * Release all locks held by a client (for lease expiry cleanup).
 */
void lock_release_all_for_client(struct lock_table *lt, uint64_t clientid);

/** Check if a lock stateid exists (for TEST_STATEID). */
bool lock_state_exists(const struct lock_table *lt,
                       const uint8_t other[NFS4_OTHER_SIZE]);

struct session_table;

/**
 * Revoke locks on @fileid held by clients whose lease has expired.
 * RFC 8881 §8.4.3 courtesy-client support.  Pynfs COUR2.
 *
 * @return Number of lock entries revoked.
 */
int lock_revoke_expired_for_file(struct lock_table *lt,
                                 struct session_table *st,
                                 uint64_t fileid);

#endif /* LOCK_STATE_H */
