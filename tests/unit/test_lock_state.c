/*
 * Copyright (c) 2026 PeakAIO
 * SPDX-License-Identifier: MIT
 *
 * test_lock_state.c -- byte-range lock manager lifecycle tests.
 *
 * Drives lock_acquire / lock_test / lock_release / lock_free_stateid
 * directly (no catalogue attached, so persistence is skipped) and
 * verifies the RFC 8881 per-lock-owner stateid lifecycle:
 *
 *   - one stateid per (fileid, clientid, owner); `other` stable,
 *     seqid incremented on every successful LOCK / LOCKU,
 *   - existing-owner LOCKs resolved by the presented stateid,
 *   - POSIX range replace / split semantics,
 *   - conflicts only across DIFFERENT owners (including two owners
 *     on the same clientid),
 *   - FREE_STATEID releases rangeless owner states only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pnfs_mds.h"
#include "lock_state.h"

static int tests_run;
static int tests_passed;
static int tests_failed;

#define ASSERT_EQ(a, b) do {						\
	if ((a) != (b)) {						\
		fprintf(stderr, "  FAIL %s:%d: %s (%lld) != %s (%lld)\n",\
			__FILE__, __LINE__,				\
			#a, (long long)(a), #b, (long long)(b));	\
		tests_failed++;						\
		return;							\
	}								\
} while (0)

#define ASSERT_TRUE(x) do {						\
	if (!(x)) {							\
		fprintf(stderr, "  FAIL %s:%d: %s is false\n",		\
			__FILE__, __LINE__, #x);			\
		tests_failed++;						\
		return;							\
	}								\
} while (0)

#define RUN_TEST(fn) do {						\
	int _fail_before = tests_failed;				\
	tests_run++;							\
	fprintf(stdout, "  %-48s", #fn);				\
	fflush(stdout);							\
	fn();								\
	if (tests_failed == _fail_before) {				\
		tests_passed++;						\
		fprintf(stdout, "PASS\n");				\
	}								\
} while (0)

#define CID_A  0x1000000000001ULL
#define CID_B  0x2000000000002ULL

static const uint8_t OWNER_A[] = { 'o', 'w', 'n', 'A' };
static const uint8_t OWNER_B[] = { 'o', 'w', 'n', 'B' };

/** Convenience wrapper: LOCK by a (possibly new) owner. */
static int do_lock(struct lock_table *lt, uint64_t fileid,
		   uint32_t type, uint64_t off, uint64_t len,
		   uint64_t cid, const uint8_t *owner, uint32_t olen,
		   bool new_owner, struct nfs4_stateid *sid,
		   struct lock_conflict *conf)
{
	return lock_acquire(lt, fileid, type, off, len, cid,
			    owner, olen, NULL, new_owner, sid, conf);
}

static void test_new_owner_grant_seqid_one(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid, 0, sizeof(sid));

	ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 0, 10,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid, NULL), 0);
	ASSERT_EQ(sid.seqid, 1u);
	ASSERT_TRUE(lock_state_exists(lt, sid.other));

	lock_table_destroy(lt);
}

static void test_same_owner_lock_keeps_other_bumps_seqid(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid, sid2;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid, 0, sizeof(sid));

	ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 0, 10,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid, NULL), 0);
	ASSERT_EQ(sid.seqid, 1u);

	/* Second range on the same owner: existing-owner arm carries
	 * ONLY the stateid on the wire. */
	sid2 = sid;
	ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 20, 10,
			  CID_A, NULL, 0,
			  false, &sid2, NULL), 0);
	ASSERT_EQ(sid2.seqid, 2u);
	ASSERT_EQ(memcmp(sid2.other, sid.other, NFS4_OTHER_SIZE), 0);

	lock_table_destroy(lt);
}

static void test_existing_owner_bad_stateid(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid, bogus;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid, 0, sizeof(sid));

	ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 0, 10,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid, NULL), 0);

	/* Unknown stateid on the existing-owner arm -> BAD_STATEID. */
	memset(&bogus, 0xab, sizeof(bogus));
	ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 20, 10,
			  CID_A, NULL, 0,
			  false, &bogus, NULL), NFS4ERR_BAD_STATEID);

	/* Stale seqid -> OLD_STATEID. */
	{
		struct nfs4_stateid stale = sid;
		struct nfs4_stateid cur = sid;

		ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 20, 10,
				  CID_A, NULL, 0,
				  false, &cur, NULL), 0);
		ASSERT_EQ(cur.seqid, 2u);
		/* stale still carries seqid 1. */
		ASSERT_EQ(do_lock(lt, 100, WRITE_LT, 40, 10,
				  CID_A, NULL, 0,
				  false, &stale, NULL),
			  NFS4ERR_OLD_STATEID);
	}

	lock_table_destroy(lt);
}

static void test_cross_owner_conflict_same_client(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid_a, sid_b;
	struct lock_conflict conf;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid_a, 0, sizeof(sid_a));
	memset(&sid_b, 0, sizeof(sid_b));
	memset(&conf, 0, sizeof(conf));

	ASSERT_EQ(do_lock(lt, 200, WRITE_LT, 0, 100,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid_a, NULL), 0);

	/* Different owner, SAME clientid (two processes on one
	 * client): write locks must conflict. */
	ASSERT_EQ(do_lock(lt, 200, WRITE_LT, 50, 10,
			  CID_A, OWNER_B, sizeof(OWNER_B),
			  true, &sid_b, &conf), NFS4ERR_DENIED);
	ASSERT_EQ(conf.clientid, CID_A);
	ASSERT_EQ(conf.offset, 0u);
	ASSERT_EQ(conf.length, 100u);
	ASSERT_EQ(conf.lock_type, (uint32_t)WRITE_LT);

	/* LOCKT sees the same conflict. */
	ASSERT_EQ(lock_test(lt, 200, WRITE_LT, 50, 10,
			    CID_A, OWNER_B, sizeof(OWNER_B), &conf),
		  NFS4ERR_DENIED);
	/* ...and reports none for the holder itself. */
	ASSERT_EQ(lock_test(lt, 200, WRITE_LT, 50, 10,
			    CID_A, OWNER_A, sizeof(OWNER_A), NULL), 0);

	/* Read/read across owners does not conflict. */
	ASSERT_EQ(do_lock(lt, 201, READ_LT, 0, 100,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid_a, NULL), 0);
	ASSERT_EQ(do_lock(lt, 201, READ_LT, 0, 100,
			  CID_B, OWNER_B, sizeof(OWNER_B),
			  true, &sid_b, NULL), 0);

	lock_table_destroy(lt);
}

static void test_partial_unlock_splits_range(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid_a, sid_b;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid_a, 0, sizeof(sid_a));
	memset(&sid_b, 0, sizeof(sid_b));

	/* Owner A holds [0, 100). */
	ASSERT_EQ(do_lock(lt, 300, WRITE_LT, 0, 100,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid_a, NULL), 0);

	/* Unlock the middle [40, 50): punches a hole. */
	ASSERT_EQ(lock_release(lt, &sid_a, 0, 40, 10), 0);
	ASSERT_EQ(sid_a.seqid, 2u);

	/* Owner B fits into the hole... */
	ASSERT_EQ(do_lock(lt, 300, WRITE_LT, 40, 10,
			  CID_B, OWNER_B, sizeof(OWNER_B),
			  true, &sid_b, NULL), 0);
	/* ...but still conflicts with the remainders. */
	{
		struct nfs4_stateid tmp;
		memset(&tmp, 0, sizeof(tmp));
		ASSERT_EQ(do_lock(lt, 300, WRITE_LT, 35, 4,
				  CID_B, OWNER_B, sizeof(OWNER_B),
				  false, &sid_b, NULL),
			  NFS4ERR_DENIED);
		(void)tmp;
	}
	{
		struct nfs4_stateid sid_b2 = sid_b;
		ASSERT_EQ(do_lock(lt, 300, WRITE_LT, 50, 4,
				  CID_B, NULL, 0,
				  false, &sid_b2, NULL),
			  NFS4ERR_DENIED);
	}

	lock_table_destroy(lt);
}

static void test_same_owner_overlap_replaces(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid_a, sid_b;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid_a, 0, sizeof(sid_a));
	memset(&sid_b, 0, sizeof(sid_b));

	/* WRITE [0,100), then downgrade the middle to READ. */
	ASSERT_EQ(do_lock(lt, 400, WRITE_LT, 0, 100,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid_a, NULL), 0);
	ASSERT_EQ(do_lock(lt, 400, READ_LT, 40, 20,
			  CID_A, NULL, 0,
			  false, &sid_a, NULL), 0);
	ASSERT_EQ(sid_a.seqid, 2u);

	/* Another owner can now READ the downgraded window... */
	ASSERT_EQ(do_lock(lt, 400, READ_LT, 45, 5,
			  CID_B, OWNER_B, sizeof(OWNER_B),
			  true, &sid_b, NULL), 0);
	/* ...but not the surrounding WRITE regions. */
	{
		struct nfs4_stateid sid_b2 = sid_b;
		ASSERT_EQ(do_lock(lt, 400, READ_LT, 30, 5,
				  CID_B, NULL, 0,
				  false, &sid_b2, NULL),
			  NFS4ERR_DENIED);
	}

	lock_table_destroy(lt);
}

static void test_free_stateid_lifecycle(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid, 0, sizeof(sid));

	ASSERT_EQ(do_lock(lt, 500, WRITE_LT, 0, 10,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid, NULL), 0);

	/* Ranges still held -> LOCKS_HELD. */
	ASSERT_EQ(lock_free_stateid(lt, sid.other), NFS4ERR_LOCKS_HELD);

	/* Full unlock: state survives (TEST_STATEID still OK). */
	ASSERT_EQ(lock_release(lt, &sid, 0, 0, 10), 0);
	ASSERT_TRUE(lock_state_exists(lt, sid.other));

	/* Now FREE succeeds and the stateid is gone. */
	ASSERT_EQ(lock_free_stateid(lt, sid.other), 0);
	ASSERT_TRUE(!lock_state_exists(lt, sid.other));
	ASSERT_EQ(lock_free_stateid(lt, sid.other), NFS4ERR_BAD_STATEID);

	lock_table_destroy(lt);
}

static void test_release_all_for_client(void)
{
	struct lock_table *lt = NULL;
	struct nfs4_stateid sid_a, sid_b;

	ASSERT_EQ(lock_table_init(1, &lt), 0);
	memset(&sid_a, 0, sizeof(sid_a));
	memset(&sid_b, 0, sizeof(sid_b));

	ASSERT_EQ(do_lock(lt, 600, WRITE_LT, 0, 10,
			  CID_A, OWNER_A, sizeof(OWNER_A),
			  true, &sid_a, NULL), 0);
	ASSERT_EQ(do_lock(lt, 601, WRITE_LT, 0, 10,
			  CID_B, OWNER_B, sizeof(OWNER_B),
			  true, &sid_b, NULL), 0);

	lock_release_all_for_client(lt, CID_A);
	ASSERT_TRUE(!lock_state_exists(lt, sid_a.other));
	ASSERT_TRUE(lock_state_exists(lt, sid_b.other));

	lock_table_destroy(lt);
}

int main(void)
{
	fprintf(stdout, "Running lock_state lifecycle tests:\n");

	RUN_TEST(test_new_owner_grant_seqid_one);
	RUN_TEST(test_same_owner_lock_keeps_other_bumps_seqid);
	RUN_TEST(test_existing_owner_bad_stateid);
	RUN_TEST(test_cross_owner_conflict_same_client);
	RUN_TEST(test_partial_unlock_splits_range);
	RUN_TEST(test_same_owner_overlap_replaces);
	RUN_TEST(test_free_stateid_lifecycle);
	RUN_TEST(test_release_all_for_client);

	fprintf(stdout, "\n%d/%d tests passed.\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
