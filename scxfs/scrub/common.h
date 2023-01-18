// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_SCRUB_COMMON_H__
#define __SCXFS_SCRUB_COMMON_H__

/*
 * We /could/ terminate a scrub/repair operation early.  If we're not
 * in a good place to continue (fatal signal, etc.) then bail out.
 * Note that we're careful not to make any judgements about *error.
 */
static inline bool
xchk_should_terminate(
	struct scxfs_scrub	*sc,
	int			*error)
{
	/*
	 * If preemption is disabled, we need to yield to the scheduler every
	 * few seconds so that we don't run afoul of the soft lockup watchdog
	 * or RCU stall detector.
	 */
	cond_resched();

	if (fatal_signal_pending(current)) {
		if (*error == 0)
			*error = -EAGAIN;
		return true;
	}
	return false;
}

int xchk_trans_alloc(struct scxfs_scrub *sc, uint resblks);
bool xchk_process_error(struct scxfs_scrub *sc, scxfs_agnumber_t agno,
		scxfs_agblock_t bno, int *error);
bool xchk_fblock_process_error(struct scxfs_scrub *sc, int whichfork,
		scxfs_fileoff_t offset, int *error);

bool xchk_xref_process_error(struct scxfs_scrub *sc,
		scxfs_agnumber_t agno, scxfs_agblock_t bno, int *error);
bool xchk_fblock_xref_process_error(struct scxfs_scrub *sc,
		int whichfork, scxfs_fileoff_t offset, int *error);

void xchk_block_set_preen(struct scxfs_scrub *sc,
		struct scxfs_buf *bp);
void xchk_ino_set_preen(struct scxfs_scrub *sc, scxfs_ino_t ino);

void xchk_set_corrupt(struct scxfs_scrub *sc);
void xchk_block_set_corrupt(struct scxfs_scrub *sc,
		struct scxfs_buf *bp);
void xchk_ino_set_corrupt(struct scxfs_scrub *sc, scxfs_ino_t ino);
void xchk_fblock_set_corrupt(struct scxfs_scrub *sc, int whichfork,
		scxfs_fileoff_t offset);

void xchk_block_xref_set_corrupt(struct scxfs_scrub *sc,
		struct scxfs_buf *bp);
void xchk_ino_xref_set_corrupt(struct scxfs_scrub *sc,
		scxfs_ino_t ino);
void xchk_fblock_xref_set_corrupt(struct scxfs_scrub *sc,
		int whichfork, scxfs_fileoff_t offset);

void xchk_ino_set_warning(struct scxfs_scrub *sc, scxfs_ino_t ino);
void xchk_fblock_set_warning(struct scxfs_scrub *sc, int whichfork,
		scxfs_fileoff_t offset);

void xchk_set_incomplete(struct scxfs_scrub *sc);
int xchk_checkpoint_log(struct scxfs_mount *mp);

/* Are we set up for a cross-referencing check? */
bool xchk_should_check_xref(struct scxfs_scrub *sc, int *error,
			   struct scxfs_btree_cur **curpp);

/* Setup functions */
int xchk_setup_fs(struct scxfs_scrub *sc, struct scxfs_inode *ip);
int xchk_setup_ag_allocbt(struct scxfs_scrub *sc,
			       struct scxfs_inode *ip);
int xchk_setup_ag_iallocbt(struct scxfs_scrub *sc,
				struct scxfs_inode *ip);
int xchk_setup_ag_rmapbt(struct scxfs_scrub *sc,
			      struct scxfs_inode *ip);
int xchk_setup_ag_refcountbt(struct scxfs_scrub *sc,
				  struct scxfs_inode *ip);
int xchk_setup_inode(struct scxfs_scrub *sc,
			  struct scxfs_inode *ip);
int xchk_setup_inode_bmap(struct scxfs_scrub *sc,
			       struct scxfs_inode *ip);
int xchk_setup_inode_bmap_data(struct scxfs_scrub *sc,
				    struct scxfs_inode *ip);
int xchk_setup_directory(struct scxfs_scrub *sc,
			      struct scxfs_inode *ip);
int xchk_setup_xattr(struct scxfs_scrub *sc,
			  struct scxfs_inode *ip);
int xchk_setup_symlink(struct scxfs_scrub *sc,
			    struct scxfs_inode *ip);
int xchk_setup_parent(struct scxfs_scrub *sc,
			   struct scxfs_inode *ip);
#ifdef CONFIG_XFS_RT
int xchk_setup_rt(struct scxfs_scrub *sc, struct scxfs_inode *ip);
#else
static inline int
xchk_setup_rt(struct scxfs_scrub *sc, struct scxfs_inode *ip)
{
	return -ENOENT;
}
#endif
#ifdef CONFIG_XFS_QUOTA
int xchk_setup_quota(struct scxfs_scrub *sc, struct scxfs_inode *ip);
#else
static inline int
xchk_setup_quota(struct scxfs_scrub *sc, struct scxfs_inode *ip)
{
	return -ENOENT;
}
#endif
int xchk_setup_fscounters(struct scxfs_scrub *sc, struct scxfs_inode *ip);

void xchk_ag_free(struct scxfs_scrub *sc, struct xchk_ag *sa);
int xchk_ag_init(struct scxfs_scrub *sc, scxfs_agnumber_t agno,
		struct xchk_ag *sa);
void xchk_perag_get(struct scxfs_mount *mp, struct xchk_ag *sa);
int xchk_ag_read_headers(struct scxfs_scrub *sc, scxfs_agnumber_t agno,
		struct scxfs_buf **agi, struct scxfs_buf **agf,
		struct scxfs_buf **agfl);
void xchk_ag_btcur_free(struct xchk_ag *sa);
int xchk_ag_btcur_init(struct scxfs_scrub *sc, struct xchk_ag *sa);
int xchk_count_rmap_ownedby_ag(struct scxfs_scrub *sc, struct scxfs_btree_cur *cur,
		const struct scxfs_owner_info *oinfo, scxfs_filblks_t *blocks);

int xchk_setup_ag_btree(struct scxfs_scrub *sc, struct scxfs_inode *ip,
		bool force_log);
int xchk_get_inode(struct scxfs_scrub *sc, struct scxfs_inode *ip_in);
int xchk_setup_inode_contents(struct scxfs_scrub *sc, struct scxfs_inode *ip,
		unsigned int resblks);
void xchk_buffer_recheck(struct scxfs_scrub *sc, struct scxfs_buf *bp);

/*
 * Don't bother cross-referencing if we already found corruption or cross
 * referencing discrepancies.
 */
static inline bool xchk_skip_xref(struct scxfs_scrub_metadata *sm)
{
	return sm->sm_flags & (SCXFS_SCRUB_OFLAG_CORRUPT |
			       SCXFS_SCRUB_OFLAG_XCORRUPT);
}

int xchk_metadata_inode_forks(struct scxfs_scrub *sc);
int xchk_ilock_inverted(struct scxfs_inode *ip, uint lock_mode);
void xchk_stop_reaping(struct scxfs_scrub *sc);
void xchk_start_reaping(struct scxfs_scrub *sc);

#endif	/* __SCXFS_SCRUB_COMMON_H__ */
