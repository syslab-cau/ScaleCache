// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_TRANS_PRIV_H__
#define	__SCXFS_TRANS_PRIV_H__

struct scxfs_log_item;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_ail;
struct scxfs_log_vec;


void	scxfs_trans_init(struct scxfs_mount *);
void	scxfs_trans_add_item(struct scxfs_trans *, struct scxfs_log_item *);
void	scxfs_trans_del_item(struct scxfs_log_item *);
void	scxfs_trans_unreserve_and_mod_sb(struct scxfs_trans *tp);

void	scxfs_trans_committed_bulk(struct scxfs_ail *ailp, struct scxfs_log_vec *lv,
				scxfs_lsn_t commit_lsn, bool aborted);
/*
 * AIL traversal cursor.
 *
 * Rather than using a generation number for detecting changes in the ail, use
 * a cursor that is protected by the ail lock. The aild cursor exists in the
 * struct scxfs_ail, but other traversals can declare it on the stack and link it
 * to the ail list.
 *
 * When an object is deleted from or moved int the AIL, the cursor list is
 * searched to see if the object is a designated cursor item. If it is, it is
 * deleted from the cursor so that the next time the cursor is used traversal
 * will return to the start.
 *
 * This means a traversal colliding with a removal will cause a restart of the
 * list scan, rather than any insertion or deletion anywhere in the list. The
 * low bit of the item pointer is set if the cursor has been invalidated so
 * that we can tell the difference between invalidation and reaching the end
 * of the list to trigger traversal restarts.
 */
struct scxfs_ail_cursor {
	struct list_head	list;
	struct scxfs_log_item	*item;
};

/*
 * Private AIL structures.
 *
 * Eventually we need to drive the locking in here as well.
 */
struct scxfs_ail {
	struct scxfs_mount	*ail_mount;
	struct task_struct	*ail_task;
	struct list_head	ail_head;
	scxfs_lsn_t		ail_target;
	scxfs_lsn_t		ail_target_prev;
	struct list_head	ail_cursors;
	spinlock_t		ail_lock;
	scxfs_lsn_t		ail_last_pushed_lsn;
	int			ail_log_flush;
	struct list_head	ail_buf_list;
	wait_queue_head_t	ail_empty;
};

/*
 * From scxfs_trans_ail.c
 */
void	scxfs_trans_ail_update_bulk(struct scxfs_ail *ailp,
				struct scxfs_ail_cursor *cur,
				struct scxfs_log_item **log_items, int nr_items,
				scxfs_lsn_t lsn) __releases(ailp->ail_lock);
/*
 * Return a pointer to the first item in the AIL.  If the AIL is empty, then
 * return NULL.
 */
static inline struct scxfs_log_item *
scxfs_ail_min(
	struct scxfs_ail  *ailp)
{
	return list_first_entry_or_null(&ailp->ail_head, struct scxfs_log_item,
					li_ail);
}

static inline void
scxfs_trans_ail_update(
	struct scxfs_ail		*ailp,
	struct scxfs_log_item	*lip,
	scxfs_lsn_t		lsn) __releases(ailp->ail_lock)
{
	scxfs_trans_ail_update_bulk(ailp, NULL, &lip, 1, lsn);
}

bool scxfs_ail_delete_one(struct scxfs_ail *ailp, struct scxfs_log_item *lip);
void scxfs_trans_ail_delete(struct scxfs_ail *ailp, struct scxfs_log_item *lip,
		int shutdown_type) __releases(ailp->ail_lock);

static inline void
scxfs_trans_ail_remove(
	struct scxfs_log_item	*lip,
	int			shutdown_type)
{
	struct scxfs_ail		*ailp = lip->li_ailp;

	spin_lock(&ailp->ail_lock);
	/* scxfs_trans_ail_delete() drops the AIL lock */
	if (test_bit(SCXFS_LI_IN_AIL, &lip->li_flags))
		scxfs_trans_ail_delete(ailp, lip, shutdown_type);
	else
		spin_unlock(&ailp->ail_lock);
}

void			scxfs_ail_push(struct scxfs_ail *, scxfs_lsn_t);
void			scxfs_ail_push_all(struct scxfs_ail *);
void			scxfs_ail_push_all_sync(struct scxfs_ail *);
struct scxfs_log_item	*scxfs_ail_min(struct scxfs_ail  *ailp);
scxfs_lsn_t		scxfs_ail_min_lsn(struct scxfs_ail *ailp);

struct scxfs_log_item *	scxfs_trans_ail_cursor_first(struct scxfs_ail *ailp,
					struct scxfs_ail_cursor *cur,
					scxfs_lsn_t lsn);
struct scxfs_log_item *	scxfs_trans_ail_cursor_last(struct scxfs_ail *ailp,
					struct scxfs_ail_cursor *cur,
					scxfs_lsn_t lsn);
struct scxfs_log_item *	scxfs_trans_ail_cursor_next(struct scxfs_ail *ailp,
					struct scxfs_ail_cursor *cur);
void			scxfs_trans_ail_cursor_done(struct scxfs_ail_cursor *cur);

#if BITS_PER_LONG != 64
static inline void
scxfs_trans_ail_copy_lsn(
	struct scxfs_ail	*ailp,
	scxfs_lsn_t	*dst,
	scxfs_lsn_t	*src)
{
	ASSERT(sizeof(scxfs_lsn_t) == 8);	/* don't lock if it shrinks */
	spin_lock(&ailp->ail_lock);
	*dst = *src;
	spin_unlock(&ailp->ail_lock);
}
#else
static inline void
scxfs_trans_ail_copy_lsn(
	struct scxfs_ail	*ailp,
	scxfs_lsn_t	*dst,
	scxfs_lsn_t	*src)
{
	ASSERT(sizeof(scxfs_lsn_t) == 8);
	*dst = *src;
}
#endif

static inline void
scxfs_clear_li_failed(
	struct scxfs_log_item	*lip)
{
	struct scxfs_buf	*bp = lip->li_buf;

	ASSERT(test_bit(SCXFS_LI_IN_AIL, &lip->li_flags));
	lockdep_assert_held(&lip->li_ailp->ail_lock);

	if (test_and_clear_bit(SCXFS_LI_FAILED, &lip->li_flags)) {
		lip->li_buf = NULL;
		scxfs_buf_rele(bp);
	}
}

static inline void
scxfs_set_li_failed(
	struct scxfs_log_item	*lip,
	struct scxfs_buf		*bp)
{
	lockdep_assert_held(&lip->li_ailp->ail_lock);

	if (!test_and_set_bit(SCXFS_LI_FAILED, &lip->li_flags)) {
		scxfs_buf_hold(bp);
		lip->li_buf = bp;
	}
}

#endif	/* __SCXFS_TRANS_PRIV_H__ */
