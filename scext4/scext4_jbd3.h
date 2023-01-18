// SPDX-License-Identifier: GPL-2.0+
/*
 * scext4_jbd3.h
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1998--1999 Red Hat corp --- All Rights Reserved
 *
 * Ext4-specific journaling extensions.
 */

#ifndef _SCEXT4_JBD3_H
#define _SCEXT4_JBD3_H

#include <linux/fs.h>
#include <linux/jbd3.h>
#include "scext4.h"

#define SCEXT4_JOURNAL(inode)	(SCEXT4_SB((inode)->i_sb)->s_journal)

/* Define the number of blocks we need to account to a transaction to
 * modify one block of data.
 *
 * We may have to touch one inode, one bitmap buffer, up to three
 * indirection blocks, the group and superblock summaries, and the data
 * block to complete the transaction.
 *
 * For extents-enabled fs we may have to allocate and modify up to
 * 5 levels of tree, data block (for each of these we need bitmap + group
 * summaries), root which is stored in the inode, sb
 */

#define SCEXT4_SINGLEDATA_TRANS_BLOCKS(sb)				\
	(scext4_has_feature_extents(sb) ? 20U : 8U)

/* Extended attribute operations touch at most two data buffers,
 * two bitmap buffers, and two group summaries, in addition to the inode
 * and the superblock, which are already accounted for. */

#define SCEXT4_XATTR_TRANS_BLOCKS		6U

/* Define the minimum size for a transaction which modifies data.  This
 * needs to take into account the fact that we may end up modifying two
 * quota files too (one for the group, one for the user quota).  The
 * superblock only gets updated once, of course, so don't bother
 * counting that again for the quota updates. */

#define SCEXT4_DATA_TRANS_BLOCKS(sb)	(SCEXT4_SINGLEDATA_TRANS_BLOCKS(sb) + \
					 SCEXT4_XATTR_TRANS_BLOCKS - 2 + \
					 SCEXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

/*
 * Define the number of metadata blocks we need to account to modify data.
 *
 * This include super block, inode block, quota blocks and xattr blocks
 */
#define SCEXT4_META_TRANS_BLOCKS(sb)	(SCEXT4_XATTR_TRANS_BLOCKS + \
					SCEXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

/* Define an arbitrary limit for the amount of data we will anticipate
 * writing to any given transaction.  For unbounded transactions such as
 * write(2) and truncate(2) we can write more than this, but we always
 * start off at the maximum transaction size and grow the transaction
 * optimistically as we go. */

#define SCEXT4_MAX_TRANS_DATA		64U

/* We break up a large truncate or write transaction once the handle's
 * buffer credits gets this low, we need either to extend the
 * transaction or to start a new one.  Reserve enough space here for
 * inode, bitmap, superblock, group and indirection updates for at least
 * one block, plus two quota updates.  Quota allocations are not
 * needed. */

#define SCEXT4_RESERVE_TRANS_BLOCKS	12U

/*
 * Number of credits needed if we need to insert an entry into a
 * directory.  For each new index block, we need 4 blocks (old index
 * block, new index block, bitmap block, bg summary).  For normal
 * htree directories there are 2 levels; if the largedir feature
 * enabled it's 3 levels.
 */
#define SCEXT4_INDEX_EXTRA_TRANS_BLOCKS	12U

#ifdef CONFIG_QUOTA
/* Amount of blocks needed for quota update - we know that the structure was
 * allocated so we need to update only data block */
#define SCEXT4_QUOTA_TRANS_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		scext4_has_feature_quota(sb)) ? 1 : 0)
/* Amount of blocks needed for quota insert/delete - we do some block writes
 * but inode, sb and group updates are done only once */
#define SCEXT4_QUOTA_INIT_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		scext4_has_feature_quota(sb)) ?\
		(DQUOT_INIT_ALLOC*(SCEXT4_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_INIT_REWRITE) : 0)

#define SCEXT4_QUOTA_DEL_BLOCKS(sb) ((test_opt(sb, QUOTA) ||\
		scext4_has_feature_quota(sb)) ?\
		(DQUOT_DEL_ALLOC*(SCEXT4_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_DEL_REWRITE) : 0)
#else
#define SCEXT4_QUOTA_TRANS_BLOCKS(sb) 0
#define SCEXT4_QUOTA_INIT_BLOCKS(sb) 0
#define SCEXT4_QUOTA_DEL_BLOCKS(sb) 0
#endif
#define SCEXT4_MAXQUOTAS_TRANS_BLOCKS(sb) (SCEXT4_MAXQUOTAS*SCEXT4_QUOTA_TRANS_BLOCKS(sb))
#define SCEXT4_MAXQUOTAS_INIT_BLOCKS(sb) (SCEXT4_MAXQUOTAS*SCEXT4_QUOTA_INIT_BLOCKS(sb))
#define SCEXT4_MAXQUOTAS_DEL_BLOCKS(sb) (SCEXT4_MAXQUOTAS*SCEXT4_QUOTA_DEL_BLOCKS(sb))

/*
 * Ext4 handle operation types -- for logging purposes
 */
#define SCEXT4_HT_MISC             0
#define SCEXT4_HT_INODE            1
#define SCEXT4_HT_WRITE_PAGE       2
#define SCEXT4_HT_MAP_BLOCKS       3
#define SCEXT4_HT_DIR              4
#define SCEXT4_HT_TRUNCATE         5
#define SCEXT4_HT_QUOTA            6
#define SCEXT4_HT_RESIZE           7
#define SCEXT4_HT_MIGRATE          8
#define SCEXT4_HT_MOVE_EXTENTS     9
#define SCEXT4_HT_XATTR           10
#define SCEXT4_HT_EXT_CONVERT     11
#define SCEXT4_HT_MAX             12

/**
 *   struct scext4_journal_cb_entry - Base structure for callback information.
 *
 *   This struct is a 'seed' structure for a using with your own callback
 *   structs. If you are using callbacks you must allocate one of these
 *   or another struct of your own definition which has this struct
 *   as it's first element and pass it to scext4_journal_callback_add().
 */
struct scext4_journal_cb_entry {
	/* list information for other callbacks attached to the same handle */
	struct list_head jce_list;

	/*  Function to call with this callback structure */
	void (*jce_func)(struct super_block *sb,
			 struct scext4_journal_cb_entry *jce, int error);

	/* user data goes here */
};

/**
 * scext4_journal_callback_add: add a function to call after transaction commit
 * @handle: active journal transaction handle to register callback on
 * @func: callback function to call after the transaction has committed:
 *        @sb: superblock of current filesystem for transaction
 *        @jce: returned journal callback data
 *        @rc: journal state at commit (0 = transaction committed properly)
 * @jce: journal callback data (internal and function private data struct)
 *
 * The registered function will be called in the context of the journal thread
 * after the transaction for which the handle was created has completed.
 *
 * No locks are held when the callback function is called, so it is safe to
 * call blocking functions from within the callback, but the callback should
 * not block or run for too long, or the filesystem will be blocked waiting for
 * the next transaction to commit. No journaling functions can be used, or
 * there is a risk of deadlock.
 *
 * There is no guaranteed calling order of multiple registered callbacks on
 * the same transaction.
 */
static inline void _scext4_journal_callback_add(handle_t *handle,
			struct scext4_journal_cb_entry *jce)
{
	/* Add the jce to transaction's private list */
	list_add_tail(&jce->jce_list, &handle->h_transaction->t_private_list);
}

static inline void scext4_journal_callback_add(handle_t *handle,
			void (*func)(struct super_block *sb,
				     struct scext4_journal_cb_entry *jce,
				     int rc),
			struct scext4_journal_cb_entry *jce)
{
	struct scext4_sb_info *sbi =
			SCEXT4_SB(handle->h_transaction->t_journal->j_private);

	/* Add the jce to transaction's private list */
	jce->jce_func = func;
	spin_lock(&sbi->s_md_lock);
	_scext4_journal_callback_add(handle, jce);
	spin_unlock(&sbi->s_md_lock);
}


/**
 * scext4_journal_callback_del: delete a registered callback
 * @handle: active journal transaction handle on which callback was registered
 * @jce: registered journal callback entry to unregister
 * Return true if object was successfully removed
 */
static inline bool scext4_journal_callback_try_del(handle_t *handle,
					     struct scext4_journal_cb_entry *jce)
{
	bool deleted;
	struct scext4_sb_info *sbi =
			SCEXT4_SB(handle->h_transaction->t_journal->j_private);

	spin_lock(&sbi->s_md_lock);
	deleted = !list_empty(&jce->jce_list);
	list_del_init(&jce->jce_list);
	spin_unlock(&sbi->s_md_lock);
	return deleted;
}

int
scext4_mark_iloc_dirty(handle_t *handle,
		     struct inode *inode,
		     struct scext4_iloc *iloc);

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int scext4_reserve_inode_write(handle_t *handle, struct inode *inode,
			struct scext4_iloc *iloc);

int scext4_mark_inode_dirty(handle_t *handle, struct inode *inode);

int scext4_expand_extra_isize(struct inode *inode,
			    unsigned int new_extra_isize,
			    struct scext4_iloc *iloc);
/*
 * Wrapper functions with which scext4 calls into JBD.
 */
int __scext4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh);

int __scext4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, scext4_fsblk_t blocknr);

int __scext4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh);

int __scext4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh);

int __scext4_handle_dirty_super(const char *where, unsigned int line,
			      handle_t *handle, struct super_block *sb);

#define scext4_journal_get_write_access(handle, bh) \
	__scext4_journal_get_write_access(__func__, __LINE__, (handle), (bh))
#define scext4_forget(handle, is_metadata, inode, bh, block_nr) \
	__scext4_forget(__func__, __LINE__, (handle), (is_metadata), (inode), \
		      (bh), (block_nr))
#define scext4_journal_get_create_access(handle, bh) \
	__scext4_journal_get_create_access(__func__, __LINE__, (handle), (bh))
#define scext4_handle_dirty_metadata(handle, inode, bh) \
	__scext4_handle_dirty_metadata(__func__, __LINE__, (handle), (inode), \
				     (bh))
#define scext4_handle_dirty_super(handle, sb) \
	__scext4_handle_dirty_super(__func__, __LINE__, (handle), (sb))

handle_t *__scext4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks);
int __scext4_journal_stop(const char *where, unsigned int line, handle_t *handle);

#define SCEXT4_NOJOURNAL_MAX_REF_COUNT ((unsigned long) 4096)

/* Note:  Do not use this for NULL handles.  This is only to determine if
 * a properly allocated handle is using a journal or not. */
static inline int scext4_handle_valid(handle_t *handle)
{
	if ((unsigned long)handle < SCEXT4_NOJOURNAL_MAX_REF_COUNT)
		return 0;
	return 1;
}

static inline void scext4_handle_sync(handle_t *handle)
{
	if (scext4_handle_valid(handle))
		handle->h_sync = 1;
}

static inline int scext4_handle_is_aborted(handle_t *handle)
{
	if (scext4_handle_valid(handle))
		return is_handle_aborted(handle);
	return 0;
}

static inline int scext4_handle_has_enough_credits(handle_t *handle, int needed)
{
	if (scext4_handle_valid(handle) && handle->h_buffer_credits < needed)
		return 0;
	return 1;
}

#define scext4_journal_start_sb(sb, type, nblocks)			\
	__scext4_journal_start_sb((sb), __LINE__, (type), (nblocks), 0)

#define scext4_journal_start(inode, type, nblocks)			\
	__scext4_journal_start((inode), __LINE__, (type), (nblocks), 0)

#define scext4_journal_start_with_reserve(inode, type, blocks, rsv_blocks) \
	__scext4_journal_start((inode), __LINE__, (type), (blocks), (rsv_blocks))

static inline handle_t *__scext4_journal_start(struct inode *inode,
					     unsigned int line, int type,
					     int blocks, int rsv_blocks)
{
	return __scext4_journal_start_sb(inode->i_sb, line, type, blocks,
				       rsv_blocks);
}

#define scext4_journal_stop(handle) \
	__scext4_journal_stop(__func__, __LINE__, (handle))

#define scext4_journal_start_reserved(handle, type) \
	__scext4_journal_start_reserved((handle), __LINE__, (type))

handle_t *__scext4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type);

static inline void scext4_journal_free_reserved(handle_t *handle)
{
	if (scext4_handle_valid(handle))
		jbd3_journal_free_reserved(handle);
}

static inline handle_t *scext4_journal_current_handle(void)
{
	return journal_current_handle();
}

static inline int scext4_journal_extend(handle_t *handle, int nblocks)
{
	if (scext4_handle_valid(handle))
		return jbd3_journal_extend(handle, nblocks);
	return 0;
}

static inline int scext4_journal_restart(handle_t *handle, int nblocks)
{
	if (scext4_handle_valid(handle))
		return jbd3_journal_restart(handle, nblocks);
	return 0;
}

static inline int scext4_journal_blocks_per_page(struct inode *inode)
{
	if (SCEXT4_JOURNAL(inode) != NULL)
		return jbd3_journal_blocks_per_page(inode);
	return 0;
}

static inline int scext4_journal_force_commit(journal_t *journal)
{
	if (journal)
		return jbd3_journal_force_commit(journal);
	return 0;
}

static inline int scext4_jbd3_inode_add_write(handle_t *handle,
		struct inode *inode, loff_t start_byte, loff_t length)
{
	if (scext4_handle_valid(handle))
		return jbd3_journal_inode_ranged_write(handle,
				SCEXT4_I(inode)->jinode, start_byte, length);
	return 0;
}

static inline int scext4_jbd3_inode_add_wait(handle_t *handle,
		struct inode *inode, loff_t start_byte, loff_t length)
{
	if (scext4_handle_valid(handle))
		return jbd3_journal_inode_ranged_wait(handle,
				SCEXT4_I(inode)->jinode, start_byte, length);
	return 0;
}

static inline void scext4_update_inode_fsync_trans(handle_t *handle,
						 struct inode *inode,
						 int datasync)
{
	struct scext4_inode_info *ei = SCEXT4_I(inode);

	if (scext4_handle_valid(handle) && !is_handle_aborted(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		if (datasync)
			ei->i_datasync_tid = handle->h_transaction->t_tid;
	}
}

/* super.c */
int scext4_force_commit(struct super_block *sb);

/*
 * Ext4 inode journal modes
 */
#define SCEXT4_INODE_JOURNAL_DATA_MODE	0x01 /* journal data mode */
#define SCEXT4_INODE_ORDERED_DATA_MODE	0x02 /* ordered data mode */
#define SCEXT4_INODE_WRITEBACK_DATA_MODE	0x04 /* writeback data mode */

static inline int scext4_inode_journal_mode(struct inode *inode)
{
	if (SCEXT4_JOURNAL(inode) == NULL)
		return SCEXT4_INODE_WRITEBACK_DATA_MODE;	/* writeback */
	/* We do not support data journalling with delayed allocation */
	if (!S_ISREG(inode->i_mode) ||
	    test_opt(inode->i_sb, DATA_FLAGS) == SCEXT4_MOUNT_JOURNAL_DATA ||
	    (scext4_test_inode_flag(inode, SCEXT4_INODE_JOURNAL_DATA) &&
	    !test_opt(inode->i_sb, DELALLOC))) {
		/* We do not support data journalling for encrypted data */
		if (S_ISREG(inode->i_mode) && IS_ENCRYPTED(inode))
			return SCEXT4_INODE_ORDERED_DATA_MODE;  /* ordered */
		return SCEXT4_INODE_JOURNAL_DATA_MODE;	/* journal data */
	}
	if (test_opt(inode->i_sb, DATA_FLAGS) == SCEXT4_MOUNT_ORDERED_DATA)
		return SCEXT4_INODE_ORDERED_DATA_MODE;	/* ordered */
	if (test_opt(inode->i_sb, DATA_FLAGS) == SCEXT4_MOUNT_WRITEBACK_DATA)
		return SCEXT4_INODE_WRITEBACK_DATA_MODE;	/* writeback */
	BUG();
}

static inline int scext4_should_journal_data(struct inode *inode)
{
	return scext4_inode_journal_mode(inode) & SCEXT4_INODE_JOURNAL_DATA_MODE;
}

static inline int scext4_should_order_data(struct inode *inode)
{
	return scext4_inode_journal_mode(inode) & SCEXT4_INODE_ORDERED_DATA_MODE;
}

static inline int scext4_should_writeback_data(struct inode *inode)
{
	return scext4_inode_journal_mode(inode) & SCEXT4_INODE_WRITEBACK_DATA_MODE;
}

/*
 * This function controls whether or not we should try to go down the
 * dioread_nolock code paths, which makes it safe to avoid taking
 * i_mutex for direct I/O reads.  This only works for extent-based
 * files, and it doesn't work if data journaling is enabled, since the
 * dioread_nolock code uses b_private to pass information back to the
 * I/O completion handler, and this conflicts with the jbd's use of
 * b_private.
 */
static inline int scext4_should_dioread_nolock(struct inode *inode)
{
	if (!test_opt(inode->i_sb, DIOREAD_NOLOCK))
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (!(scext4_test_inode_flag(inode, SCEXT4_INODE_EXTENTS)))
		return 0;
	if (scext4_should_journal_data(inode))
		return 0;
	return 1;
}

#endif	/* _SCEXT4_JBD3_H */
