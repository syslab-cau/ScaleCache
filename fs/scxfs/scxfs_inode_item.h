// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_INODE_ITEM_H__
#define	__SCXFS_INODE_ITEM_H__

/* kernel only definitions */

struct scxfs_buf;
struct scxfs_bmbt_rec;
struct scxfs_inode;
struct scxfs_mount;

typedef struct scxfs_inode_log_item {
	struct scxfs_log_item	ili_item;	   /* common portion */
	struct scxfs_inode	*ili_inode;	   /* inode ptr */
	scxfs_lsn_t		ili_flush_lsn;	   /* lsn at last flush */
	scxfs_lsn_t		ili_last_lsn;	   /* lsn at last transaction */
	unsigned short		ili_lock_flags;	   /* lock flags */
	unsigned short		ili_logged;	   /* flushed logged data */
	unsigned int		ili_last_fields;   /* fields when flushed */
	unsigned int		ili_fields;	   /* fields to be logged */
	unsigned int		ili_fsync_fields;  /* logged since last fsync */
} scxfs_inode_log_item_t;

static inline int scxfs_inode_clean(scxfs_inode_t *ip)
{
	return !ip->i_itemp || !(ip->i_itemp->ili_fields & SCXFS_ILOG_ALL);
}

extern void scxfs_inode_item_init(struct scxfs_inode *, struct scxfs_mount *);
extern void scxfs_inode_item_destroy(struct scxfs_inode *);
extern void scxfs_iflush_done(struct scxfs_buf *, struct scxfs_log_item *);
extern void scxfs_istale_done(struct scxfs_buf *, struct scxfs_log_item *);
extern void scxfs_iflush_abort(struct scxfs_inode *, bool);
extern int scxfs_inode_item_format_convert(scxfs_log_iovec_t *,
					 struct scxfs_inode_log_format *);

extern struct kmem_zone	*scxfs_ili_zone;

#endif	/* __SCXFS_INODE_ITEM_H__ */
