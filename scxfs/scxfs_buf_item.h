// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_BUF_ITEM_H__
#define	__SCXFS_BUF_ITEM_H__

/* kernel only definitions */

/* buf log item flags */
#define	SCXFS_BLI_HOLD		0x01
#define	SCXFS_BLI_DIRTY		0x02
#define	SCXFS_BLI_STALE		0x04
#define	SCXFS_BLI_LOGGED		0x08
#define	SCXFS_BLI_INODE_ALLOC_BUF	0x10
#define SCXFS_BLI_STALE_INODE	0x20
#define	SCXFS_BLI_INODE_BUF	0x40
#define	SCXFS_BLI_ORDERED		0x80

#define SCXFS_BLI_FLAGS \
	{ SCXFS_BLI_HOLD,		"HOLD" }, \
	{ SCXFS_BLI_DIRTY,	"DIRTY" }, \
	{ SCXFS_BLI_STALE,	"STALE" }, \
	{ SCXFS_BLI_LOGGED,	"LOGGED" }, \
	{ SCXFS_BLI_INODE_ALLOC_BUF, "INODE_ALLOC" }, \
	{ SCXFS_BLI_STALE_INODE,	"STALE_INODE" }, \
	{ SCXFS_BLI_INODE_BUF,	"INODE_BUF" }, \
	{ SCXFS_BLI_ORDERED,	"ORDERED" }


struct scxfs_buf;
struct scxfs_mount;
struct scxfs_buf_log_item;

/*
 * This is the in core log item structure used to track information
 * needed to log buffers.  It tracks how many times the lock has been
 * locked, and which 128 byte chunks of the buffer are dirty.
 */
struct scxfs_buf_log_item {
	struct scxfs_log_item	bli_item;	/* common item structure */
	struct scxfs_buf		*bli_buf;	/* real buffer pointer */
	unsigned int		bli_flags;	/* misc flags */
	unsigned int		bli_recur;	/* lock recursion count */
	atomic_t		bli_refcount;	/* cnt of tp refs */
	int			bli_format_count;	/* count of headers */
	struct scxfs_buf_log_format *bli_formats;	/* array of in-log header ptrs */
	struct scxfs_buf_log_format __bli_format;	/* embedded in-log header */
};

int	scxfs_buf_item_init(struct scxfs_buf *, struct scxfs_mount *);
void	scxfs_buf_item_relse(struct scxfs_buf *);
bool	scxfs_buf_item_put(struct scxfs_buf_log_item *);
void	scxfs_buf_item_log(struct scxfs_buf_log_item *, uint, uint);
bool	scxfs_buf_item_dirty_format(struct scxfs_buf_log_item *);
void	scxfs_buf_attach_iodone(struct scxfs_buf *,
			      void(*)(struct scxfs_buf *, struct scxfs_log_item *),
			      struct scxfs_log_item *);
void	scxfs_buf_iodone_callbacks(struct scxfs_buf *);
void	scxfs_buf_iodone(struct scxfs_buf *, struct scxfs_log_item *);
bool	scxfs_buf_resubmit_failed_buffers(struct scxfs_buf *,
					struct list_head *);

extern kmem_zone_t	*scxfs_buf_item_zone;

#endif	/* __SCXFS_BUF_ITEM_H__ */
