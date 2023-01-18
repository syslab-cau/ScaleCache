// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * Copyright (c) 2010 David Chinner.
 * Copyright (c) 2011 Christoph Hellwig.
 * All Rights Reserved.
 */
#ifndef __SCXFS_EXTENT_BUSY_H__
#define	__SCXFS_EXTENT_BUSY_H__

struct scxfs_mount;
struct scxfs_trans;
struct scxfs_alloc_arg;

/*
 * Busy block/extent entry.  Indexed by a rbtree in perag to mark blocks that
 * have been freed but whose transactions aren't committed to disk yet.
 *
 * Note that we use the transaction ID to record the transaction, not the
 * transaction structure itself. See scxfs_extent_busy_insert() for details.
 */
struct scxfs_extent_busy {
	struct rb_node	rb_node;	/* ag by-bno indexed search tree */
	struct list_head list;		/* transaction busy extent list */
	scxfs_agnumber_t	agno;
	scxfs_agblock_t	bno;
	scxfs_extlen_t	length;
	unsigned int	flags;
#define SCXFS_EXTENT_BUSY_DISCARDED	0x01	/* undergoing a discard op. */
#define SCXFS_EXTENT_BUSY_SKIP_DISCARD	0x02	/* do not discard */
};

void
scxfs_extent_busy_insert(struct scxfs_trans *tp, scxfs_agnumber_t agno,
	scxfs_agblock_t bno, scxfs_extlen_t len, unsigned int flags);

void
scxfs_extent_busy_clear(struct scxfs_mount *mp, struct list_head *list,
	bool do_discard);

int
scxfs_extent_busy_search(struct scxfs_mount *mp, scxfs_agnumber_t agno,
	scxfs_agblock_t bno, scxfs_extlen_t len);

void
scxfs_extent_busy_reuse(struct scxfs_mount *mp, scxfs_agnumber_t agno,
	scxfs_agblock_t fbno, scxfs_extlen_t flen, bool userdata);

bool
scxfs_extent_busy_trim(struct scxfs_alloc_arg *args, scxfs_agblock_t *bno,
		scxfs_extlen_t *len, unsigned *busy_gen);

void
scxfs_extent_busy_flush(struct scxfs_mount *mp, struct scxfs_perag *pag,
	unsigned busy_gen);

void
scxfs_extent_busy_wait_all(struct scxfs_mount *mp);

int
scxfs_extent_busy_ag_cmp(void *priv, struct list_head *a, struct list_head *b);

static inline void scxfs_extent_busy_sort(struct list_head *list)
{
	list_sort(NULL, list, scxfs_extent_busy_ag_cmp);
}

#endif /* __SCXFS_EXTENT_BUSY_H__ */
