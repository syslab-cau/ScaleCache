// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_DEFER_H__
#define	__SCXFS_DEFER_H__

struct scxfs_defer_op_type;

/*
 * Header for deferred operation list.
 */
enum scxfs_defer_ops_type {
	SCXFS_DEFER_OPS_TYPE_BMAP,
	SCXFS_DEFER_OPS_TYPE_REFCOUNT,
	SCXFS_DEFER_OPS_TYPE_RMAP,
	SCXFS_DEFER_OPS_TYPE_FREE,
	SCXFS_DEFER_OPS_TYPE_AGFL_FREE,
	SCXFS_DEFER_OPS_TYPE_MAX,
};

/*
 * Save a log intent item and a list of extents, so that we can replay
 * whatever action had to happen to the extent list and file the log done
 * item.
 */
struct scxfs_defer_pending {
	struct list_head		dfp_list;	/* pending items */
	struct list_head		dfp_work;	/* work items */
	void				*dfp_intent;	/* log intent item */
	void				*dfp_done;	/* log done item */
	unsigned int			dfp_count;	/* # extent items */
	enum scxfs_defer_ops_type		dfp_type;
};

void scxfs_defer_add(struct scxfs_trans *tp, enum scxfs_defer_ops_type type,
		struct list_head *h);
int scxfs_defer_finish_noroll(struct scxfs_trans **tp);
int scxfs_defer_finish(struct scxfs_trans **tp);
void scxfs_defer_cancel(struct scxfs_trans *);
void scxfs_defer_move(struct scxfs_trans *dtp, struct scxfs_trans *stp);

/* Description of a deferred type. */
struct scxfs_defer_op_type {
	void (*abort_intent)(void *);
	void *(*create_done)(struct scxfs_trans *, void *, unsigned int);
	int (*finish_item)(struct scxfs_trans *, struct list_head *, void *,
			void **);
	void (*finish_cleanup)(struct scxfs_trans *, void *, int);
	void (*cancel_item)(struct list_head *);
	int (*diff_items)(void *, struct list_head *, struct list_head *);
	void *(*create_intent)(struct scxfs_trans *, uint);
	void (*log_item)(struct scxfs_trans *, void *, struct list_head *);
	unsigned int		max_items;
};

extern const struct scxfs_defer_op_type scxfs_bmap_update_defer_type;
extern const struct scxfs_defer_op_type scxfs_refcount_update_defer_type;
extern const struct scxfs_defer_op_type scxfs_rmap_update_defer_type;
extern const struct scxfs_defer_op_type scxfs_extent_free_defer_type;
extern const struct scxfs_defer_op_type scxfs_agfl_free_defer_type;

#endif /* __SCXFS_DEFER_H__ */
