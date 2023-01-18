// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_TRANS_H__
#define	__SCXFS_TRANS_H__

/* kernel only transaction subsystem defines */

struct scxfs_buf;
struct scxfs_buftarg;
struct scxfs_efd_log_item;
struct scxfs_efi_log_item;
struct scxfs_inode;
struct scxfs_item_ops;
struct scxfs_log_iovec;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_trans_res;
struct scxfs_dquot_acct;
struct scxfs_rud_log_item;
struct scxfs_rui_log_item;
struct scxfs_btree_cur;
struct scxfs_cui_log_item;
struct scxfs_cud_log_item;
struct scxfs_bui_log_item;
struct scxfs_bud_log_item;

struct scxfs_log_item {
	struct list_head		li_ail;		/* AIL pointers */
	struct list_head		li_trans;	/* transaction list */
	scxfs_lsn_t			li_lsn;		/* last on-disk lsn */
	struct scxfs_mount		*li_mountp;	/* ptr to fs mount */
	struct scxfs_ail			*li_ailp;	/* ptr to AIL */
	uint				li_type;	/* item type */
	unsigned long			li_flags;	/* misc flags */
	struct scxfs_buf			*li_buf;	/* real buffer pointer */
	struct list_head		li_bio_list;	/* buffer item list */
	void				(*li_cb)(struct scxfs_buf *,
						 struct scxfs_log_item *);
							/* buffer item iodone */
							/* callback func */
	const struct scxfs_item_ops	*li_ops;	/* function list */

	/* delayed logging */
	struct list_head		li_cil;		/* CIL pointers */
	struct scxfs_log_vec		*li_lv;		/* active log vector */
	struct scxfs_log_vec		*li_lv_shadow;	/* standby vector */
	scxfs_lsn_t			li_seq;		/* CIL commit seq */
};

/*
 * li_flags use the (set/test/clear)_bit atomic interfaces because updates can
 * race with each other and we don't want to have to use the AIL lock to
 * serialise all updates.
 */
#define	SCXFS_LI_IN_AIL	0
#define	SCXFS_LI_ABORTED	1
#define	SCXFS_LI_FAILED	2
#define	SCXFS_LI_DIRTY	3	/* log item dirty in transaction */

#define SCXFS_LI_FLAGS \
	{ (1 << SCXFS_LI_IN_AIL),		"IN_AIL" }, \
	{ (1 << SCXFS_LI_ABORTED),	"ABORTED" }, \
	{ (1 << SCXFS_LI_FAILED),		"FAILED" }, \
	{ (1 << SCXFS_LI_DIRTY),		"DIRTY" }

struct scxfs_item_ops {
	unsigned flags;
	void (*iop_size)(struct scxfs_log_item *, int *, int *);
	void (*iop_format)(struct scxfs_log_item *, struct scxfs_log_vec *);
	void (*iop_pin)(struct scxfs_log_item *);
	void (*iop_unpin)(struct scxfs_log_item *, int remove);
	uint (*iop_push)(struct scxfs_log_item *, struct list_head *);
	void (*iop_committing)(struct scxfs_log_item *, scxfs_lsn_t commit_lsn);
	void (*iop_release)(struct scxfs_log_item *);
	scxfs_lsn_t (*iop_committed)(struct scxfs_log_item *, scxfs_lsn_t);
	void (*iop_error)(struct scxfs_log_item *, scxfs_buf_t *);
};

/*
 * Release the log item as soon as committed.  This is for items just logging
 * intents that never need to be written back in place.
 */
#define SCXFS_ITEM_RELEASE_WHEN_COMMITTED	(1 << 0)

void	scxfs_log_item_init(struct scxfs_mount *mp, struct scxfs_log_item *item,
			  int type, const struct scxfs_item_ops *ops);

/*
 * Return values for the iop_push() routines.
 */
#define SCXFS_ITEM_SUCCESS	0
#define SCXFS_ITEM_PINNED		1
#define SCXFS_ITEM_LOCKED		2
#define SCXFS_ITEM_FLUSHING	3

/*
 * Deferred operation item relogging limits.
 */
#define SCXFS_DEFER_OPS_NR_INODES	2	/* join up to two inodes */
#define SCXFS_DEFER_OPS_NR_BUFS	2	/* join up to two buffers */

/*
 * This is the structure maintained for every active transaction.
 */
typedef struct scxfs_trans {
	unsigned int		t_magic;	/* magic number */
	unsigned int		t_log_res;	/* amt of log space resvd */
	unsigned int		t_log_count;	/* count for perm log res */
	unsigned int		t_blk_res;	/* # of blocks resvd */
	unsigned int		t_blk_res_used;	/* # of resvd blocks used */
	unsigned int		t_rtx_res;	/* # of rt extents resvd */
	unsigned int		t_rtx_res_used;	/* # of resvd rt extents used */
	unsigned int		t_flags;	/* misc flags */
	scxfs_fsblock_t		t_firstblock;	/* first block allocated */
	struct xlog_ticket	*t_ticket;	/* log mgr ticket */
	struct scxfs_mount	*t_mountp;	/* ptr to fs mount struct */
	struct scxfs_dquot_acct   *t_dqinfo;	/* acctg info for dquots */
	int64_t			t_icount_delta;	/* superblock icount change */
	int64_t			t_ifree_delta;	/* superblock ifree change */
	int64_t			t_fdblocks_delta; /* superblock fdblocks chg */
	int64_t			t_res_fdblocks_delta; /* on-disk only chg */
	int64_t			t_frextents_delta;/* superblock freextents chg*/
	int64_t			t_res_frextents_delta; /* on-disk only chg */
#if defined(DEBUG) || defined(SCXFS_WARN)
	int64_t			t_ag_freeblks_delta; /* debugging counter */
	int64_t			t_ag_flist_delta; /* debugging counter */
	int64_t			t_ag_btree_delta; /* debugging counter */
#endif
	int64_t			t_dblocks_delta;/* superblock dblocks change */
	int64_t			t_agcount_delta;/* superblock agcount change */
	int64_t			t_imaxpct_delta;/* superblock imaxpct change */
	int64_t			t_rextsize_delta;/* superblock rextsize chg */
	int64_t			t_rbmblocks_delta;/* superblock rbmblocks chg */
	int64_t			t_rblocks_delta;/* superblock rblocks change */
	int64_t			t_rextents_delta;/* superblocks rextents chg */
	int64_t			t_rextslog_delta;/* superblocks rextslog chg */
	struct list_head	t_items;	/* log item descriptors */
	struct list_head	t_busy;		/* list of busy extents */
	struct list_head	t_dfops;	/* deferred operations */
	unsigned long		t_pflags;	/* saved process flags state */
} scxfs_trans_t;

/*
 * SCXFS transaction mechanism exported interfaces that are
 * actually macros.
 */
#define	scxfs_trans_set_sync(tp)		((tp)->t_flags |= SCXFS_TRANS_SYNC)

#if defined(DEBUG) || defined(SCXFS_WARN)
#define	scxfs_trans_agblocks_delta(tp, d)	((tp)->t_ag_freeblks_delta += (int64_t)d)
#define	scxfs_trans_agflist_delta(tp, d)	((tp)->t_ag_flist_delta += (int64_t)d)
#define	scxfs_trans_agbtree_delta(tp, d)	((tp)->t_ag_btree_delta += (int64_t)d)
#else
#define	scxfs_trans_agblocks_delta(tp, d)
#define	scxfs_trans_agflist_delta(tp, d)
#define	scxfs_trans_agbtree_delta(tp, d)
#endif

/*
 * SCXFS transaction mechanism exported interfaces.
 */
int		scxfs_trans_alloc(struct scxfs_mount *mp, struct scxfs_trans_res *resp,
			uint blocks, uint rtextents, uint flags,
			struct scxfs_trans **tpp);
int		scxfs_trans_alloc_empty(struct scxfs_mount *mp,
			struct scxfs_trans **tpp);
void		scxfs_trans_mod_sb(scxfs_trans_t *, uint, int64_t);

struct scxfs_buf	*scxfs_trans_get_buf_map(struct scxfs_trans *tp,
				       struct scxfs_buftarg *target,
				       struct scxfs_buf_map *map, int nmaps,
				       uint flags);

static inline struct scxfs_buf *
scxfs_trans_get_buf(
	struct scxfs_trans	*tp,
	struct scxfs_buftarg	*target,
	scxfs_daddr_t		blkno,
	int			numblks,
	uint			flags)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return scxfs_trans_get_buf_map(tp, target, &map, 1, flags);
}

int		scxfs_trans_read_buf_map(struct scxfs_mount *mp,
				       struct scxfs_trans *tp,
				       struct scxfs_buftarg *target,
				       struct scxfs_buf_map *map, int nmaps,
				       scxfs_buf_flags_t flags,
				       struct scxfs_buf **bpp,
				       const struct scxfs_buf_ops *ops);

static inline int
scxfs_trans_read_buf(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct scxfs_buftarg	*target,
	scxfs_daddr_t		blkno,
	int			numblks,
	scxfs_buf_flags_t		flags,
	struct scxfs_buf		**bpp,
	const struct scxfs_buf_ops *ops)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return scxfs_trans_read_buf_map(mp, tp, target, &map, 1,
				      flags, bpp, ops);
}

struct scxfs_buf	*scxfs_trans_getsb(scxfs_trans_t *, struct scxfs_mount *);

void		scxfs_trans_brelse(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_bjoin(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_bhold(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_bhold_release(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_binval(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_inode_buf(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_stale_inode_buf(scxfs_trans_t *, struct scxfs_buf *);
bool		scxfs_trans_ordered_buf(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_dquot_buf(scxfs_trans_t *, struct scxfs_buf *, uint);
void		scxfs_trans_inode_alloc_buf(scxfs_trans_t *, struct scxfs_buf *);
void		scxfs_trans_ichgtime(struct scxfs_trans *, struct scxfs_inode *, int);
void		scxfs_trans_ijoin(struct scxfs_trans *, struct scxfs_inode *, uint);
void		scxfs_trans_log_buf(struct scxfs_trans *, struct scxfs_buf *, uint,
				  uint);
void		scxfs_trans_dirty_buf(struct scxfs_trans *, struct scxfs_buf *);
bool		scxfs_trans_buf_is_dirty(struct scxfs_buf *bp);
void		scxfs_trans_log_inode(scxfs_trans_t *, struct scxfs_inode *, uint);

int		scxfs_trans_commit(struct scxfs_trans *);
int		scxfs_trans_roll(struct scxfs_trans **);
int		scxfs_trans_roll_inode(struct scxfs_trans **, struct scxfs_inode *);
void		scxfs_trans_cancel(scxfs_trans_t *);
int		scxfs_trans_ail_init(struct scxfs_mount *);
void		scxfs_trans_ail_destroy(struct scxfs_mount *);

void		scxfs_trans_buf_set_type(struct scxfs_trans *, struct scxfs_buf *,
				       enum scxfs_blft);
void		scxfs_trans_buf_copy_type(struct scxfs_buf *dst_bp,
					struct scxfs_buf *src_bp);

extern kmem_zone_t	*scxfs_trans_zone;

#endif	/* __SCXFS_TRANS_H__ */
