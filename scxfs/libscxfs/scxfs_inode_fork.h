// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_INODE_FORK_H__
#define	__SCXFS_INODE_FORK_H__

struct scxfs_inode_log_item;
struct scxfs_dinode;

/*
 * File incore extent information, present for each of data & attr forks.
 */
struct scxfs_ifork {
	int64_t			if_bytes;	/* bytes in if_u1 */
	struct scxfs_btree_block	*if_broot;	/* file's incore btree root */
	unsigned int		if_seq;		/* fork mod counter */
	int			if_height;	/* height of the extent tree */
	union {
		void		*if_root;	/* extent tree root */
		char		*if_data;	/* inline file data */
	} if_u1;
	short			if_broot_bytes;	/* bytes allocated for root */
	unsigned char		if_flags;	/* per-fork flags */
};

/*
 * Per-fork incore inode flags.
 */
#define	SCXFS_IFINLINE	0x01	/* Inline data is read in */
#define	SCXFS_IFEXTENTS	0x02	/* All extent pointers are read in */
#define	SCXFS_IFBROOT	0x04	/* i_broot points to the bmap b-tree root */

/*
 * Fork handling.
 */

#define SCXFS_IFORK_Q(ip)			((ip)->i_d.di_forkoff != 0)
#define SCXFS_IFORK_BOFF(ip)		((int)((ip)->i_d.di_forkoff << 3))

#define SCXFS_IFORK_PTR(ip,w)		\
	((w) == SCXFS_DATA_FORK ? \
		&(ip)->i_df : \
		((w) == SCXFS_ATTR_FORK ? \
			(ip)->i_afp : \
			(ip)->i_cowfp))
#define SCXFS_IFORK_DSIZE(ip) \
	(SCXFS_IFORK_Q(ip) ? \
		SCXFS_IFORK_BOFF(ip) : \
		SCXFS_LITINO((ip)->i_mount, (ip)->i_d.di_version))
#define SCXFS_IFORK_ASIZE(ip) \
	(SCXFS_IFORK_Q(ip) ? \
		SCXFS_LITINO((ip)->i_mount, (ip)->i_d.di_version) - \
			SCXFS_IFORK_BOFF(ip) : \
		0)
#define SCXFS_IFORK_SIZE(ip,w) \
	((w) == SCXFS_DATA_FORK ? \
		SCXFS_IFORK_DSIZE(ip) : \
		((w) == SCXFS_ATTR_FORK ? \
			SCXFS_IFORK_ASIZE(ip) : \
			0))
#define SCXFS_IFORK_FORMAT(ip,w) \
	((w) == SCXFS_DATA_FORK ? \
		(ip)->i_d.di_format : \
		((w) == SCXFS_ATTR_FORK ? \
			(ip)->i_d.di_aformat : \
			(ip)->i_cformat))
#define SCXFS_IFORK_FMT_SET(ip,w,n) \
	((w) == SCXFS_DATA_FORK ? \
		((ip)->i_d.di_format = (n)) : \
		((w) == SCXFS_ATTR_FORK ? \
			((ip)->i_d.di_aformat = (n)) : \
			((ip)->i_cformat = (n))))
#define SCXFS_IFORK_NEXTENTS(ip,w) \
	((w) == SCXFS_DATA_FORK ? \
		(ip)->i_d.di_nextents : \
		((w) == SCXFS_ATTR_FORK ? \
			(ip)->i_d.di_anextents : \
			(ip)->i_cnextents))
#define SCXFS_IFORK_NEXT_SET(ip,w,n) \
	((w) == SCXFS_DATA_FORK ? \
		((ip)->i_d.di_nextents = (n)) : \
		((w) == SCXFS_ATTR_FORK ? \
			((ip)->i_d.di_anextents = (n)) : \
			((ip)->i_cnextents = (n))))
#define SCXFS_IFORK_MAXEXT(ip, w) \
	(SCXFS_IFORK_SIZE(ip, w) / sizeof(scxfs_bmbt_rec_t))

struct scxfs_ifork *scxfs_iext_state_to_fork(struct scxfs_inode *ip, int state);

int		scxfs_iformat_fork(struct scxfs_inode *, struct scxfs_dinode *);
void		scxfs_iflush_fork(struct scxfs_inode *, struct scxfs_dinode *,
				struct scxfs_inode_log_item *, int);
void		scxfs_idestroy_fork(struct scxfs_inode *, int);
void		scxfs_idata_realloc(struct scxfs_inode *ip, int64_t byte_diff,
				int whichfork);
void		scxfs_iroot_realloc(struct scxfs_inode *, int, int);
int		scxfs_iread_extents(struct scxfs_trans *, struct scxfs_inode *, int);
int		scxfs_iextents_copy(struct scxfs_inode *, struct scxfs_bmbt_rec *,
				  int);
void		scxfs_init_local_fork(struct scxfs_inode *ip, int whichfork,
				const void *data, int64_t size);

scxfs_extnum_t	scxfs_iext_count(struct scxfs_ifork *ifp);
void		scxfs_iext_insert(struct scxfs_inode *, struct scxfs_iext_cursor *cur,
			struct scxfs_bmbt_irec *, int);
void		scxfs_iext_remove(struct scxfs_inode *, struct scxfs_iext_cursor *,
			int);
void		scxfs_iext_destroy(struct scxfs_ifork *);

bool		scxfs_iext_lookup_extent(struct scxfs_inode *ip,
			struct scxfs_ifork *ifp, scxfs_fileoff_t bno,
			struct scxfs_iext_cursor *cur,
			struct scxfs_bmbt_irec *gotp);
bool		scxfs_iext_lookup_extent_before(struct scxfs_inode *ip,
			struct scxfs_ifork *ifp, scxfs_fileoff_t *end,
			struct scxfs_iext_cursor *cur,
			struct scxfs_bmbt_irec *gotp);
bool		scxfs_iext_get_extent(struct scxfs_ifork *ifp,
			struct scxfs_iext_cursor *cur,
			struct scxfs_bmbt_irec *gotp);
void		scxfs_iext_update_extent(struct scxfs_inode *ip, int state,
			struct scxfs_iext_cursor *cur,
			struct scxfs_bmbt_irec *gotp);

void		scxfs_iext_first(struct scxfs_ifork *, struct scxfs_iext_cursor *);
void		scxfs_iext_last(struct scxfs_ifork *, struct scxfs_iext_cursor *);
void		scxfs_iext_next(struct scxfs_ifork *, struct scxfs_iext_cursor *);
void		scxfs_iext_prev(struct scxfs_ifork *, struct scxfs_iext_cursor *);

static inline bool scxfs_iext_next_extent(struct scxfs_ifork *ifp,
		struct scxfs_iext_cursor *cur, struct scxfs_bmbt_irec *gotp)
{
	scxfs_iext_next(ifp, cur);
	return scxfs_iext_get_extent(ifp, cur, gotp);
}

static inline bool scxfs_iext_prev_extent(struct scxfs_ifork *ifp,
		struct scxfs_iext_cursor *cur, struct scxfs_bmbt_irec *gotp)
{
	scxfs_iext_prev(ifp, cur);
	return scxfs_iext_get_extent(ifp, cur, gotp);
}

/*
 * Return the extent after cur in gotp without updating the cursor.
 */
static inline bool scxfs_iext_peek_next_extent(struct scxfs_ifork *ifp,
		struct scxfs_iext_cursor *cur, struct scxfs_bmbt_irec *gotp)
{
	struct scxfs_iext_cursor ncur = *cur;

	scxfs_iext_next(ifp, &ncur);
	return scxfs_iext_get_extent(ifp, &ncur, gotp);
}

/*
 * Return the extent before cur in gotp without updating the cursor.
 */
static inline bool scxfs_iext_peek_prev_extent(struct scxfs_ifork *ifp,
		struct scxfs_iext_cursor *cur, struct scxfs_bmbt_irec *gotp)
{
	struct scxfs_iext_cursor ncur = *cur;

	scxfs_iext_prev(ifp, &ncur);
	return scxfs_iext_get_extent(ifp, &ncur, gotp);
}

#define for_each_scxfs_iext(ifp, ext, got)		\
	for (scxfs_iext_first((ifp), (ext));		\
	     scxfs_iext_get_extent((ifp), (ext), (got));	\
	     scxfs_iext_next((ifp), (ext)))

extern struct kmem_zone	*scxfs_ifork_zone;

extern void scxfs_ifork_init_cow(struct scxfs_inode *ip);

typedef scxfs_failaddr_t (*scxfs_ifork_verifier_t)(struct scxfs_inode *);

struct scxfs_ifork_ops {
	scxfs_ifork_verifier_t	verify_symlink;
	scxfs_ifork_verifier_t	verify_dir;
	scxfs_ifork_verifier_t	verify_attr;
};
extern struct scxfs_ifork_ops	scxfs_default_ifork_ops;

scxfs_failaddr_t scxfs_ifork_verify_data(struct scxfs_inode *ip,
		struct scxfs_ifork_ops *ops);
scxfs_failaddr_t scxfs_ifork_verify_attr(struct scxfs_inode *ip,
		struct scxfs_ifork_ops *ops);

#endif	/* __SCXFS_INODE_FORK_H__ */
