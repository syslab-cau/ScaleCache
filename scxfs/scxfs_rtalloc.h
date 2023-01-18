// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_RTALLOC_H__
#define	__SCXFS_RTALLOC_H__

/* kernel only definitions and functions */

struct scxfs_mount;
struct scxfs_trans;

/*
 * XXX: Most of the realtime allocation functions deal in units of realtime
 * extents, not realtime blocks.  This looks funny when paired with the type
 * name and screams for a larger cleanup.
 */
struct scxfs_rtalloc_rec {
	scxfs_rtblock_t		ar_startext;
	scxfs_rtblock_t		ar_extcount;
};

typedef int (*scxfs_rtalloc_query_range_fn)(
	struct scxfs_trans	*tp,
	struct scxfs_rtalloc_rec	*rec,
	void			*priv);

#ifdef CONFIG_XFS_RT
/*
 * Function prototypes for exported functions.
 */

/*
 * Allocate an extent in the realtime subvolume, with the usual allocation
 * parameters.  The length units are all in realtime extents, as is the
 * result block number.
 */
int					/* error */
scxfs_rtallocate_extent(
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_rtblock_t		bno,	/* starting block number to allocate */
	scxfs_extlen_t		minlen,	/* minimum length to allocate */
	scxfs_extlen_t		maxlen,	/* maximum length to allocate */
	scxfs_extlen_t		*len,	/* out: actual length allocated */
	int			wasdel,	/* was a delayed allocation extent */
	scxfs_extlen_t		prod,	/* extent product factor */
	scxfs_rtblock_t		*rtblock); /* out: start block allocated */

/*
 * Free an extent in the realtime subvolume.  Length is expressed in
 * realtime extents, as is the block number.
 */
int					/* error */
scxfs_rtfree_extent(
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_rtblock_t		bno,	/* starting block number to free */
	scxfs_extlen_t		len);	/* length of extent freed */

/*
 * Initialize realtime fields in the mount structure.
 */
int					/* error */
scxfs_rtmount_init(
	struct scxfs_mount	*mp);	/* file system mount structure */
void
scxfs_rtunmount_inodes(
	struct scxfs_mount	*mp);

/*
 * Get the bitmap and summary inodes into the mount structure
 * at mount time.
 */
int					/* error */
scxfs_rtmount_inodes(
	struct scxfs_mount	*mp);	/* file system mount structure */

/*
 * Pick an extent for allocation at the start of a new realtime file.
 * Use the sequence number stored in the atime field of the bitmap inode.
 * Translate this to a fraction of the rtextents, and return the product
 * of rtextents and the fraction.
 * The fraction sequence is 0, 1/2, 1/4, 3/4, 1/8, ..., 7/8, 1/16, ...
 */
int					/* error */
scxfs_rtpick_extent(
	struct scxfs_mount	*mp,	/* file system mount point */
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_extlen_t		len,	/* allocation length (rtextents) */
	scxfs_rtblock_t		*pick);	/* result rt extent */

/*
 * Grow the realtime area of the filesystem.
 */
int
scxfs_growfs_rt(
	struct scxfs_mount	*mp,	/* file system mount structure */
	scxfs_growfs_rt_t		*in);	/* user supplied growfs struct */

/*
 * From scxfs_rtbitmap.c
 */
int scxfs_rtbuf_get(struct scxfs_mount *mp, struct scxfs_trans *tp,
		  scxfs_rtblock_t block, int issum, struct scxfs_buf **bpp);
int scxfs_rtcheck_range(struct scxfs_mount *mp, struct scxfs_trans *tp,
		      scxfs_rtblock_t start, scxfs_extlen_t len, int val,
		      scxfs_rtblock_t *new, int *stat);
int scxfs_rtfind_back(struct scxfs_mount *mp, struct scxfs_trans *tp,
		    scxfs_rtblock_t start, scxfs_rtblock_t limit,
		    scxfs_rtblock_t *rtblock);
int scxfs_rtfind_forw(struct scxfs_mount *mp, struct scxfs_trans *tp,
		    scxfs_rtblock_t start, scxfs_rtblock_t limit,
		    scxfs_rtblock_t *rtblock);
int scxfs_rtmodify_range(struct scxfs_mount *mp, struct scxfs_trans *tp,
		       scxfs_rtblock_t start, scxfs_extlen_t len, int val);
int scxfs_rtmodify_summary_int(struct scxfs_mount *mp, struct scxfs_trans *tp,
			     int log, scxfs_rtblock_t bbno, int delta,
			     scxfs_buf_t **rbpp, scxfs_fsblock_t *rsb,
			     scxfs_suminfo_t *sum);
int scxfs_rtmodify_summary(struct scxfs_mount *mp, struct scxfs_trans *tp, int log,
			 scxfs_rtblock_t bbno, int delta, scxfs_buf_t **rbpp,
			 scxfs_fsblock_t *rsb);
int scxfs_rtfree_range(struct scxfs_mount *mp, struct scxfs_trans *tp,
		     scxfs_rtblock_t start, scxfs_extlen_t len,
		     struct scxfs_buf **rbpp, scxfs_fsblock_t *rsb);
int scxfs_rtalloc_query_range(struct scxfs_trans *tp,
			    struct scxfs_rtalloc_rec *low_rec,
			    struct scxfs_rtalloc_rec *high_rec,
			    scxfs_rtalloc_query_range_fn fn,
			    void *priv);
int scxfs_rtalloc_query_all(struct scxfs_trans *tp,
			  scxfs_rtalloc_query_range_fn fn,
			  void *priv);
bool scxfs_verify_rtbno(struct scxfs_mount *mp, scxfs_rtblock_t rtbno);
int scxfs_rtalloc_extent_is_free(struct scxfs_mount *mp, struct scxfs_trans *tp,
			       scxfs_rtblock_t start, scxfs_extlen_t len,
			       bool *is_free);
#else
# define scxfs_rtallocate_extent(t,b,min,max,l,f,p,rb)    (ENOSYS)
# define scxfs_rtfree_extent(t,b,l)                       (ENOSYS)
# define scxfs_rtpick_extent(m,t,l,rb)                    (ENOSYS)
# define scxfs_growfs_rt(mp,in)                           (ENOSYS)
# define scxfs_rtalloc_query_range(t,l,h,f,p)             (ENOSYS)
# define scxfs_rtalloc_query_all(t,f,p)                   (ENOSYS)
# define scxfs_rtbuf_get(m,t,b,i,p)                       (ENOSYS)
# define scxfs_verify_rtbno(m, r)			(false)
# define scxfs_rtalloc_extent_is_free(m,t,s,l,i)          (ENOSYS)
static inline int		/* error */
scxfs_rtmount_init(
	scxfs_mount_t	*mp)	/* file system mount structure */
{
	if (mp->m_sb.sb_rblocks == 0)
		return 0;

	scxfs_warn(mp, "Not built with CONFIG_XFS_RT");
	return -ENOSYS;
}
# define scxfs_rtmount_inodes(m)  (((mp)->m_sb.sb_rblocks == 0)? 0 : (ENOSYS))
# define scxfs_rtunmount_inodes(m)
#endif	/* CONFIG_XFS_RT */

#endif	/* __SCXFS_RTALLOC_H__ */
