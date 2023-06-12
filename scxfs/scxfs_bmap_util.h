// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_BMAP_UTIL_H__
#define	__SCXFS_BMAP_UTIL_H__

/* Kernel only BMAP related definitions and functions */

struct scxfs_bmbt_irec;
struct scxfs_extent_free_item;
struct scxfs_ifork;
struct scxfs_inode;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_bmalloca;

#ifdef CONFIG_XFS_RT
int	scxfs_bmap_rtalloc(struct scxfs_bmalloca *ap);
#else /* !CONFIG_XFS_RT */
/*
 * Attempts to allocate RT extents when RT is disable indicates corruption and
 * should trigger a shutdown.
 */
static inline int
scxfs_bmap_rtalloc(struct scxfs_bmalloca *ap)
{
	return -EFSCORRUPTED;
}
#endif /* CONFIG_XFS_RT */

int	scxfs_bmap_eof(struct scxfs_inode *ip, scxfs_fileoff_t endoff,
		     int whichfork, int *eof);
int	scxfs_bmap_punch_delalloc_range(struct scxfs_inode *ip,
		scxfs_fileoff_t start_fsb, scxfs_fileoff_t length);

struct kgetbmap {
	__s64		bmv_offset;	/* file offset of segment in blocks */
	__s64		bmv_block;	/* starting block (64-bit daddr_t)  */
	__s64		bmv_length;	/* length of segment, blocks	    */
	__s32		bmv_oflags;	/* output flags */
};
int	scxfs_getbmap(struct scxfs_inode *ip, struct getbmapx *bmv,
		struct kgetbmap *out);

/* functions in scxfs_bmap.c that are only needed by scxfs_bmap_util.c */
int	scxfs_bmap_extsize_align(struct scxfs_mount *mp, struct scxfs_bmbt_irec *gotp,
			       struct scxfs_bmbt_irec *prevp, scxfs_extlen_t extsz,
			       int rt, int eof, int delay, int convert,
			       scxfs_fileoff_t *offp, scxfs_extlen_t *lenp);
void	scxfs_bmap_adjacent(struct scxfs_bmalloca *ap);
int	scxfs_bmap_last_extent(struct scxfs_trans *tp, struct scxfs_inode *ip,
			     int whichfork, struct scxfs_bmbt_irec *rec,
			     int *is_empty);

/* preallocation and hole punch interface */
int	scxfs_alloc_file_space(struct scxfs_inode *ip, scxfs_off_t offset,
			     scxfs_off_t len, int alloc_type);
int	scxfs_free_file_space(struct scxfs_inode *ip, scxfs_off_t offset,
			    scxfs_off_t len);
int	scxfs_zero_file_space(struct scxfs_inode *ip, scxfs_off_t offset,
			    scxfs_off_t len);
int	scxfs_collapse_file_space(struct scxfs_inode *, scxfs_off_t offset,
				scxfs_off_t len);
int	scxfs_insert_file_space(struct scxfs_inode *, scxfs_off_t offset,
				scxfs_off_t len);

/* EOF block manipulation functions */
bool	scxfs_can_free_eofblocks(struct scxfs_inode *ip, bool force);
int	scxfs_free_eofblocks(struct scxfs_inode *ip);

int	scxfs_swap_extents(struct scxfs_inode *ip, struct scxfs_inode *tip,
			 struct scxfs_swapext *sx);

scxfs_daddr_t scxfs_fsb_to_db(struct scxfs_inode *ip, scxfs_fsblock_t fsb);

scxfs_extnum_t scxfs_bmap_count_leaves(struct scxfs_ifork *ifp, scxfs_filblks_t *count);
int scxfs_bmap_count_blocks(struct scxfs_trans *tp, struct scxfs_inode *ip,
			  int whichfork, scxfs_extnum_t *nextents,
			  scxfs_filblks_t *count);

int	scxfs_flush_unmap_range(struct scxfs_inode *ip, scxfs_off_t offset,
			      scxfs_off_t len);

#endif	/* __SCXFS_BMAP_UTIL_H__ */
