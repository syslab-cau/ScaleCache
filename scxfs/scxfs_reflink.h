// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_REFLINK_H
#define __SCXFS_REFLINK_H 1

static inline bool scxfs_is_always_cow_inode(struct scxfs_inode *ip)
{
	return ip->i_mount->m_always_cow &&
		scxfs_sb_version_hasreflink(&ip->i_mount->m_sb);
}

static inline bool scxfs_is_cow_inode(struct scxfs_inode *ip)
{
	return scxfs_is_reflink_inode(ip) || scxfs_is_always_cow_inode(ip);
}

extern int scxfs_reflink_find_shared(struct scxfs_mount *mp, struct scxfs_trans *tp,
		scxfs_agnumber_t agno, scxfs_agblock_t agbno, scxfs_extlen_t aglen,
		scxfs_agblock_t *fbno, scxfs_extlen_t *flen, bool find_maximal);
extern int scxfs_reflink_trim_around_shared(struct scxfs_inode *ip,
		struct scxfs_bmbt_irec *irec, bool *shared);
bool scxfs_inode_need_cow(struct scxfs_inode *ip, struct scxfs_bmbt_irec *imap,
		bool *shared);

extern int scxfs_reflink_allocate_cow(struct scxfs_inode *ip,
		struct scxfs_bmbt_irec *imap, bool *shared, uint *lockmode,
		bool convert_now);
extern int scxfs_reflink_convert_cow(struct scxfs_inode *ip, scxfs_off_t offset,
		scxfs_off_t count);

extern int scxfs_reflink_cancel_cow_blocks(struct scxfs_inode *ip,
		struct scxfs_trans **tpp, scxfs_fileoff_t offset_fsb,
		scxfs_fileoff_t end_fsb, bool cancel_real);
extern int scxfs_reflink_cancel_cow_range(struct scxfs_inode *ip, scxfs_off_t offset,
		scxfs_off_t count, bool cancel_real);
extern int scxfs_reflink_end_cow(struct scxfs_inode *ip, scxfs_off_t offset,
		scxfs_off_t count);
extern int scxfs_reflink_recover_cow(struct scxfs_mount *mp);
extern loff_t scxfs_reflink_remap_range(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, loff_t len,
		unsigned int remap_flags);
extern int scxfs_reflink_inode_has_shared_extents(struct scxfs_trans *tp,
		struct scxfs_inode *ip, bool *has_shared);
extern int scxfs_reflink_clear_inode_flag(struct scxfs_inode *ip,
		struct scxfs_trans **tpp);
extern int scxfs_reflink_unshare(struct scxfs_inode *ip, scxfs_off_t offset,
		scxfs_off_t len);
extern int scxfs_reflink_remap_prep(struct file *file_in, loff_t pos_in,
		struct file *file_out, loff_t pos_out, loff_t *len,
		unsigned int remap_flags);
extern int scxfs_reflink_remap_blocks(struct scxfs_inode *src, loff_t pos_in,
		struct scxfs_inode *dest, loff_t pos_out, loff_t remap_len,
		loff_t *remapped);
extern int scxfs_reflink_update_dest(struct scxfs_inode *dest, scxfs_off_t newlen,
		scxfs_extlen_t cowextsize, unsigned int remap_flags);
extern void scxfs_reflink_remap_unlock(struct file *file_in,
		struct file *file_out);

#endif /* __SCXFS_REFLINK_H */
