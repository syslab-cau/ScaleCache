// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_INODE_BUF_H__
#define	__SCXFS_INODE_BUF_H__

struct scxfs_inode;
struct scxfs_dinode;

/*
 * In memory representation of the SCXFS inode. This is held in the in-core struct
 * scxfs_inode and represents the current on disk values but the structure is not
 * in on-disk format.  That is, this structure is always translated to on-disk
 * format specific structures at the appropriate time.
 */
struct scxfs_icdinode {
	int8_t		di_version;	/* inode version */
	int8_t		di_format;	/* format of di_c data */
	uint16_t	di_flushiter;	/* incremented on flush */
	uint32_t	di_uid;		/* owner's user id */
	uint32_t	di_gid;		/* owner's group id */
	uint16_t	di_projid_lo;	/* lower part of owner's project id */
	uint16_t	di_projid_hi;	/* higher part of owner's project id */
	scxfs_fsize_t	di_size;	/* number of bytes in file */
	scxfs_rfsblock_t	di_nblocks;	/* # of direct & btree blocks used */
	scxfs_extlen_t	di_extsize;	/* basic/minimum extent size for file */
	scxfs_extnum_t	di_nextents;	/* number of extents in data fork */
	scxfs_aextnum_t	di_anextents;	/* number of extents in attribute fork*/
	uint8_t		di_forkoff;	/* attr fork offs, <<3 for 64b align */
	int8_t		di_aformat;	/* format of attr fork's data */
	uint32_t	di_dmevmask;	/* DMIG event mask */
	uint16_t	di_dmstate;	/* DMIG state info */
	uint16_t	di_flags;	/* random flags, SCXFS_DIFLAG_... */

	uint64_t	di_flags2;	/* more random flags */
	uint32_t	di_cowextsize;	/* basic cow extent size for file */

	scxfs_ictimestamp_t di_crtime;	/* time created */
};

/*
 * Inode location information.  Stored in the inode and passed to
 * scxfs_imap_to_bp() to get a buffer and dinode for a given inode.
 */
struct scxfs_imap {
	scxfs_daddr_t	im_blkno;	/* starting BB of inode chunk */
	unsigned short	im_len;		/* length in BBs of inode chunk */
	unsigned short	im_boffset;	/* inode offset in block in bytes */
};

int	scxfs_imap_to_bp(struct scxfs_mount *, struct scxfs_trans *,
		       struct scxfs_imap *, struct scxfs_dinode **,
		       struct scxfs_buf **, uint, uint);
int	scxfs_iread(struct scxfs_mount *, struct scxfs_trans *,
		  struct scxfs_inode *, uint);
void	scxfs_dinode_calc_crc(struct scxfs_mount *, struct scxfs_dinode *);
void	scxfs_inode_to_disk(struct scxfs_inode *ip, struct scxfs_dinode *to,
			  scxfs_lsn_t lsn);
void	scxfs_inode_from_disk(struct scxfs_inode *ip, struct scxfs_dinode *from);
void	scxfs_log_dinode_to_disk(struct scxfs_log_dinode *from,
			       struct scxfs_dinode *to);

bool	scxfs_dinode_good_version(struct scxfs_mount *mp, __u8 version);

#if defined(DEBUG)
void	scxfs_inobp_check(struct scxfs_mount *, struct scxfs_buf *);
#else
#define	scxfs_inobp_check(mp, bp)
#endif /* DEBUG */

scxfs_failaddr_t scxfs_dinode_verify(struct scxfs_mount *mp, scxfs_ino_t ino,
			   struct scxfs_dinode *dip);
scxfs_failaddr_t scxfs_inode_validate_extsize(struct scxfs_mount *mp,
		uint32_t extsize, uint16_t mode, uint16_t flags);
scxfs_failaddr_t scxfs_inode_validate_cowextsize(struct scxfs_mount *mp,
		uint32_t cowextsize, uint16_t mode, uint16_t flags,
		uint64_t flags2);

#endif	/* __SCXFS_INODE_BUF_H__ */
