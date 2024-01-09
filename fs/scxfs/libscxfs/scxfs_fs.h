// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (c) 1995-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_FS_H__
#define __SCXFS_FS_H__

/*
 * SGI's SCXFS filesystem's major stuff (constants, structures)
 */

/*
 * Direct I/O attribute record used with SCXFS_IOC_DIOINFO
 * d_miniosz is the min xfer size, xfer size multiple and file seek offset
 * alignment.
 */
#ifndef HAVE_DIOATTR
struct dioattr {
	__u32		d_mem;		/* data buffer memory alignment */
	__u32		d_miniosz;	/* min xfer size		*/
	__u32		d_maxiosz;	/* max xfer size		*/
};
#endif

/*
 * Structure for SCXFS_IOC_GETBMAP.
 * On input, fill in bmv_offset and bmv_length of the first structure
 * to indicate the area of interest in the file, and bmv_entries with
 * the number of array elements given back.  The first structure is
 * updated on return to give the offset and length for the next call.
 */
#ifndef HAVE_GETBMAP
struct getbmap {
	__s64		bmv_offset;	/* file offset of segment in blocks */
	__s64		bmv_block;	/* starting block (64-bit daddr_t)  */
	__s64		bmv_length;	/* length of segment, blocks	    */
	__s32		bmv_count;	/* # of entries in array incl. 1st  */
	__s32		bmv_entries;	/* # of entries filled in (output)  */
};
#endif

/*
 *	Structure for SCXFS_IOC_GETBMAPX.	 Fields bmv_offset through bmv_entries
 *	are used exactly as in the getbmap structure.  The getbmapx structure
 *	has additional bmv_iflags and bmv_oflags fields. The bmv_iflags field
 *	is only used for the first structure.  It contains input flags
 *	specifying SCXFS_IOC_GETBMAPX actions.  The bmv_oflags field is filled
 *	in by the SCXFS_IOC_GETBMAPX command for each returned structure after
 *	the first.
 */
#ifndef HAVE_GETBMAPX
struct getbmapx {
	__s64		bmv_offset;	/* file offset of segment in blocks */
	__s64		bmv_block;	/* starting block (64-bit daddr_t)  */
	__s64		bmv_length;	/* length of segment, blocks	    */
	__s32		bmv_count;	/* # of entries in array incl. 1st  */
	__s32		bmv_entries;	/* # of entries filled in (output). */
	__s32		bmv_iflags;	/* input flags (1st structure)	    */
	__s32		bmv_oflags;	/* output flags (after 1st structure)*/
	__s32		bmv_unused1;	/* future use			    */
	__s32		bmv_unused2;	/* future use			    */
};
#endif

/*	bmv_iflags values - set by SCXFS_IOC_GETBMAPX caller.	*/
#define BMV_IF_ATTRFORK		0x1	/* return attr fork rather than data */
#define BMV_IF_NO_DMAPI_READ	0x2	/* Do not generate DMAPI read event  */
#define BMV_IF_PREALLOC		0x4	/* rtn status BMV_OF_PREALLOC if req */
#define BMV_IF_DELALLOC		0x8	/* rtn status BMV_OF_DELALLOC if req */
#define BMV_IF_NO_HOLES		0x10	/* Do not return holes */
#define BMV_IF_COWFORK		0x20	/* return CoW fork rather than data */
#define BMV_IF_VALID	\
	(BMV_IF_ATTRFORK|BMV_IF_NO_DMAPI_READ|BMV_IF_PREALLOC|	\
	 BMV_IF_DELALLOC|BMV_IF_NO_HOLES|BMV_IF_COWFORK)

/*	bmv_oflags values - returned for each non-header segment */
#define BMV_OF_PREALLOC		0x1	/* segment = unwritten pre-allocation */
#define BMV_OF_DELALLOC		0x2	/* segment = delayed allocation */
#define BMV_OF_LAST		0x4	/* segment is the last in the file */
#define BMV_OF_SHARED		0x8	/* segment shared with another file */

/*	fmr_owner special values for FS_IOC_GETFSMAP */
#define SCXFS_FMR_OWN_FREE	FMR_OWN_FREE      /* free space */
#define SCXFS_FMR_OWN_UNKNOWN	FMR_OWN_UNKNOWN   /* unknown owner */
#define SCXFS_FMR_OWN_FS		FMR_OWNER('X', 1) /* static fs metadata */
#define SCXFS_FMR_OWN_LOG		FMR_OWNER('X', 2) /* journalling log */
#define SCXFS_FMR_OWN_AG		FMR_OWNER('X', 3) /* per-AG metadata */
#define SCXFS_FMR_OWN_INOBT	FMR_OWNER('X', 4) /* inode btree blocks */
#define SCXFS_FMR_OWN_INODES	FMR_OWNER('X', 5) /* inodes */
#define SCXFS_FMR_OWN_REFC	FMR_OWNER('X', 6) /* refcount tree */
#define SCXFS_FMR_OWN_COW		FMR_OWNER('X', 7) /* cow staging */
#define SCXFS_FMR_OWN_DEFECTIVE	FMR_OWNER('X', 8) /* bad blocks */

/*
 * Structure for SCXFS_IOC_FSSETDM.
 * For use by backup and restore programs to set the SCXFS on-disk inode
 * fields di_dmevmask and di_dmstate.  These must be set to exactly and
 * only values previously obtained via scxfs_bulkstat!  (Specifically the
 * struct scxfs_bstat fields bs_dmevmask and bs_dmstate.)
 */
#ifndef HAVE_FSDMIDATA
struct fsdmidata {
	__u32		fsd_dmevmask;	/* corresponds to di_dmevmask */
	__u16		fsd_padding;
	__u16		fsd_dmstate;	/* corresponds to di_dmstate  */
};
#endif

/*
 * File segment locking set data type for 64 bit access.
 * Also used for all the RESV/FREE interfaces.
 */
typedef struct scxfs_flock64 {
	__s16		l_type;
	__s16		l_whence;
	__s64		l_start;
	__s64		l_len;		/* len == 0 means until end of file */
	__s32		l_sysid;
	__u32		l_pid;
	__s32		l_pad[4];	/* reserve area			    */
} scxfs_flock64_t;

/*
 * Output for SCXFS_IOC_FSGEOMETRY_V1
 */
struct scxfs_fsop_geom_v1 {
	__u32		blocksize;	/* filesystem (data) block size */
	__u32		rtextsize;	/* realtime extent size		*/
	__u32		agblocks;	/* fsblocks in an AG		*/
	__u32		agcount;	/* number of allocation groups	*/
	__u32		logblocks;	/* fsblocks in the log		*/
	__u32		sectsize;	/* (data) sector size, bytes	*/
	__u32		inodesize;	/* inode size in bytes		*/
	__u32		imaxpct;	/* max allowed inode space(%)	*/
	__u64		datablocks;	/* fsblocks in data subvolume	*/
	__u64		rtblocks;	/* fsblocks in realtime subvol	*/
	__u64		rtextents;	/* rt extents in realtime subvol*/
	__u64		logstart;	/* starting fsblock of the log	*/
	unsigned char	uuid[16];	/* unique id of the filesystem	*/
	__u32		sunit;		/* stripe unit, fsblocks	*/
	__u32		swidth;		/* stripe width, fsblocks	*/
	__s32		version;	/* structure version		*/
	__u32		flags;		/* superblock version flags	*/
	__u32		logsectsize;	/* log sector size, bytes	*/
	__u32		rtsectsize;	/* realtime sector size, bytes	*/
	__u32		dirblocksize;	/* directory block size, bytes	*/
};

/*
 * Output for SCXFS_IOC_FSGEOMETRY_V4
 */
struct scxfs_fsop_geom_v4 {
	__u32		blocksize;	/* filesystem (data) block size */
	__u32		rtextsize;	/* realtime extent size		*/
	__u32		agblocks;	/* fsblocks in an AG		*/
	__u32		agcount;	/* number of allocation groups	*/
	__u32		logblocks;	/* fsblocks in the log		*/
	__u32		sectsize;	/* (data) sector size, bytes	*/
	__u32		inodesize;	/* inode size in bytes		*/
	__u32		imaxpct;	/* max allowed inode space(%)	*/
	__u64		datablocks;	/* fsblocks in data subvolume	*/
	__u64		rtblocks;	/* fsblocks in realtime subvol	*/
	__u64		rtextents;	/* rt extents in realtime subvol*/
	__u64		logstart;	/* starting fsblock of the log	*/
	unsigned char	uuid[16];	/* unique id of the filesystem	*/
	__u32		sunit;		/* stripe unit, fsblocks	*/
	__u32		swidth;		/* stripe width, fsblocks	*/
	__s32		version;	/* structure version		*/
	__u32		flags;		/* superblock version flags	*/
	__u32		logsectsize;	/* log sector size, bytes	*/
	__u32		rtsectsize;	/* realtime sector size, bytes	*/
	__u32		dirblocksize;	/* directory block size, bytes	*/
	__u32		logsunit;	/* log stripe unit, bytes	*/
};

/*
 * Output for SCXFS_IOC_FSGEOMETRY
 */
struct scxfs_fsop_geom {
	__u32		blocksize;	/* filesystem (data) block size */
	__u32		rtextsize;	/* realtime extent size		*/
	__u32		agblocks;	/* fsblocks in an AG		*/
	__u32		agcount;	/* number of allocation groups	*/
	__u32		logblocks;	/* fsblocks in the log		*/
	__u32		sectsize;	/* (data) sector size, bytes	*/
	__u32		inodesize;	/* inode size in bytes		*/
	__u32		imaxpct;	/* max allowed inode space(%)	*/
	__u64		datablocks;	/* fsblocks in data subvolume	*/
	__u64		rtblocks;	/* fsblocks in realtime subvol	*/
	__u64		rtextents;	/* rt extents in realtime subvol*/
	__u64		logstart;	/* starting fsblock of the log	*/
	unsigned char	uuid[16];	/* unique id of the filesystem	*/
	__u32		sunit;		/* stripe unit, fsblocks	*/
	__u32		swidth;		/* stripe width, fsblocks	*/
	__s32		version;	/* structure version		*/
	__u32		flags;		/* superblock version flags	*/
	__u32		logsectsize;	/* log sector size, bytes	*/
	__u32		rtsectsize;	/* realtime sector size, bytes	*/
	__u32		dirblocksize;	/* directory block size, bytes	*/
	__u32		logsunit;	/* log stripe unit, bytes	*/
	uint32_t	sick;		/* o: unhealthy fs & rt metadata */
	uint32_t	checked;	/* o: checked fs & rt metadata	*/
	__u64		reserved[17];	/* reserved space		*/
};

#define SCXFS_FSOP_GEOM_SICK_COUNTERS	(1 << 0)  /* summary counters */
#define SCXFS_FSOP_GEOM_SICK_UQUOTA	(1 << 1)  /* user quota */
#define SCXFS_FSOP_GEOM_SICK_GQUOTA	(1 << 2)  /* group quota */
#define SCXFS_FSOP_GEOM_SICK_PQUOTA	(1 << 3)  /* project quota */
#define SCXFS_FSOP_GEOM_SICK_RT_BITMAP	(1 << 4)  /* realtime bitmap */
#define SCXFS_FSOP_GEOM_SICK_RT_SUMMARY	(1 << 5)  /* realtime summary */

/* Output for SCXFS_FS_COUNTS */
typedef struct scxfs_fsop_counts {
	__u64	freedata;	/* free data section blocks */
	__u64	freertx;	/* free rt extents */
	__u64	freeino;	/* free inodes */
	__u64	allocino;	/* total allocated inodes */
} scxfs_fsop_counts_t;

/* Input/Output for SCXFS_GET_RESBLKS and SCXFS_SET_RESBLKS */
typedef struct scxfs_fsop_resblks {
	__u64  resblks;
	__u64  resblks_avail;
} scxfs_fsop_resblks_t;

#define SCXFS_FSOP_GEOM_VERSION		0
#define SCXFS_FSOP_GEOM_VERSION_V5	5

#define SCXFS_FSOP_GEOM_FLAGS_ATTR	(1 << 0)  /* attributes in use	   */
#define SCXFS_FSOP_GEOM_FLAGS_NLINK	(1 << 1)  /* 32-bit nlink values   */
#define SCXFS_FSOP_GEOM_FLAGS_QUOTA	(1 << 2)  /* quotas enabled	   */
#define SCXFS_FSOP_GEOM_FLAGS_IALIGN	(1 << 3)  /* inode alignment	   */
#define SCXFS_FSOP_GEOM_FLAGS_DALIGN	(1 << 4)  /* large data alignment  */
#define SCXFS_FSOP_GEOM_FLAGS_SHARED	(1 << 5)  /* read-only shared	   */
#define SCXFS_FSOP_GEOM_FLAGS_EXTFLG	(1 << 6)  /* special extent flag   */
#define SCXFS_FSOP_GEOM_FLAGS_DIRV2	(1 << 7)  /* directory version 2   */
#define SCXFS_FSOP_GEOM_FLAGS_LOGV2	(1 << 8)  /* log format version 2  */
#define SCXFS_FSOP_GEOM_FLAGS_SECTOR	(1 << 9)  /* sector sizes >1BB	   */
#define SCXFS_FSOP_GEOM_FLAGS_ATTR2	(1 << 10) /* inline attributes rework */
#define SCXFS_FSOP_GEOM_FLAGS_PROJID32	(1 << 11) /* 32-bit project IDs	   */
#define SCXFS_FSOP_GEOM_FLAGS_DIRV2CI	(1 << 12) /* ASCII only CI names   */
	/*  -- Do not use --		(1 << 13)    SGI parent pointers   */
#define SCXFS_FSOP_GEOM_FLAGS_LAZYSB	(1 << 14) /* lazy superblock counters */
#define SCXFS_FSOP_GEOM_FLAGS_V5SB	(1 << 15) /* version 5 superblock  */
#define SCXFS_FSOP_GEOM_FLAGS_FTYPE	(1 << 16) /* inode directory types */
#define SCXFS_FSOP_GEOM_FLAGS_FINOBT	(1 << 17) /* free inode btree	   */
#define SCXFS_FSOP_GEOM_FLAGS_SPINODES	(1 << 18) /* sparse inode chunks   */
#define SCXFS_FSOP_GEOM_FLAGS_RMAPBT	(1 << 19) /* reverse mapping btree */
#define SCXFS_FSOP_GEOM_FLAGS_REFLINK	(1 << 20) /* files can share blocks */

/*
 * Minimum and maximum sizes need for growth checks.
 *
 * Block counts are in units of filesystem blocks, not basic blocks.
 */
#define SCXFS_MIN_AG_BLOCKS	64
#define SCXFS_MIN_LOG_BLOCKS	512ULL
#define SCXFS_MAX_LOG_BLOCKS	(1024 * 1024ULL)
#define SCXFS_MIN_LOG_BYTES	(10 * 1024 * 1024ULL)

/*
 * Limits on sb_agblocks/sb_agblklog -- mkfs won't format AGs smaller than
 * 16MB or larger than 1TB.
 */
#define SCXFS_MIN_AG_BYTES	(1ULL << 24)	/* 16 MB */
#define SCXFS_MAX_AG_BYTES	(1ULL << 40)	/* 1 TB */

/* keep the maximum size under 2^31 by a small amount */
#define SCXFS_MAX_LOG_BYTES \
	((2 * 1024 * 1024 * 1024ULL) - SCXFS_MIN_LOG_BYTES)

/* Used for sanity checks on superblock */
#define SCXFS_MAX_DBLOCKS(s) ((scxfs_rfsblock_t)(s)->sb_agcount * (s)->sb_agblocks)
#define SCXFS_MIN_DBLOCKS(s) ((scxfs_rfsblock_t)((s)->sb_agcount - 1) *	\
			 (s)->sb_agblocks + SCXFS_MIN_AG_BLOCKS)

/*
 * Output for SCXFS_IOC_AG_GEOMETRY
 */
struct scxfs_ag_geometry {
	uint32_t	ag_number;	/* i/o: AG number */
	uint32_t	ag_length;	/* o: length in blocks */
	uint32_t	ag_freeblks;	/* o: free space */
	uint32_t	ag_icount;	/* o: inodes allocated */
	uint32_t	ag_ifree;	/* o: inodes free */
	uint32_t	ag_sick;	/* o: sick things in ag */
	uint32_t	ag_checked;	/* o: checked metadata in ag */
	uint32_t	ag_flags;	/* i/o: flags for this ag */
	uint64_t	ag_reserved[12];/* o: zero */
};
#define SCXFS_AG_GEOM_SICK_SB	(1 << 0)  /* superblock */
#define SCXFS_AG_GEOM_SICK_AGF	(1 << 1)  /* AGF header */
#define SCXFS_AG_GEOM_SICK_AGFL	(1 << 2)  /* AGFL header */
#define SCXFS_AG_GEOM_SICK_AGI	(1 << 3)  /* AGI header */
#define SCXFS_AG_GEOM_SICK_BNOBT	(1 << 4)  /* free space by block */
#define SCXFS_AG_GEOM_SICK_CNTBT	(1 << 5)  /* free space by length */
#define SCXFS_AG_GEOM_SICK_INOBT	(1 << 6)  /* inode index */
#define SCXFS_AG_GEOM_SICK_FINOBT	(1 << 7)  /* free inode index */
#define SCXFS_AG_GEOM_SICK_RMAPBT	(1 << 8)  /* reverse mappings */
#define SCXFS_AG_GEOM_SICK_REFCNTBT (1 << 9)  /* reference counts */

/*
 * Structures for SCXFS_IOC_FSGROWFSDATA, SCXFS_IOC_FSGROWFSLOG & SCXFS_IOC_FSGROWFSRT
 */
typedef struct scxfs_growfs_data {
	__u64		newblocks;	/* new data subvol size, fsblocks */
	__u32		imaxpct;	/* new inode space percentage limit */
} scxfs_growfs_data_t;

typedef struct scxfs_growfs_log {
	__u32		newblocks;	/* new log size, fsblocks */
	__u32		isint;		/* 1 if new log is internal */
} scxfs_growfs_log_t;

typedef struct scxfs_growfs_rt {
	__u64		newblocks;	/* new realtime size, fsblocks */
	__u32		extsize;	/* new realtime extent size, fsblocks */
} scxfs_growfs_rt_t;


/*
 * Structures returned from ioctl SCXFS_IOC_FSBULKSTAT & SCXFS_IOC_FSBULKSTAT_SINGLE
 */
typedef struct scxfs_bstime {
	time_t		tv_sec;		/* seconds		*/
	__s32		tv_nsec;	/* and nanoseconds	*/
} scxfs_bstime_t;

struct scxfs_bstat {
	__u64		bs_ino;		/* inode number			*/
	__u16		bs_mode;	/* type and mode		*/
	__u16		bs_nlink;	/* number of links		*/
	__u32		bs_uid;		/* user id			*/
	__u32		bs_gid;		/* group id			*/
	__u32		bs_rdev;	/* device value			*/
	__s32		bs_blksize;	/* block size			*/
	__s64		bs_size;	/* file size			*/
	scxfs_bstime_t	bs_atime;	/* access time			*/
	scxfs_bstime_t	bs_mtime;	/* modify time			*/
	scxfs_bstime_t	bs_ctime;	/* inode change time		*/
	int64_t		bs_blocks;	/* number of blocks		*/
	__u32		bs_xflags;	/* extended flags		*/
	__s32		bs_extsize;	/* extent size			*/
	__s32		bs_extents;	/* number of extents		*/
	__u32		bs_gen;		/* generation count		*/
	__u16		bs_projid_lo;	/* lower part of project id	*/
#define	bs_projid	bs_projid_lo	/* (previously just bs_projid)	*/
	__u16		bs_forkoff;	/* inode fork offset in bytes	*/
	__u16		bs_projid_hi;	/* higher part of project id	*/
	uint16_t	bs_sick;	/* sick inode metadata		*/
	uint16_t	bs_checked;	/* checked inode metadata	*/
	unsigned char	bs_pad[2];	/* pad space, unused		*/
	__u32		bs_cowextsize;	/* cow extent size		*/
	__u32		bs_dmevmask;	/* DMIG event mask		*/
	__u16		bs_dmstate;	/* DMIG state info		*/
	__u16		bs_aextents;	/* attribute number of extents	*/
};

/* New bulkstat structure that reports v5 features and fixes padding issues */
struct scxfs_bulkstat {
	uint64_t	bs_ino;		/* inode number			*/
	uint64_t	bs_size;	/* file size			*/

	uint64_t	bs_blocks;	/* number of blocks		*/
	uint64_t	bs_xflags;	/* extended flags		*/

	int64_t		bs_atime;	/* access time, seconds		*/
	int64_t		bs_mtime;	/* modify time, seconds		*/

	int64_t		bs_ctime;	/* inode change time, seconds	*/
	int64_t		bs_btime;	/* creation time, seconds	*/

	uint32_t	bs_gen;		/* generation count		*/
	uint32_t	bs_uid;		/* user id			*/
	uint32_t	bs_gid;		/* group id			*/
	uint32_t	bs_projectid;	/* project id			*/

	uint32_t	bs_atime_nsec;	/* access time, nanoseconds	*/
	uint32_t	bs_mtime_nsec;	/* modify time, nanoseconds	*/
	uint32_t	bs_ctime_nsec;	/* inode change time, nanoseconds */
	uint32_t	bs_btime_nsec;	/* creation time, nanoseconds	*/

	uint32_t	bs_blksize;	/* block size			*/
	uint32_t	bs_rdev;	/* device value			*/
	uint32_t	bs_cowextsize_blks; /* cow extent size hint, blocks */
	uint32_t	bs_extsize_blks; /* extent size hint, blocks	*/

	uint32_t	bs_nlink;	/* number of links		*/
	uint32_t	bs_extents;	/* number of extents		*/
	uint32_t	bs_aextents;	/* attribute number of extents	*/
	uint16_t	bs_version;	/* structure version		*/
	uint16_t	bs_forkoff;	/* inode fork offset in bytes	*/

	uint16_t	bs_sick;	/* sick inode metadata		*/
	uint16_t	bs_checked;	/* checked inode metadata	*/
	uint16_t	bs_mode;	/* type and mode		*/
	uint16_t	bs_pad2;	/* zeroed			*/

	uint64_t	bs_pad[7];	/* zeroed			*/
};

#define SCXFS_BULKSTAT_VERSION_V1	(1)
#define SCXFS_BULKSTAT_VERSION_V5	(5)

/* bs_sick flags */
#define SCXFS_BS_SICK_INODE	(1 << 0)  /* inode core */
#define SCXFS_BS_SICK_BMBTD	(1 << 1)  /* data fork */
#define SCXFS_BS_SICK_BMBTA	(1 << 2)  /* attr fork */
#define SCXFS_BS_SICK_BMBTC	(1 << 3)  /* cow fork */
#define SCXFS_BS_SICK_DIR		(1 << 4)  /* directory */
#define SCXFS_BS_SICK_XATTR	(1 << 5)  /* extended attributes */
#define SCXFS_BS_SICK_SYMLINK	(1 << 6)  /* symbolic link remote target */
#define SCXFS_BS_SICK_PARENT	(1 << 7)  /* parent pointers */

/*
 * Project quota id helpers (previously projid was 16bit only
 * and using two 16bit values to hold new 32bit projid was choosen
 * to retain compatibility with "old" filesystems).
 */
static inline uint32_t
bstat_get_projid(const struct scxfs_bstat *bs)
{
	return (uint32_t)bs->bs_projid_hi << 16 | bs->bs_projid_lo;
}

/*
 * The user-level BulkStat Request interface structure.
 */
struct scxfs_fsop_bulkreq {
	__u64		__user *lastip;	/* last inode # pointer		*/
	__s32		icount;		/* count of entries in buffer	*/
	void		__user *ubuffer;/* user buffer for inode desc.	*/
	__s32		__user *ocount;	/* output count pointer		*/
};

/*
 * Structures returned from scxfs_inumbers routine (SCXFS_IOC_FSINUMBERS).
 */
struct scxfs_inogrp {
	__u64		xi_startino;	/* starting inode number	*/
	__s32		xi_alloccount;	/* # bits set in allocmask	*/
	__u64		xi_allocmask;	/* mask of allocated inodes	*/
};

/* New inumbers structure that reports v5 features and fixes padding issues */
struct scxfs_inumbers {
	uint64_t	xi_startino;	/* starting inode number	*/
	uint64_t	xi_allocmask;	/* mask of allocated inodes	*/
	uint8_t		xi_alloccount;	/* # bits set in allocmask	*/
	uint8_t		xi_version;	/* version			*/
	uint8_t		xi_padding[6];	/* zero				*/
};

#define SCXFS_INUMBERS_VERSION_V1	(1)
#define SCXFS_INUMBERS_VERSION_V5	(5)

/* Header for bulk inode requests. */
struct scxfs_bulk_ireq {
	uint64_t	ino;		/* I/O: start with this inode	*/
	uint32_t	flags;		/* I/O: operation flags		*/
	uint32_t	icount;		/* I: count of entries in buffer */
	uint32_t	ocount;		/* O: count of entries filled out */
	uint32_t	agno;		/* I: see comment for IREQ_AGNO	*/
	uint64_t	reserved[5];	/* must be zero			*/
};

/*
 * Only return results from the specified @agno.  If @ino is zero, start
 * with the first inode of @agno.
 */
#define SCXFS_BULK_IREQ_AGNO	(1 << 0)

/*
 * Return bulkstat information for a single inode, where @ino value is a
 * special value, not a literal inode number.  See the SCXFS_BULK_IREQ_SPECIAL_*
 * values below.  Not compatible with SCXFS_BULK_IREQ_AGNO.
 */
#define SCXFS_BULK_IREQ_SPECIAL	(1 << 1)

#define SCXFS_BULK_IREQ_FLAGS_ALL	(SCXFS_BULK_IREQ_AGNO | \
				 SCXFS_BULK_IREQ_SPECIAL)

/* Operate on the root directory inode. */
#define SCXFS_BULK_IREQ_SPECIAL_ROOT	(1)

/*
 * ioctl structures for v5 bulkstat and inumbers requests
 */
struct scxfs_bulkstat_req {
	struct scxfs_bulk_ireq	hdr;
	struct scxfs_bulkstat	bulkstat[];
};
#define SCXFS_BULKSTAT_REQ_SIZE(nr)	(sizeof(struct scxfs_bulkstat_req) + \
					 (nr) * sizeof(struct scxfs_bulkstat))

struct scxfs_inumbers_req {
	struct scxfs_bulk_ireq	hdr;
	struct scxfs_inumbers	inumbers[];
};
#define SCXFS_INUMBERS_REQ_SIZE(nr)	(sizeof(struct scxfs_inumbers_req) + \
					 (nr) * sizeof(struct scxfs_inumbers))

/*
 * Error injection.
 */
typedef struct scxfs_error_injection {
	__s32		fd;
	__s32		errtag;
} scxfs_error_injection_t;


/*
 * Speculative preallocation trimming.
 */
#define SCXFS_EOFBLOCKS_VERSION		1
struct scxfs_fs_eofblocks {
	__u32		eof_version;
	__u32		eof_flags;
	uid_t		eof_uid;
	gid_t		eof_gid;
	prid_t		eof_prid;
	__u32		pad32;
	__u64		eof_min_file_size;
	__u64		pad64[12];
};

/* eof_flags values */
#define SCXFS_EOF_FLAGS_SYNC		(1 << 0) /* sync/wait mode scan */
#define SCXFS_EOF_FLAGS_UID		(1 << 1) /* filter by uid */
#define SCXFS_EOF_FLAGS_GID		(1 << 2) /* filter by gid */
#define SCXFS_EOF_FLAGS_PRID		(1 << 3) /* filter by project id */
#define SCXFS_EOF_FLAGS_MINFILESIZE	(1 << 4) /* filter by min file size */
#define SCXFS_EOF_FLAGS_UNION		(1 << 5) /* union filter algorithm;
						  * kernel only, not included in
						  * valid mask */
#define SCXFS_EOF_FLAGS_VALID	\
	(SCXFS_EOF_FLAGS_SYNC |	\
	 SCXFS_EOF_FLAGS_UID |	\
	 SCXFS_EOF_FLAGS_GID |	\
	 SCXFS_EOF_FLAGS_PRID |	\
	 SCXFS_EOF_FLAGS_MINFILESIZE)


/*
 * The user-level Handle Request interface structure.
 */
typedef struct scxfs_fsop_handlereq {
	__u32		fd;		/* fd for FD_TO_HANDLE		*/
	void		__user *path;	/* user pathname		*/
	__u32		oflags;		/* open flags			*/
	void		__user *ihandle;/* user supplied handle		*/
	__u32		ihandlen;	/* user supplied length		*/
	void		__user *ohandle;/* user buffer for handle	*/
	__u32		__user *ohandlen;/* user buffer length		*/
} scxfs_fsop_handlereq_t;

/*
 * Compound structures for passing args through Handle Request interfaces
 * scxfs_fssetdm_by_handle, scxfs_attrlist_by_handle, scxfs_attrmulti_by_handle
 * - ioctls: SCXFS_IOC_FSSETDM_BY_HANDLE, SCXFS_IOC_ATTRLIST_BY_HANDLE, and
 *	     SCXFS_IOC_ATTRMULTI_BY_HANDLE
 */

typedef struct scxfs_fsop_setdm_handlereq {
	struct scxfs_fsop_handlereq	hreq;	/* handle information	*/
	struct fsdmidata		__user *data;	/* DMAPI data	*/
} scxfs_fsop_setdm_handlereq_t;

typedef struct scxfs_attrlist_cursor {
	__u32		opaque[4];
} scxfs_attrlist_cursor_t;

typedef struct scxfs_fsop_attrlist_handlereq {
	struct scxfs_fsop_handlereq	hreq; /* handle interface structure */
	struct scxfs_attrlist_cursor	pos; /* opaque cookie, list offset */
	__u32				flags;	/* which namespace to use */
	__u32				buflen;	/* length of buffer supplied */
	void				__user *buffer;	/* returned names */
} scxfs_fsop_attrlist_handlereq_t;

typedef struct scxfs_attr_multiop {
	__u32		am_opcode;
#define ATTR_OP_GET	1	/* return the indicated attr's value */
#define ATTR_OP_SET	2	/* set/create the indicated attr/value pair */
#define ATTR_OP_REMOVE	3	/* remove the indicated attr */
	__s32		am_error;
	void		__user *am_attrname;
	void		__user *am_attrvalue;
	__u32		am_length;
	__u32		am_flags;
} scxfs_attr_multiop_t;

typedef struct scxfs_fsop_attrmulti_handlereq {
	struct scxfs_fsop_handlereq	hreq; /* handle interface structure */
	__u32				opcount;/* count of following multiop */
	struct scxfs_attr_multiop		__user *ops; /* attr_multi data */
} scxfs_fsop_attrmulti_handlereq_t;

/*
 * per machine unique filesystem identifier types.
 */
typedef struct { __u32 val[2]; } scxfs_fsid_t; /* file system id type */

typedef struct scxfs_fid {
	__u16	fid_len;		/* length of remainder	*/
	__u16	fid_pad;
	__u32	fid_gen;		/* generation number	*/
	__u64	fid_ino;		/* 64 bits inode number */
} scxfs_fid_t;

typedef struct scxfs_handle {
	union {
		__s64	    align;	/* force alignment of ha_fid	 */
		scxfs_fsid_t  _ha_fsid;	/* unique file system identifier */
	} ha_u;
	scxfs_fid_t	ha_fid;		/* file system specific file ID	 */
} scxfs_handle_t;
#define ha_fsid ha_u._ha_fsid

/*
 * Structure passed to SCXFS_IOC_SWAPEXT
 */
typedef struct scxfs_swapext
{
	int64_t		sx_version;	/* version */
#define SCXFS_SX_VERSION		0
	int64_t		sx_fdtarget;	/* fd of target file */
	int64_t		sx_fdtmp;	/* fd of tmp file */
	scxfs_off_t	sx_offset;	/* offset into file */
	scxfs_off_t	sx_length;	/* leng from offset */
	char		sx_pad[16];	/* pad space, unused */
	struct scxfs_bstat sx_stat;	/* stat of target b4 copy */
} scxfs_swapext_t;

/*
 * Flags for going down operation
 */
#define SCXFS_FSOP_GOING_FLAGS_DEFAULT		0x0	/* going down */
#define SCXFS_FSOP_GOING_FLAGS_LOGFLUSH		0x1	/* flush log but not data */
#define SCXFS_FSOP_GOING_FLAGS_NOLOGFLUSH		0x2	/* don't flush log nor data */

/* metadata scrubbing */
struct scxfs_scrub_metadata {
	__u32 sm_type;		/* What to check? */
	__u32 sm_flags;		/* flags; see below. */
	__u64 sm_ino;		/* inode number. */
	__u32 sm_gen;		/* inode generation. */
	__u32 sm_agno;		/* ag number. */
	__u64 sm_reserved[5];	/* pad to 64 bytes */
};

/*
 * Metadata types and flags for scrub operation.
 */

/* Scrub subcommands. */
#define SCXFS_SCRUB_TYPE_PROBE	0	/* presence test ioctl */
#define SCXFS_SCRUB_TYPE_SB	1	/* superblock */
#define SCXFS_SCRUB_TYPE_AGF	2	/* AG free header */
#define SCXFS_SCRUB_TYPE_AGFL	3	/* AG free list */
#define SCXFS_SCRUB_TYPE_AGI	4	/* AG inode header */
#define SCXFS_SCRUB_TYPE_BNOBT	5	/* freesp by block btree */
#define SCXFS_SCRUB_TYPE_CNTBT	6	/* freesp by length btree */
#define SCXFS_SCRUB_TYPE_INOBT	7	/* inode btree */
#define SCXFS_SCRUB_TYPE_FINOBT	8	/* free inode btree */
#define SCXFS_SCRUB_TYPE_RMAPBT	9	/* reverse mapping btree */
#define SCXFS_SCRUB_TYPE_REFCNTBT	10	/* reference count btree */
#define SCXFS_SCRUB_TYPE_INODE	11	/* inode record */
#define SCXFS_SCRUB_TYPE_BMBTD	12	/* data fork block mapping */
#define SCXFS_SCRUB_TYPE_BMBTA	13	/* attr fork block mapping */
#define SCXFS_SCRUB_TYPE_BMBTC	14	/* CoW fork block mapping */
#define SCXFS_SCRUB_TYPE_DIR	15	/* directory */
#define SCXFS_SCRUB_TYPE_XATTR	16	/* extended attribute */
#define SCXFS_SCRUB_TYPE_SYMLINK	17	/* symbolic link */
#define SCXFS_SCRUB_TYPE_PARENT	18	/* parent pointers */
#define SCXFS_SCRUB_TYPE_RTBITMAP	19	/* realtime bitmap */
#define SCXFS_SCRUB_TYPE_RTSUM	20	/* realtime summary */
#define SCXFS_SCRUB_TYPE_UQUOTA	21	/* user quotas */
#define SCXFS_SCRUB_TYPE_GQUOTA	22	/* group quotas */
#define SCXFS_SCRUB_TYPE_PQUOTA	23	/* project quotas */
#define SCXFS_SCRUB_TYPE_FSCOUNTERS 24	/* fs summary counters */

/* Number of scrub subcommands. */
#define SCXFS_SCRUB_TYPE_NR	25

/* i: Repair this metadata. */
#define SCXFS_SCRUB_IFLAG_REPAIR		(1 << 0)

/* o: Metadata object needs repair. */
#define SCXFS_SCRUB_OFLAG_CORRUPT		(1 << 1)

/*
 * o: Metadata object could be optimized.  It's not corrupt, but
 *    we could improve on it somehow.
 */
#define SCXFS_SCRUB_OFLAG_PREEN		(1 << 2)

/* o: Cross-referencing failed. */
#define SCXFS_SCRUB_OFLAG_XFAIL		(1 << 3)

/* o: Metadata object disagrees with cross-referenced metadata. */
#define SCXFS_SCRUB_OFLAG_XCORRUPT	(1 << 4)

/* o: Scan was not complete. */
#define SCXFS_SCRUB_OFLAG_INCOMPLETE	(1 << 5)

/* o: Metadata object looked funny but isn't corrupt. */
#define SCXFS_SCRUB_OFLAG_WARNING		(1 << 6)

/*
 * o: IFLAG_REPAIR was set but metadata object did not need fixing or
 *    optimization and has therefore not been altered.
 */
#define SCXFS_SCRUB_OFLAG_NO_REPAIR_NEEDED (1 << 7)

#define SCXFS_SCRUB_FLAGS_IN	(SCXFS_SCRUB_IFLAG_REPAIR)
#define SCXFS_SCRUB_FLAGS_OUT	(SCXFS_SCRUB_OFLAG_CORRUPT | \
				 SCXFS_SCRUB_OFLAG_PREEN | \
				 SCXFS_SCRUB_OFLAG_XFAIL | \
				 SCXFS_SCRUB_OFLAG_XCORRUPT | \
				 SCXFS_SCRUB_OFLAG_INCOMPLETE | \
				 SCXFS_SCRUB_OFLAG_WARNING | \
				 SCXFS_SCRUB_OFLAG_NO_REPAIR_NEEDED)
#define SCXFS_SCRUB_FLAGS_ALL	(SCXFS_SCRUB_FLAGS_IN | SCXFS_SCRUB_FLAGS_OUT)

/*
 * ioctl limits
 */
#ifdef XATTR_LIST_MAX
#  define SCXFS_XATTR_LIST_MAX XATTR_LIST_MAX
#else
#  define SCXFS_XATTR_LIST_MAX 65536
#endif


/*
 * ioctl commands that are used by Linux filesystems
 */
#define SCXFS_IOC_GETXFLAGS	FS_IOC_GETFLAGS
#define SCXFS_IOC_SETXFLAGS	FS_IOC_SETFLAGS
#define SCXFS_IOC_GETVERSION	FS_IOC_GETVERSION

/*
 * ioctl commands that replace IRIX fcntl()'s
 * For 'documentation' purposed more than anything else,
 * the "cmd #" field reflects the IRIX fcntl number.
 */
#define SCXFS_IOC_ALLOCSP		_IOW ('X', 10, struct scxfs_flock64)
#define SCXFS_IOC_FREESP		_IOW ('X', 11, struct scxfs_flock64)
#define SCXFS_IOC_DIOINFO		_IOR ('X', 30, struct dioattr)
#define SCXFS_IOC_FSGETXATTR	FS_IOC_FSGETXATTR
#define SCXFS_IOC_FSSETXATTR	FS_IOC_FSSETXATTR
#define SCXFS_IOC_ALLOCSP64	_IOW ('X', 36, struct scxfs_flock64)
#define SCXFS_IOC_FREESP64	_IOW ('X', 37, struct scxfs_flock64)
#define SCXFS_IOC_GETBMAP		_IOWR('X', 38, struct getbmap)
#define SCXFS_IOC_FSSETDM		_IOW ('X', 39, struct fsdmidata)
#define SCXFS_IOC_RESVSP		_IOW ('X', 40, struct scxfs_flock64)
#define SCXFS_IOC_UNRESVSP	_IOW ('X', 41, struct scxfs_flock64)
#define SCXFS_IOC_RESVSP64	_IOW ('X', 42, struct scxfs_flock64)
#define SCXFS_IOC_UNRESVSP64	_IOW ('X', 43, struct scxfs_flock64)
#define SCXFS_IOC_GETBMAPA	_IOWR('X', 44, struct getbmap)
#define SCXFS_IOC_FSGETXATTRA	_IOR ('X', 45, struct fsxattr)
/*	SCXFS_IOC_SETBIOSIZE ---- deprecated 46	   */
/*	SCXFS_IOC_GETBIOSIZE ---- deprecated 47	   */
#define SCXFS_IOC_GETBMAPX	_IOWR('X', 56, struct getbmap)
#define SCXFS_IOC_ZERO_RANGE	_IOW ('X', 57, struct scxfs_flock64)
#define SCXFS_IOC_FREE_EOFBLOCKS	_IOR ('X', 58, struct scxfs_fs_eofblocks)
/*	SCXFS_IOC_GETFSMAP ------ hoisted 59         */
#define SCXFS_IOC_SCRUB_METADATA	_IOWR('X', 60, struct scxfs_scrub_metadata)
#define SCXFS_IOC_AG_GEOMETRY	_IOWR('X', 61, struct scxfs_ag_geometry)

/*
 * ioctl commands that replace IRIX syssgi()'s
 */
#define SCXFS_IOC_FSGEOMETRY_V1	     _IOR ('X', 100, struct scxfs_fsop_geom_v1)
#define SCXFS_IOC_FSBULKSTAT	     _IOWR('X', 101, struct scxfs_fsop_bulkreq)
#define SCXFS_IOC_FSBULKSTAT_SINGLE    _IOWR('X', 102, struct scxfs_fsop_bulkreq)
#define SCXFS_IOC_FSINUMBERS	     _IOWR('X', 103, struct scxfs_fsop_bulkreq)
#define SCXFS_IOC_PATH_TO_FSHANDLE     _IOWR('X', 104, struct scxfs_fsop_handlereq)
#define SCXFS_IOC_PATH_TO_HANDLE	     _IOWR('X', 105, struct scxfs_fsop_handlereq)
#define SCXFS_IOC_FD_TO_HANDLE	     _IOWR('X', 106, struct scxfs_fsop_handlereq)
#define SCXFS_IOC_OPEN_BY_HANDLE	     _IOWR('X', 107, struct scxfs_fsop_handlereq)
#define SCXFS_IOC_READLINK_BY_HANDLE   _IOWR('X', 108, struct scxfs_fsop_handlereq)
#define SCXFS_IOC_SWAPEXT		     _IOWR('X', 109, struct scxfs_swapext)
#define SCXFS_IOC_FSGROWFSDATA	     _IOW ('X', 110, struct scxfs_growfs_data)
#define SCXFS_IOC_FSGROWFSLOG	     _IOW ('X', 111, struct scxfs_growfs_log)
#define SCXFS_IOC_FSGROWFSRT	     _IOW ('X', 112, struct scxfs_growfs_rt)
#define SCXFS_IOC_FSCOUNTS	     _IOR ('X', 113, struct scxfs_fsop_counts)
#define SCXFS_IOC_SET_RESBLKS	     _IOWR('X', 114, struct scxfs_fsop_resblks)
#define SCXFS_IOC_GET_RESBLKS	     _IOR ('X', 115, struct scxfs_fsop_resblks)
#define SCXFS_IOC_ERROR_INJECTION	     _IOW ('X', 116, struct scxfs_error_injection)
#define SCXFS_IOC_ERROR_CLEARALL	     _IOW ('X', 117, struct scxfs_error_injection)
/*	SCXFS_IOC_ATTRCTL_BY_HANDLE -- deprecated 118	 */

#define SCXFS_IOC_FREEZE		     _IOWR('X', 119, int)	/* aka FIFREEZE */
#define SCXFS_IOC_THAW		     _IOWR('X', 120, int)	/* aka FITHAW */

#define SCXFS_IOC_FSSETDM_BY_HANDLE    _IOW ('X', 121, struct scxfs_fsop_setdm_handlereq)
#define SCXFS_IOC_ATTRLIST_BY_HANDLE   _IOW ('X', 122, struct scxfs_fsop_attrlist_handlereq)
#define SCXFS_IOC_ATTRMULTI_BY_HANDLE  _IOW ('X', 123, struct scxfs_fsop_attrmulti_handlereq)
#define SCXFS_IOC_FSGEOMETRY_V4	     _IOR ('X', 124, struct scxfs_fsop_geom_v4)
#define SCXFS_IOC_GOINGDOWN	     _IOR ('X', 125, uint32_t)
#define SCXFS_IOC_FSGEOMETRY	     _IOR ('X', 126, struct scxfs_fsop_geom)
#define SCXFS_IOC_BULKSTAT	     _IOR ('X', 127, struct scxfs_bulkstat_req)
#define SCXFS_IOC_INUMBERS	     _IOR ('X', 128, struct scxfs_inumbers_req)
/*	SCXFS_IOC_GETFSUUID ---------- deprecated 140	 */


#ifndef HAVE_BBMACROS
/*
 * Block I/O parameterization.	A basic block (BB) is the lowest size of
 * filesystem allocation, and must equal 512.  Length units given to bio
 * routines are in BB's.
 */
#define BBSHIFT		9
#define BBSIZE		(1<<BBSHIFT)
#define BBMASK		(BBSIZE-1)
#define BTOBB(bytes)	(((__u64)(bytes) + BBSIZE - 1) >> BBSHIFT)
#define BTOBBT(bytes)	((__u64)(bytes) >> BBSHIFT)
#define BBTOB(bbs)	((bbs) << BBSHIFT)
#endif

#endif	/* __SCXFS_FS_H__ */
