// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_TYPES_H__
#define	__SCXFS_TYPES_H__

typedef uint32_t	prid_t;		/* project ID */

typedef uint32_t	scxfs_agblock_t;	/* blockno in alloc. group */
typedef uint32_t	scxfs_agino_t;	/* inode # within allocation grp */
typedef uint32_t	scxfs_extlen_t;	/* extent length in blocks */
typedef uint32_t	scxfs_agnumber_t;	/* allocation group number */
typedef int32_t		scxfs_extnum_t;	/* # of extents in a file */
typedef int16_t		scxfs_aextnum_t;	/* # extents in an attribute fork */
typedef int64_t		scxfs_fsize_t;	/* bytes in a file */
typedef uint64_t	scxfs_ufsize_t;	/* unsigned bytes in a file */

typedef int32_t		scxfs_suminfo_t;	/* type of bitmap summary info */
typedef uint32_t	scxfs_rtword_t;	/* word type for bitmap manipulations */

typedef int64_t		scxfs_lsn_t;	/* log sequence number */
typedef int32_t		scxfs_tid_t;	/* transaction identifier */

typedef uint32_t	scxfs_dablk_t;	/* dir/attr block number (in file) */
typedef uint32_t	scxfs_dahash_t;	/* dir/attr hash value */

typedef uint64_t	scxfs_fsblock_t;	/* blockno in filesystem (agno|agbno) */
typedef uint64_t	scxfs_rfsblock_t;	/* blockno in filesystem (raw) */
typedef uint64_t	scxfs_rtblock_t;	/* extent (block) in realtime area */
typedef uint64_t	scxfs_fileoff_t;	/* block number in a file */
typedef uint64_t	scxfs_filblks_t;	/* number of blocks in a file */

typedef int64_t		scxfs_srtblock_t;	/* signed version of scxfs_rtblock_t */
typedef int64_t		scxfs_sfiloff_t;	/* signed block number in a file */

/*
 * New verifiers will return the instruction address of the failing check.
 * NULL means everything is ok.
 */
typedef void *		scxfs_failaddr_t;

/*
 * Null values for the types.
 */
#define	NULLFSBLOCK	((scxfs_fsblock_t)-1)
#define	NULLRFSBLOCK	((scxfs_rfsblock_t)-1)
#define	NULLRTBLOCK	((scxfs_rtblock_t)-1)
#define	NULLFILEOFF	((scxfs_fileoff_t)-1)

#define	NULLAGBLOCK	((scxfs_agblock_t)-1)
#define	NULLAGNUMBER	((scxfs_agnumber_t)-1)

#define NULLCOMMITLSN	((scxfs_lsn_t)-1)

#define	NULLFSINO	((scxfs_ino_t)-1)
#define	NULLAGINO	((scxfs_agino_t)-1)

/*
 * Max values for extlen, extnum, aextnum.
 */
#define	MAXEXTLEN	((scxfs_extlen_t)0x001fffff)	/* 21 bits */
#define	MAXEXTNUM	((scxfs_extnum_t)0x7fffffff)	/* signed int */
#define	MAXAEXTNUM	((scxfs_aextnum_t)0x7fff)		/* signed short */

/*
 * Minimum and maximum blocksize and sectorsize.
 * The blocksize upper limit is pretty much arbitrary.
 * The sectorsize upper limit is due to sizeof(sb_sectsize).
 * CRC enable filesystems use 512 byte inodes, meaning 512 byte block sizes
 * cannot be used.
 */
#define SCXFS_MIN_BLOCKSIZE_LOG	9	/* i.e. 512 bytes */
#define SCXFS_MAX_BLOCKSIZE_LOG	16	/* i.e. 65536 bytes */
#define SCXFS_MIN_BLOCKSIZE	(1 << SCXFS_MIN_BLOCKSIZE_LOG)
#define SCXFS_MAX_BLOCKSIZE	(1 << SCXFS_MAX_BLOCKSIZE_LOG)
#define SCXFS_MIN_CRC_BLOCKSIZE	(1 << (SCXFS_MIN_BLOCKSIZE_LOG + 1))
#define SCXFS_MIN_SECTORSIZE_LOG	9	/* i.e. 512 bytes */
#define SCXFS_MAX_SECTORSIZE_LOG	15	/* i.e. 32768 bytes */
#define SCXFS_MIN_SECTORSIZE	(1 << SCXFS_MIN_SECTORSIZE_LOG)
#define SCXFS_MAX_SECTORSIZE	(1 << SCXFS_MAX_SECTORSIZE_LOG)

/*
 * Inode fork identifiers.
 */
#define	SCXFS_DATA_FORK	0
#define	SCXFS_ATTR_FORK	1
#define	SCXFS_COW_FORK	2

/*
 * Min numbers of data/attr fork btree root pointers.
 */
#define MINDBTPTRS	3
#define MINABTPTRS	2

/*
 * MAXNAMELEN is the length (including the terminating null) of
 * the longest permissible file (component) name.
 */
#define MAXNAMELEN	256

/*
 * This enum is used in string mapping in scxfs_trace.h; please keep the
 * TRACE_DEFINE_ENUMs for it up to date.
 */
typedef enum {
	SCXFS_LOOKUP_EQi, SCXFS_LOOKUP_LEi, SCXFS_LOOKUP_GEi
} scxfs_lookup_t;

#define SCXFS_AG_BTREE_CMP_FORMAT_STR \
	{ SCXFS_LOOKUP_EQi,	"eq" }, \
	{ SCXFS_LOOKUP_LEi,	"le" }, \
	{ SCXFS_LOOKUP_GEi,	"ge" }

/*
 * This enum is used in string mapping in scxfs_trace.h and scrub/trace.h;
 * please keep the TRACE_DEFINE_ENUMs for it up to date.
 */
typedef enum {
	SCXFS_BTNUM_BNOi, SCXFS_BTNUM_CNTi, SCXFS_BTNUM_RMAPi, SCXFS_BTNUM_BMAPi,
	SCXFS_BTNUM_INOi, SCXFS_BTNUM_FINOi, SCXFS_BTNUM_REFCi, SCXFS_BTNUM_MAX
} scxfs_btnum_t;

#define SCXFS_BTNUM_STRINGS \
	{ SCXFS_BTNUM_BNOi,	"bnobt" }, \
	{ SCXFS_BTNUM_CNTi,	"cntbt" }, \
	{ SCXFS_BTNUM_RMAPi,	"rmapbt" }, \
	{ SCXFS_BTNUM_BMAPi,	"bmbt" }, \
	{ SCXFS_BTNUM_INOi,	"inobt" }, \
	{ SCXFS_BTNUM_FINOi,	"finobt" }, \
	{ SCXFS_BTNUM_REFCi,	"refcbt" }

struct scxfs_name {
	const unsigned char	*name;
	int			len;
	int			type;
};

/*
 * uid_t and gid_t are hard-coded to 32 bits in the inode.
 * Hence, an 'id' in a dquot is 32 bits..
 */
typedef uint32_t	scxfs_dqid_t;

/*
 * Constants for bit manipulations.
 */
#define	SCXFS_NBBYLOG	3		/* log2(NBBY) */
#define	SCXFS_WORDLOG	2		/* log2(sizeof(scxfs_rtword_t)) */
#define	SCXFS_NBWORDLOG	(SCXFS_NBBYLOG + SCXFS_WORDLOG)
#define	SCXFS_NBWORD	(1 << SCXFS_NBWORDLOG)
#define	SCXFS_WORDMASK	((1 << SCXFS_WORDLOG) - 1)

struct scxfs_iext_cursor {
	struct scxfs_iext_leaf	*leaf;
	int			pos;
};

typedef enum {
	SCXFS_EXT_NORM, SCXFS_EXT_UNWRITTEN,
} scxfs_exntst_t;

typedef struct scxfs_bmbt_irec
{
	scxfs_fileoff_t	br_startoff;	/* starting file offset */
	scxfs_fsblock_t	br_startblock;	/* starting block number */
	scxfs_filblks_t	br_blockcount;	/* number of blocks */
	scxfs_exntst_t	br_state;	/* extent state */
} scxfs_bmbt_irec_t;

/* per-AG block reservation types */
enum scxfs_ag_resv_type {
	SCXFS_AG_RESV_NONE = 0,
	SCXFS_AG_RESV_AGFL,
	SCXFS_AG_RESV_METADATA,
	SCXFS_AG_RESV_RMAPBT,
};

/*
 * Type verifier functions
 */
struct scxfs_mount;

scxfs_agblock_t scxfs_ag_block_count(struct scxfs_mount *mp, scxfs_agnumber_t agno);
bool scxfs_verify_agbno(struct scxfs_mount *mp, scxfs_agnumber_t agno,
		scxfs_agblock_t agbno);
bool scxfs_verify_fsbno(struct scxfs_mount *mp, scxfs_fsblock_t fsbno);

void scxfs_agino_range(struct scxfs_mount *mp, scxfs_agnumber_t agno,
		scxfs_agino_t *first, scxfs_agino_t *last);
bool scxfs_verify_agino(struct scxfs_mount *mp, scxfs_agnumber_t agno,
		scxfs_agino_t agino);
bool scxfs_verify_agino_or_null(struct scxfs_mount *mp, scxfs_agnumber_t agno,
		scxfs_agino_t agino);
bool scxfs_verify_ino(struct scxfs_mount *mp, scxfs_ino_t ino);
bool scxfs_internal_inum(struct scxfs_mount *mp, scxfs_ino_t ino);
bool scxfs_verify_dir_ino(struct scxfs_mount *mp, scxfs_ino_t ino);
bool scxfs_verify_rtbno(struct scxfs_mount *mp, scxfs_rtblock_t rtbno);
bool scxfs_verify_icount(struct scxfs_mount *mp, unsigned long long icount);
bool scxfs_verify_dablk(struct scxfs_mount *mp, scxfs_fileoff_t off);
void scxfs_icount_range(struct scxfs_mount *mp, unsigned long long *min,
		unsigned long long *max);

#endif	/* __SCXFS_TYPES_H__ */
