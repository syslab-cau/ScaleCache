// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002,2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_DA_BTREE_H__
#define	__SCXFS_DA_BTREE_H__

struct scxfs_inode;
struct scxfs_trans;
struct zone;
struct scxfs_dir_ops;

/*
 * Directory/attribute geometry information. There will be one of these for each
 * data fork type, and it will be passed around via the scxfs_da_args. Global
 * structures will be attached to the scxfs_mount.
 */
struct scxfs_da_geometry {
	int		blksize;	/* da block size in bytes */
	int		fsbcount;	/* da block size in filesystem blocks */
	uint8_t		fsblog;		/* log2 of _filesystem_ block size */
	uint8_t		blklog;		/* log2 of da block size */
	uint		node_ents;	/* # of entries in a danode */
	int		magicpct;	/* 37% of block size in bytes */
	scxfs_dablk_t	datablk;	/* blockno of dir data v2 */
	scxfs_dablk_t	leafblk;	/* blockno of leaf data v2 */
	scxfs_dablk_t	freeblk;	/* blockno of free data v2 */
};

/*========================================================================
 * Btree searching and modification structure definitions.
 *========================================================================*/

/*
 * Search comparison results
 */
enum scxfs_dacmp {
	SCXFS_CMP_DIFFERENT,	/* names are completely different */
	SCXFS_CMP_EXACT,		/* names are exactly the same */
	SCXFS_CMP_CASE		/* names are same but differ in case */
};

/*
 * Structure to ease passing around component names.
 */
typedef struct scxfs_da_args {
	struct scxfs_da_geometry *geo;	/* da block geometry */
	const uint8_t		*name;		/* string (maybe not NULL terminated) */
	int		namelen;	/* length of string (maybe no NULL) */
	uint8_t		filetype;	/* filetype of inode for directories */
	uint8_t		*value;		/* set of bytes (maybe contain NULLs) */
	int		valuelen;	/* length of value */
	int		flags;		/* argument flags (eg: ATTR_NOCREATE) */
	scxfs_dahash_t	hashval;	/* hash value of name */
	scxfs_ino_t	inumber;	/* input/output inode number */
	struct scxfs_inode *dp;		/* directory inode to manipulate */
	struct scxfs_trans *trans;	/* current trans (changes over time) */
	scxfs_extlen_t	total;		/* total blocks needed, for 1st bmap */
	int		whichfork;	/* data or attribute fork */
	scxfs_dablk_t	blkno;		/* blkno of attr leaf of interest */
	int		index;		/* index of attr of interest in blk */
	scxfs_dablk_t	rmtblkno;	/* remote attr value starting blkno */
	int		rmtblkcnt;	/* remote attr value block count */
	int		rmtvaluelen;	/* remote attr value length in bytes */
	scxfs_dablk_t	blkno2;		/* blkno of 2nd attr leaf of interest */
	int		index2;		/* index of 2nd attr in blk */
	scxfs_dablk_t	rmtblkno2;	/* remote attr value starting blkno */
	int		rmtblkcnt2;	/* remote attr value block count */
	int		rmtvaluelen2;	/* remote attr value length in bytes */
	int		op_flags;	/* operation flags */
	enum scxfs_dacmp	cmpresult;	/* name compare result for lookups */
} scxfs_da_args_t;

/*
 * Operation flags:
 */
#define SCXFS_DA_OP_JUSTCHECK	0x0001	/* check for ok with no space */
#define SCXFS_DA_OP_RENAME	0x0002	/* this is an atomic rename op */
#define SCXFS_DA_OP_ADDNAME	0x0004	/* this is an add operation */
#define SCXFS_DA_OP_OKNOENT	0x0008	/* lookup/add op, ENOENT ok, else die */
#define SCXFS_DA_OP_CILOOKUP	0x0010	/* lookup to return CI name if found */
#define SCXFS_DA_OP_ALLOCVAL	0x0020	/* lookup to alloc buffer if found  */

#define SCXFS_DA_OP_FLAGS \
	{ SCXFS_DA_OP_JUSTCHECK,	"JUSTCHECK" }, \
	{ SCXFS_DA_OP_RENAME,	"RENAME" }, \
	{ SCXFS_DA_OP_ADDNAME,	"ADDNAME" }, \
	{ SCXFS_DA_OP_OKNOENT,	"OKNOENT" }, \
	{ SCXFS_DA_OP_CILOOKUP,	"CILOOKUP" }, \
	{ SCXFS_DA_OP_ALLOCVAL,	"ALLOCVAL" }

/*
 * Storage for holding state during Btree searches and split/join ops.
 *
 * Only need space for 5 intermediate nodes.  With a minimum of 62-way
 * fanout to the Btree, we can support over 900 million directory blocks,
 * which is slightly more than enough.
 */
typedef struct scxfs_da_state_blk {
	struct scxfs_buf	*bp;		/* buffer containing block */
	scxfs_dablk_t	blkno;		/* filesystem blkno of buffer */
	scxfs_daddr_t	disk_blkno;	/* on-disk blkno (in BBs) of buffer */
	int		index;		/* relevant index into block */
	scxfs_dahash_t	hashval;	/* last hash value in block */
	int		magic;		/* blk's magic number, ie: blk type */
} scxfs_da_state_blk_t;

typedef struct scxfs_da_state_path {
	int			active;		/* number of active levels */
	scxfs_da_state_blk_t	blk[SCXFS_DA_NODE_MAXDEPTH];
} scxfs_da_state_path_t;

typedef struct scxfs_da_state {
	scxfs_da_args_t		*args;		/* filename arguments */
	struct scxfs_mount	*mp;		/* filesystem mount point */
	scxfs_da_state_path_t	path;		/* search/split paths */
	scxfs_da_state_path_t	altpath;	/* alternate path for join */
	unsigned char		inleaf;		/* insert into 1->lf, 0->splf */
	unsigned char		extravalid;	/* T/F: extrablk is in use */
	unsigned char		extraafter;	/* T/F: extrablk is after new */
	scxfs_da_state_blk_t	extrablk;	/* for double-splits on leaves */
						/* for dirv2 extrablk is data */
} scxfs_da_state_t;

/*
 * Utility macros to aid in logging changed structure fields.
 */
#define SCXFS_DA_LOGOFF(BASE, ADDR)	((char *)(ADDR) - (char *)(BASE))
#define SCXFS_DA_LOGRANGE(BASE, ADDR, SIZE)	\
		(uint)(SCXFS_DA_LOGOFF(BASE, ADDR)), \
		(uint)(SCXFS_DA_LOGOFF(BASE, ADDR)+(SIZE)-1)

/*
 * Name ops for directory and/or attr name operations
 */
struct scxfs_nameops {
	scxfs_dahash_t	(*hashname)(struct scxfs_name *);
	enum scxfs_dacmp	(*compname)(struct scxfs_da_args *,
					const unsigned char *, int);
};


/*========================================================================
 * Function prototypes.
 *========================================================================*/

/*
 * Routines used for growing the Btree.
 */
int	scxfs_da3_node_create(struct scxfs_da_args *args, scxfs_dablk_t blkno,
			    int level, struct scxfs_buf **bpp, int whichfork);
int	scxfs_da3_split(scxfs_da_state_t *state);

/*
 * Routines used for shrinking the Btree.
 */
int	scxfs_da3_join(scxfs_da_state_t *state);
void	scxfs_da3_fixhashpath(struct scxfs_da_state *state,
			    struct scxfs_da_state_path *path_to_to_fix);

/*
 * Routines used for finding things in the Btree.
 */
int	scxfs_da3_node_lookup_int(scxfs_da_state_t *state, int *result);
int	scxfs_da3_path_shift(scxfs_da_state_t *state, scxfs_da_state_path_t *path,
					 int forward, int release, int *result);
/*
 * Utility routines.
 */
int	scxfs_da3_blk_link(scxfs_da_state_t *state, scxfs_da_state_blk_t *old_blk,
				       scxfs_da_state_blk_t *new_blk);
int	scxfs_da3_node_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
			 scxfs_dablk_t bno, scxfs_daddr_t mappedbno,
			 struct scxfs_buf **bpp, int which_fork);

/*
 * Utility routines.
 */
int	scxfs_da_grow_inode(scxfs_da_args_t *args, scxfs_dablk_t *new_blkno);
int	scxfs_da_grow_inode_int(struct scxfs_da_args *args, scxfs_fileoff_t *bno,
			      int count);
int	scxfs_da_get_buf(struct scxfs_trans *trans, struct scxfs_inode *dp,
			      scxfs_dablk_t bno, scxfs_daddr_t mappedbno,
			      struct scxfs_buf **bp, int whichfork);
int	scxfs_da_read_buf(struct scxfs_trans *trans, struct scxfs_inode *dp,
			       scxfs_dablk_t bno, scxfs_daddr_t mappedbno,
			       struct scxfs_buf **bpp, int whichfork,
			       const struct scxfs_buf_ops *ops);
int	scxfs_da_reada_buf(struct scxfs_inode *dp, scxfs_dablk_t bno,
				scxfs_daddr_t mapped_bno, int whichfork,
				const struct scxfs_buf_ops *ops);
int	scxfs_da_shrink_inode(scxfs_da_args_t *args, scxfs_dablk_t dead_blkno,
					  struct scxfs_buf *dead_buf);

uint scxfs_da_hashname(const uint8_t *name_string, int name_length);
enum scxfs_dacmp scxfs_da_compname(struct scxfs_da_args *args,
				const unsigned char *name, int len);


scxfs_da_state_t *scxfs_da_state_alloc(void);
void scxfs_da_state_free(scxfs_da_state_t *state);

extern struct kmem_zone *scxfs_da_state_zone;
extern const struct scxfs_nameops scxfs_default_nameops;

#endif	/* __SCXFS_DA_BTREE_H__ */
