// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_MOUNT_H__
#define	__SCXFS_MOUNT_H__

struct xlog;
struct scxfs_inode;
struct scxfs_mru_cache;
struct scxfs_nameops;
struct scxfs_ail;
struct scxfs_quotainfo;
struct scxfs_dir_ops;
struct scxfs_da_geometry;

/* dynamic preallocation free space thresholds, 5% down to 1% */
enum {
	SCXFS_LOWSP_1_PCNT = 0,
	SCXFS_LOWSP_2_PCNT,
	SCXFS_LOWSP_3_PCNT,
	SCXFS_LOWSP_4_PCNT,
	SCXFS_LOWSP_5_PCNT,
	SCXFS_LOWSP_MAX,
};

/*
 * Error Configuration
 *
 * Error classes define the subsystem the configuration belongs to.
 * Error numbers define the errors that are configurable.
 */
enum {
	SCXFS_ERR_METADATA,
	SCXFS_ERR_CLASS_MAX,
};
enum {
	SCXFS_ERR_DEFAULT,
	SCXFS_ERR_EIO,
	SCXFS_ERR_ENOSPC,
	SCXFS_ERR_ENODEV,
	SCXFS_ERR_ERRNO_MAX,
};

#define SCXFS_ERR_RETRY_FOREVER	-1

/*
 * Although retry_timeout is in jiffies which is normally an unsigned long,
 * we limit the retry timeout to 86400 seconds, or one day.  So even a
 * signed 32-bit long is sufficient for a HZ value up to 24855.  Making it
 * signed lets us store the special "-1" value, meaning retry forever.
 */
struct scxfs_error_cfg {
	struct scxfs_kobj	kobj;
	int		max_retries;
	long		retry_timeout;	/* in jiffies, -1 = infinite */
};

typedef struct scxfs_mount {
	struct super_block	*m_super;
	scxfs_tid_t		m_tid;		/* next unused tid for fs */

	/*
	 * Bitsets of per-fs metadata that have been checked and/or are sick.
	 * Callers must hold m_sb_lock to access these two fields.
	 */
	uint8_t			m_fs_checked;
	uint8_t			m_fs_sick;
	/*
	 * Bitsets of rt metadata that have been checked and/or are sick.
	 * Callers must hold m_sb_lock to access this field.
	 */
	uint8_t			m_rt_checked;
	uint8_t			m_rt_sick;

	struct scxfs_ail		*m_ail;		/* fs active log item list */

	struct scxfs_sb		m_sb;		/* copy of fs superblock */
	spinlock_t		m_sb_lock;	/* sb counter lock */
	struct percpu_counter	m_icount;	/* allocated inodes counter */
	struct percpu_counter	m_ifree;	/* free inodes counter */
	struct percpu_counter	m_fdblocks;	/* free block counter */
	/*
	 * Count of data device blocks reserved for delayed allocations,
	 * including indlen blocks.  Does not include allocated CoW staging
	 * extents or anything related to the rt device.
	 */
	struct percpu_counter	m_delalloc_blks;

	struct scxfs_buf		*m_sb_bp;	/* buffer for superblock */
	char			*m_fsname;	/* filesystem name */
	int			m_fsname_len;	/* strlen of fs name */
	char			*m_rtname;	/* realtime device name */
	char			*m_logname;	/* external log device name */
	int			m_bsize;	/* fs logical block size */
	scxfs_agnumber_t		m_agfrotor;	/* last ag where space found */
	scxfs_agnumber_t		m_agirotor;	/* last ag dir inode alloced */
	spinlock_t		m_agirotor_lock;/* .. and lock protecting it */
	scxfs_agnumber_t		m_maxagi;	/* highest inode alloc group */
	uint			m_readio_log;	/* min read size log bytes */
	uint			m_readio_blocks; /* min read size blocks */
	uint			m_writeio_log;	/* min write size log bytes */
	uint			m_writeio_blocks; /* min write size blocks */
	struct scxfs_da_geometry	*m_dir_geo;	/* directory block geometry */
	struct scxfs_da_geometry	*m_attr_geo;	/* attribute block geometry */
	struct xlog		*m_log;		/* log specific stuff */
	struct scxfs_ino_geometry	m_ino_geo;	/* inode geometry */
	int			m_logbufs;	/* number of log buffers */
	int			m_logbsize;	/* size of each log buffer */
	uint			m_rsumlevels;	/* rt summary levels */
	uint			m_rsumsize;	/* size of rt summary, bytes */
	/*
	 * Optional cache of rt summary level per bitmap block with the
	 * invariant that m_rsum_cache[bbno] <= the minimum i for which
	 * rsum[i][bbno] != 0. Reads and writes are serialized by the rsumip
	 * inode lock.
	 */
	uint8_t			*m_rsum_cache;
	struct scxfs_inode	*m_rbmip;	/* pointer to bitmap inode */
	struct scxfs_inode	*m_rsumip;	/* pointer to summary inode */
	struct scxfs_inode	*m_rootip;	/* pointer to root directory */
	struct scxfs_quotainfo	*m_quotainfo;	/* disk quota information */
	scxfs_buftarg_t		*m_ddev_targp;	/* saves taking the address */
	scxfs_buftarg_t		*m_logdev_targp;/* ptr to log device */
	scxfs_buftarg_t		*m_rtdev_targp;	/* ptr to rt device */
	uint8_t			m_blkbit_log;	/* blocklog + NBBY */
	uint8_t			m_blkbb_log;	/* blocklog - BBSHIFT */
	uint8_t			m_agno_log;	/* log #ag's */
	uint			m_blockmask;	/* sb_blocksize-1 */
	uint			m_blockwsize;	/* sb_blocksize in words */
	uint			m_blockwmask;	/* blockwsize-1 */
	uint			m_alloc_mxr[2];	/* max alloc btree records */
	uint			m_alloc_mnr[2];	/* min alloc btree records */
	uint			m_bmap_dmxr[2];	/* max bmap btree records */
	uint			m_bmap_dmnr[2];	/* min bmap btree records */
	uint			m_rmap_mxr[2];	/* max rmap btree records */
	uint			m_rmap_mnr[2];	/* min rmap btree records */
	uint			m_refc_mxr[2];	/* max refc btree records */
	uint			m_refc_mnr[2];	/* min refc btree records */
	uint			m_ag_maxlevels;	/* SCXFS_AG_MAXLEVELS */
	uint			m_bm_maxlevels[2]; /* SCXFS_BM_MAXLEVELS */
	uint			m_rmap_maxlevels; /* max rmap btree levels */
	uint			m_refc_maxlevels; /* max refcount btree level */
	scxfs_extlen_t		m_ag_prealloc_blocks; /* reserved ag blocks */
	uint			m_alloc_set_aside; /* space we can't use */
	uint			m_ag_max_usable; /* max space per AG */
	struct radix_tree_root	m_perag_tree;	/* per-ag accounting info */
	spinlock_t		m_perag_lock;	/* lock for m_perag_tree */
	struct mutex		m_growlock;	/* growfs mutex */
	int			m_fixedfsid[2];	/* unchanged for life of FS */
	uint64_t		m_flags;	/* global mount flags */
	bool			m_finobt_nores; /* no per-AG finobt resv. */
	uint			m_qflags;	/* quota status flags */
	struct scxfs_trans_resv	m_resv;		/* precomputed res values */
	uint64_t		m_resblks;	/* total reserved blocks */
	uint64_t		m_resblks_avail;/* available reserved blocks */
	uint64_t		m_resblks_save;	/* reserved blks @ remount,ro */
	int			m_dalign;	/* stripe unit */
	int			m_swidth;	/* stripe width */
	uint8_t			m_sectbb_log;	/* sectlog - BBSHIFT */
	const struct scxfs_nameops *m_dirnameops;	/* vector of dir name ops */
	const struct scxfs_dir_ops *m_dir_inode_ops; /* vector of dir inode ops */
	const struct scxfs_dir_ops *m_nondir_inode_ops; /* !dir inode ops */
	uint			m_chsize;	/* size of next field */
	atomic_t		m_active_trans;	/* number trans frozen */
	struct scxfs_mru_cache	*m_filestream;  /* per-mount filestream data */
	struct delayed_work	m_reclaim_work;	/* background inode reclaim */
	struct delayed_work	m_eofblocks_work; /* background eof blocks
						     trimming */
	struct delayed_work	m_cowblocks_work; /* background cow blocks
						     trimming */
	bool			m_update_sb;	/* sb needs update in mount */
	int64_t			m_low_space[SCXFS_LOWSP_MAX];
						/* low free space thresholds */
	struct scxfs_kobj		m_kobj;
	struct scxfs_kobj		m_error_kobj;
	struct scxfs_kobj		m_error_meta_kobj;
	struct scxfs_error_cfg	m_error_cfg[SCXFS_ERR_CLASS_MAX][SCXFS_ERR_ERRNO_MAX];
	struct xstats		m_stats;	/* per-fs stats */

	struct workqueue_struct *m_buf_workqueue;
	struct workqueue_struct	*m_unwritten_workqueue;
	struct workqueue_struct	*m_cil_workqueue;
	struct workqueue_struct	*m_reclaim_workqueue;
	struct workqueue_struct *m_eofblocks_workqueue;
	struct workqueue_struct	*m_sync_workqueue;

	/*
	 * Generation of the filesysyem layout.  This is incremented by each
	 * growfs, and used by the pNFS server to ensure the client updates
	 * its view of the block device once it gets a layout that might
	 * reference the newly added blocks.  Does not need to be persistent
	 * as long as we only allow file system size increments, but if we
	 * ever support shrinks it would have to be persisted in addition
	 * to various other kinds of pain inflicted on the pNFS server.
	 */
	uint32_t		m_generation;

	bool			m_always_cow;
	bool			m_fail_unmount;
#ifdef DEBUG
	/*
	 * Frequency with which errors are injected.  Replaces scxfs_etest; the
	 * value stored in here is the inverse of the frequency with which the
	 * error triggers.  1 = always, 2 = half the time, etc.
	 */
	unsigned int		*m_errortag;
	struct scxfs_kobj		m_errortag_kobj;
#endif
} scxfs_mount_t;

#define M_IGEO(mp)		(&(mp)->m_ino_geo)

/*
 * Flags for m_flags.
 */
#define SCXFS_MOUNT_WSYNC		(1ULL << 0)	/* for nfs - all metadata ops
						   must be synchronous except
						   for space allocations */
#define SCXFS_MOUNT_UNMOUNTING	(1ULL << 1)	/* filesystem is unmounting */
#define SCXFS_MOUNT_WAS_CLEAN	(1ULL << 3)
#define SCXFS_MOUNT_FS_SHUTDOWN	(1ULL << 4)	/* atomic stop of all filesystem
						   operations, typically for
						   disk errors in metadata */
#define SCXFS_MOUNT_DISCARD	(1ULL << 5)	/* discard unused blocks */
#define SCXFS_MOUNT_NOALIGN	(1ULL << 7)	/* turn off stripe alignment
						   allocations */
#define SCXFS_MOUNT_ATTR2		(1ULL << 8)	/* allow use of attr2 format */
#define SCXFS_MOUNT_GRPID		(1ULL << 9)	/* group-ID assigned from directory */
#define SCXFS_MOUNT_NORECOVERY	(1ULL << 10)	/* no recovery - dirty fs */
#define SCXFS_MOUNT_DFLT_IOSIZE	(1ULL << 12)	/* set default i/o size */
#define SCXFS_MOUNT_SMALL_INUMS	(1ULL << 14)	/* user wants 32bit inodes */
#define SCXFS_MOUNT_32BITINODES	(1ULL << 15)	/* inode32 allocator active */
#define SCXFS_MOUNT_NOUUID	(1ULL << 16)	/* ignore uuid during mount */
#define SCXFS_MOUNT_IKEEP		(1ULL << 18)	/* keep empty inode clusters*/
#define SCXFS_MOUNT_SWALLOC	(1ULL << 19)	/* turn on stripe width
						 * allocation */
#define SCXFS_MOUNT_RDONLY	(1ULL << 20)	/* read-only fs */
#define SCXFS_MOUNT_DIRSYNC	(1ULL << 21)	/* synchronous directory ops */
#define SCXFS_MOUNT_COMPAT_IOSIZE	(1ULL << 22)	/* don't report large preferred
						 * I/O size in stat() */
#define SCXFS_MOUNT_FILESTREAMS	(1ULL << 24)	/* enable the filestreams
						   allocator */
#define SCXFS_MOUNT_NOATTR2	(1ULL << 25)	/* disable use of attr2 format */

#define SCXFS_MOUNT_DAX		(1ULL << 62)	/* TEST ONLY! */


/*
 * Default minimum read and write sizes.
 */
#define SCXFS_READIO_LOG_LARGE	16
#define SCXFS_WRITEIO_LOG_LARGE	16

/*
 * Max and min values for mount-option defined I/O
 * preallocation sizes.
 */
#define SCXFS_MAX_IO_LOG		30	/* 1G */
#define SCXFS_MIN_IO_LOG		PAGE_SHIFT

/*
 * Synchronous read and write sizes.  This should be
 * better for NFSv2 wsync filesystems.
 */
#define	SCXFS_WSYNC_READIO_LOG	15	/* 32k */
#define	SCXFS_WSYNC_WRITEIO_LOG	14	/* 16k */

/*
 * Allow large block sizes to be reported to userspace programs if the
 * "largeio" mount option is used.
 *
 * If compatibility mode is specified, simply return the basic unit of caching
 * so that we don't get inefficient read/modify/write I/O from user apps.
 * Otherwise....
 *
 * If the underlying volume is a stripe, then return the stripe width in bytes
 * as the recommended I/O size. It is not a stripe and we've set a default
 * buffered I/O size, return that, otherwise return the compat default.
 */
static inline unsigned long
scxfs_preferred_iosize(scxfs_mount_t *mp)
{
	if (mp->m_flags & SCXFS_MOUNT_COMPAT_IOSIZE)
		return PAGE_SIZE;
	return (mp->m_swidth ?
		(mp->m_swidth << mp->m_sb.sb_blocklog) :
		((mp->m_flags & SCXFS_MOUNT_DFLT_IOSIZE) ?
			(1 << (int)max(mp->m_readio_log, mp->m_writeio_log)) :
			PAGE_SIZE));
}

#define SCXFS_LAST_UNMOUNT_WAS_CLEAN(mp)	\
				((mp)->m_flags & SCXFS_MOUNT_WAS_CLEAN)
#define SCXFS_FORCED_SHUTDOWN(mp)	((mp)->m_flags & SCXFS_MOUNT_FS_SHUTDOWN)
void scxfs_do_force_shutdown(struct scxfs_mount *mp, int flags, char *fname,
		int lnnum);
#define scxfs_force_shutdown(m,f)	\
	scxfs_do_force_shutdown(m, f, __FILE__, __LINE__)

#define SHUTDOWN_META_IO_ERROR	0x0001	/* write attempt to metadata failed */
#define SHUTDOWN_LOG_IO_ERROR	0x0002	/* write attempt to the log failed */
#define SHUTDOWN_FORCE_UMOUNT	0x0004	/* shutdown from a forced unmount */
#define SHUTDOWN_CORRUPT_INCORE	0x0008	/* corrupt in-memory data structures */
#define SHUTDOWN_REMOTE_REQ	0x0010	/* shutdown came from remote cell */
#define SHUTDOWN_DEVICE_REQ	0x0020	/* failed all paths to the device */

/*
 * Flags for scxfs_mountfs
 */
#define SCXFS_MFSI_QUIET		0x40	/* Be silent if mount errors found */

static inline scxfs_agnumber_t
scxfs_daddr_to_agno(struct scxfs_mount *mp, scxfs_daddr_t d)
{
	scxfs_rfsblock_t ld = SCXFS_BB_TO_FSBT(mp, d);
	do_div(ld, mp->m_sb.sb_agblocks);
	return (scxfs_agnumber_t) ld;
}

static inline scxfs_agblock_t
scxfs_daddr_to_agbno(struct scxfs_mount *mp, scxfs_daddr_t d)
{
	scxfs_rfsblock_t ld = SCXFS_BB_TO_FSBT(mp, d);
	return (scxfs_agblock_t) do_div(ld, mp->m_sb.sb_agblocks);
}

/* per-AG block reservation data structures*/
struct scxfs_ag_resv {
	/* number of blocks originally reserved here */
	scxfs_extlen_t			ar_orig_reserved;
	/* number of blocks reserved here */
	scxfs_extlen_t			ar_reserved;
	/* number of blocks originally asked for */
	scxfs_extlen_t			ar_asked;
};

/*
 * Per-ag incore structure, copies of information in agf and agi, to improve the
 * performance of allocation group selection.
 */
typedef struct scxfs_perag {
	struct scxfs_mount *pag_mount;	/* owner filesystem */
	scxfs_agnumber_t	pag_agno;	/* AG this structure belongs to */
	atomic_t	pag_ref;	/* perag reference count */
	char		pagf_init;	/* this agf's entry is initialized */
	char		pagi_init;	/* this agi's entry is initialized */
	char		pagf_metadata;	/* the agf is preferred to be metadata */
	char		pagi_inodeok;	/* The agi is ok for inodes */
	uint8_t		pagf_levels[SCXFS_BTNUM_AGF];
					/* # of levels in bno & cnt btree */
	bool		pagf_agflreset; /* agfl requires reset before use */
	uint32_t	pagf_flcount;	/* count of blocks in freelist */
	scxfs_extlen_t	pagf_freeblks;	/* total free blocks */
	scxfs_extlen_t	pagf_longest;	/* longest free space */
	uint32_t	pagf_btreeblks;	/* # of blocks held in AGF btrees */
	scxfs_agino_t	pagi_freecount;	/* number of free inodes */
	scxfs_agino_t	pagi_count;	/* number of allocated inodes */

	/*
	 * Inode allocation search lookup optimisation.
	 * If the pagino matches, the search for new inodes
	 * doesn't need to search the near ones again straight away
	 */
	scxfs_agino_t	pagl_pagino;
	scxfs_agino_t	pagl_leftrec;
	scxfs_agino_t	pagl_rightrec;

	/*
	 * Bitsets of per-ag metadata that have been checked and/or are sick.
	 * Callers should hold pag_state_lock before accessing this field.
	 */
	uint16_t	pag_checked;
	uint16_t	pag_sick;
	spinlock_t	pag_state_lock;

	spinlock_t	pagb_lock;	/* lock for pagb_tree */
	struct rb_root	pagb_tree;	/* ordered tree of busy extents */
	unsigned int	pagb_gen;	/* generation count for pagb_tree */
	wait_queue_head_t pagb_wait;	/* woken when pagb_gen changes */

	atomic_t        pagf_fstrms;    /* # of filestreams active in this AG */

	spinlock_t	pag_ici_lock;	/* incore inode cache lock */
	struct radix_tree_root pag_ici_root;	/* incore inode cache root */
	int		pag_ici_reclaimable;	/* reclaimable inodes */
	struct mutex	pag_ici_reclaim_lock;	/* serialisation point */
	unsigned long	pag_ici_reclaim_cursor;	/* reclaim restart point */

	/* buffer cache index */
	spinlock_t	pag_buf_lock;	/* lock for pag_buf_hash */
	struct rhashtable pag_buf_hash;

	/* for rcu-safe freeing */
	struct rcu_head	rcu_head;
	int		pagb_count;	/* pagb slots in use */

	/* Blocks reserved for all kinds of metadata. */
	struct scxfs_ag_resv	pag_meta_resv;
	/* Blocks reserved for the reverse mapping btree. */
	struct scxfs_ag_resv	pag_rmapbt_resv;

	/* reference count */
	uint8_t			pagf_refcount_level;

	/*
	 * Unlinked inode information.  This incore information reflects
	 * data stored in the AGI, so callers must hold the AGI buffer lock
	 * or have some other means to control concurrency.
	 */
	struct rhashtable	pagi_unlinked_hash;
} scxfs_perag_t;

static inline struct scxfs_ag_resv *
scxfs_perag_resv(
	struct scxfs_perag	*pag,
	enum scxfs_ag_resv_type	type)
{
	switch (type) {
	case SCXFS_AG_RESV_METADATA:
		return &pag->pag_meta_resv;
	case SCXFS_AG_RESV_RMAPBT:
		return &pag->pag_rmapbt_resv;
	default:
		return NULL;
	}
}

int scxfs_buf_hash_init(scxfs_perag_t *pag);
void scxfs_buf_hash_destroy(scxfs_perag_t *pag);

extern void	scxfs_uuid_table_free(void);
extern int	scxfs_log_sbcount(scxfs_mount_t *);
extern uint64_t scxfs_default_resblks(scxfs_mount_t *mp);
extern int	scxfs_mountfs(scxfs_mount_t *mp);
extern int	scxfs_initialize_perag(scxfs_mount_t *mp, scxfs_agnumber_t agcount,
				     scxfs_agnumber_t *maxagi);
extern void	scxfs_unmountfs(scxfs_mount_t *);

extern int	scxfs_mod_icount(struct scxfs_mount *mp, int64_t delta);
extern int	scxfs_mod_ifree(struct scxfs_mount *mp, int64_t delta);
extern int	scxfs_mod_fdblocks(struct scxfs_mount *mp, int64_t delta,
				 bool reserved);
extern int	scxfs_mod_frextents(struct scxfs_mount *mp, int64_t delta);

extern struct scxfs_buf *scxfs_getsb(scxfs_mount_t *);
extern int	scxfs_readsb(scxfs_mount_t *, int);
extern void	scxfs_freesb(scxfs_mount_t *);
extern bool	scxfs_fs_writable(struct scxfs_mount *mp, int level);
extern int	scxfs_sb_validate_fsb_count(struct scxfs_sb *, uint64_t);

extern int	scxfs_dev_is_read_only(struct scxfs_mount *, char *);

extern void	scxfs_set_low_space_thresholds(struct scxfs_mount *);

int	scxfs_zero_extent(struct scxfs_inode *ip, scxfs_fsblock_t start_fsb,
			scxfs_off_t count_fsb);

struct scxfs_error_cfg * scxfs_error_get_cfg(struct scxfs_mount *mp,
		int error_class, int error);
void scxfs_force_summary_recalc(struct scxfs_mount *mp);
void scxfs_mod_delalloc(struct scxfs_mount *mp, int64_t delta);

#endif	/* __SCXFS_MOUNT_H__ */
