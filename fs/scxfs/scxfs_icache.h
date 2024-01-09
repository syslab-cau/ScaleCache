// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef SCXFS_SYNC_H
#define SCXFS_SYNC_H 1

struct scxfs_mount;
struct scxfs_perag;

struct scxfs_eofblocks {
	__u32		eof_flags;
	kuid_t		eof_uid;
	kgid_t		eof_gid;
	prid_t		eof_prid;
	__u64		eof_min_file_size;
};

#define SYNC_WAIT		0x0001	/* wait for i/o to complete */
#define SYNC_TRYLOCK		0x0002  /* only try to lock inodes */

/*
 * tags for inode radix tree
 */
#define SCXFS_ICI_NO_TAG		(-1)	/* special flag for an untagged lookup
					   in scxfs_inode_ag_iterator */
#define SCXFS_ICI_RECLAIM_TAG	0	/* inode is to be reclaimed */
#define SCXFS_ICI_EOFBLOCKS_TAG	1	/* inode has blocks beyond EOF */
#define SCXFS_ICI_COWBLOCKS_TAG	2	/* inode can have cow blocks to gc */

/*
 * Flags for scxfs_iget()
 */
#define SCXFS_IGET_CREATE		0x1
#define SCXFS_IGET_UNTRUSTED	0x2
#define SCXFS_IGET_DONTCACHE	0x4
#define SCXFS_IGET_INCORE		0x8	/* don't read from disk or reinit */

/*
 * flags for AG inode iterator
 */
#define SCXFS_AGITER_INEW_WAIT	0x1	/* wait on new inodes */

int scxfs_iget(struct scxfs_mount *mp, struct scxfs_trans *tp, scxfs_ino_t ino,
	     uint flags, uint lock_flags, scxfs_inode_t **ipp);

/* recovery needs direct inode allocation capability */
struct scxfs_inode * scxfs_inode_alloc(struct scxfs_mount *mp, scxfs_ino_t ino);
void scxfs_inode_free(struct scxfs_inode *ip);

void scxfs_reclaim_worker(struct work_struct *work);

int scxfs_reclaim_inodes(struct scxfs_mount *mp, int mode);
int scxfs_reclaim_inodes_count(struct scxfs_mount *mp);
long scxfs_reclaim_inodes_nr(struct scxfs_mount *mp, int nr_to_scan);

void scxfs_inode_set_reclaim_tag(struct scxfs_inode *ip);

void scxfs_inode_set_eofblocks_tag(struct scxfs_inode *ip);
void scxfs_inode_clear_eofblocks_tag(struct scxfs_inode *ip);
int scxfs_icache_free_eofblocks(struct scxfs_mount *, struct scxfs_eofblocks *);
int scxfs_inode_free_quota_eofblocks(struct scxfs_inode *ip);
void scxfs_eofblocks_worker(struct work_struct *);
void scxfs_queue_eofblocks(struct scxfs_mount *);

void scxfs_inode_set_cowblocks_tag(struct scxfs_inode *ip);
void scxfs_inode_clear_cowblocks_tag(struct scxfs_inode *ip);
int scxfs_icache_free_cowblocks(struct scxfs_mount *, struct scxfs_eofblocks *);
int scxfs_inode_free_quota_cowblocks(struct scxfs_inode *ip);
void scxfs_cowblocks_worker(struct work_struct *);
void scxfs_queue_cowblocks(struct scxfs_mount *);

int scxfs_inode_ag_iterator(struct scxfs_mount *mp,
	int (*execute)(struct scxfs_inode *ip, int flags, void *args),
	int flags, void *args);
int scxfs_inode_ag_iterator_flags(struct scxfs_mount *mp,
	int (*execute)(struct scxfs_inode *ip, int flags, void *args),
	int flags, void *args, int iter_flags);
int scxfs_inode_ag_iterator_tag(struct scxfs_mount *mp,
	int (*execute)(struct scxfs_inode *ip, int flags, void *args),
	int flags, void *args, int tag);

static inline int
scxfs_fs_eofblocks_from_user(
	struct scxfs_fs_eofblocks		*src,
	struct scxfs_eofblocks		*dst)
{
	if (src->eof_version != SCXFS_EOFBLOCKS_VERSION)
		return -EINVAL;

	if (src->eof_flags & ~SCXFS_EOF_FLAGS_VALID)
		return -EINVAL;

	if (memchr_inv(&src->pad32, 0, sizeof(src->pad32)) ||
	    memchr_inv(src->pad64, 0, sizeof(src->pad64)))
		return -EINVAL;

	dst->eof_flags = src->eof_flags;
	dst->eof_prid = src->eof_prid;
	dst->eof_min_file_size = src->eof_min_file_size;

	dst->eof_uid = INVALID_UID;
	if (src->eof_flags & SCXFS_EOF_FLAGS_UID) {
		dst->eof_uid = make_kuid(current_user_ns(), src->eof_uid);
		if (!uid_valid(dst->eof_uid))
			return -EINVAL;
	}

	dst->eof_gid = INVALID_GID;
	if (src->eof_flags & SCXFS_EOF_FLAGS_GID) {
		dst->eof_gid = make_kgid(current_user_ns(), src->eof_gid);
		if (!gid_valid(dst->eof_gid))
			return -EINVAL;
	}
	return 0;
}

int scxfs_icache_inode_is_allocated(struct scxfs_mount *mp, struct scxfs_trans *tp,
				  scxfs_ino_t ino, bool *inuse);

void scxfs_stop_block_reaping(struct scxfs_mount *mp);
void scxfs_start_block_reaping(struct scxfs_mount *mp);

#endif
