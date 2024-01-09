// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_dir2.h"
#include "scxfs_dir2_priv.h"
#include "scxfs_trace.h"

/*
 * Prototypes for internal functions.
 */
static void scxfs_dir2_sf_addname_easy(scxfs_da_args_t *args,
				     scxfs_dir2_sf_entry_t *sfep,
				     scxfs_dir2_data_aoff_t offset,
				     int new_isize);
static void scxfs_dir2_sf_addname_hard(scxfs_da_args_t *args, int objchange,
				     int new_isize);
static int scxfs_dir2_sf_addname_pick(scxfs_da_args_t *args, int objchange,
				    scxfs_dir2_sf_entry_t **sfepp,
				    scxfs_dir2_data_aoff_t *offsetp);
#ifdef DEBUG
static void scxfs_dir2_sf_check(scxfs_da_args_t *args);
#else
#define	scxfs_dir2_sf_check(args)
#endif /* DEBUG */

static void scxfs_dir2_sf_toino4(scxfs_da_args_t *args);
static void scxfs_dir2_sf_toino8(scxfs_da_args_t *args);

/*
 * Given a block directory (dp/block), calculate its size as a shortform (sf)
 * directory and a header for the sf directory, if it will fit it the
 * space currently present in the inode.  If it won't fit, the output
 * size is too big (but not accurate).
 */
int						/* size for sf form */
scxfs_dir2_block_sfsize(
	scxfs_inode_t		*dp,		/* incore inode pointer */
	scxfs_dir2_data_hdr_t	*hdr,		/* block directory data */
	scxfs_dir2_sf_hdr_t	*sfhp)		/* output: header for sf form */
{
	scxfs_dir2_dataptr_t	addr;		/* data entry address */
	scxfs_dir2_leaf_entry_t	*blp;		/* leaf area of the block */
	scxfs_dir2_block_tail_t	*btp;		/* tail area of the block */
	int			count;		/* shortform entry count */
	scxfs_dir2_data_entry_t	*dep;		/* data entry in the block */
	int			i;		/* block entry index */
	int			i8count;	/* count of big-inode entries */
	int			isdot;		/* entry is "." */
	int			isdotdot;	/* entry is ".." */
	scxfs_mount_t		*mp;		/* mount structure pointer */
	int			namelen;	/* total name bytes */
	scxfs_ino_t		parent = 0;	/* parent inode number */
	int			size=0;		/* total computed size */
	int			has_ftype;
	struct scxfs_da_geometry	*geo;

	mp = dp->i_mount;
	geo = mp->m_dir_geo;

	/*
	 * if there is a filetype field, add the extra byte to the namelen
	 * for each entry that we see.
	 */
	has_ftype = scxfs_sb_version_hasftype(&mp->m_sb) ? 1 : 0;

	count = i8count = namelen = 0;
	btp = scxfs_dir2_block_tail_p(geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);

	/*
	 * Iterate over the block's data entries by using the leaf pointers.
	 */
	for (i = 0; i < be32_to_cpu(btp->count); i++) {
		if ((addr = be32_to_cpu(blp[i].address)) == SCXFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Calculate the pointer to the entry at hand.
		 */
		dep = (scxfs_dir2_data_entry_t *)((char *)hdr +
				scxfs_dir2_dataptr_to_off(geo, addr));
		/*
		 * Detect . and .., so we can special-case them.
		 * . is not included in sf directories.
		 * .. is included by just the parent inode number.
		 */
		isdot = dep->namelen == 1 && dep->name[0] == '.';
		isdotdot =
			dep->namelen == 2 &&
			dep->name[0] == '.' && dep->name[1] == '.';

		if (!isdot)
			i8count += be64_to_cpu(dep->inumber) > SCXFS_DIR2_MAX_SHORT_INUM;

		/* take into account the file type field */
		if (!isdot && !isdotdot) {
			count++;
			namelen += dep->namelen + has_ftype;
		} else if (isdotdot)
			parent = be64_to_cpu(dep->inumber);
		/*
		 * Calculate the new size, see if we should give up yet.
		 */
		size = scxfs_dir2_sf_hdr_size(i8count) +	/* header */
		       count * 3 * sizeof(u8) +		/* namelen + offset */
		       namelen +			/* name */
		       (i8count ?			/* inumber */
				count * SCXFS_INO64_SIZE :
				count * SCXFS_INO32_SIZE);
		if (size > SCXFS_IFORK_DSIZE(dp))
			return size;		/* size value is a failure */
	}
	/*
	 * Create the output header, if it worked.
	 */
	sfhp->count = count;
	sfhp->i8count = i8count;
	dp->d_ops->sf_put_parent_ino(sfhp, parent);
	return size;
}

/*
 * Convert a block format directory to shortform.
 * Caller has already checked that it will fit, and built us a header.
 */
int						/* error */
scxfs_dir2_block_to_sf(
	scxfs_da_args_t		*args,		/* operation arguments */
	struct scxfs_buf		*bp,
	int			size,		/* shortform directory size */
	scxfs_dir2_sf_hdr_t	*sfhp)		/* shortform directory hdr */
{
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_data_entry_t	*dep;		/* data entry pointer */
	scxfs_inode_t		*dp;		/* incore directory inode */
	scxfs_dir2_data_unused_t	*dup;		/* unused data pointer */
	char			*endptr;	/* end of data entries */
	int			error;		/* error return value */
	int			logflags;	/* inode logging flags */
	scxfs_mount_t		*mp;		/* filesystem mount point */
	char			*ptr;		/* current data pointer */
	scxfs_dir2_sf_entry_t	*sfep;		/* shortform entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform directory header */
	scxfs_dir2_sf_hdr_t	*dst;		/* temporary data buffer */

	trace_scxfs_dir2_block_to_sf(args);

	dp = args->dp;
	mp = dp->i_mount;

	/*
	 * allocate a temporary destination buffer the size of the inode
	 * to format the data into. Once we have formatted the data, we
	 * can free the block and copy the formatted data into the inode literal
	 * area.
	 */
	dst = kmem_alloc(mp->m_sb.sb_inodesize, 0);
	hdr = bp->b_addr;

	/*
	 * Copy the header into the newly allocate local space.
	 */
	sfp = (scxfs_dir2_sf_hdr_t *)dst;
	memcpy(sfp, sfhp, scxfs_dir2_sf_hdr_size(sfhp->i8count));

	/*
	 * Set up to loop over the block's entries.
	 */
	ptr = (char *)dp->d_ops->data_entry_p(hdr);
	endptr = scxfs_dir3_data_endp(args->geo, hdr);
	sfep = scxfs_dir2_sf_firstentry(sfp);
	/*
	 * Loop over the active and unused entries.
	 * Stop when we reach the leaf/tail portion of the block.
	 */
	while (ptr < endptr) {
		/*
		 * If it's unused, just skip over it.
		 */
		dup = (scxfs_dir2_data_unused_t *)ptr;
		if (be16_to_cpu(dup->freetag) == SCXFS_DIR2_DATA_FREE_TAG) {
			ptr += be16_to_cpu(dup->length);
			continue;
		}
		dep = (scxfs_dir2_data_entry_t *)ptr;
		/*
		 * Skip .
		 */
		if (dep->namelen == 1 && dep->name[0] == '.')
			ASSERT(be64_to_cpu(dep->inumber) == dp->i_ino);
		/*
		 * Skip .., but make sure the inode number is right.
		 */
		else if (dep->namelen == 2 &&
			 dep->name[0] == '.' && dep->name[1] == '.')
			ASSERT(be64_to_cpu(dep->inumber) ==
			       dp->d_ops->sf_get_parent_ino(sfp));
		/*
		 * Normal entry, copy it into shortform.
		 */
		else {
			sfep->namelen = dep->namelen;
			scxfs_dir2_sf_put_offset(sfep,
				(scxfs_dir2_data_aoff_t)
				((char *)dep - (char *)hdr));
			memcpy(sfep->name, dep->name, dep->namelen);
			dp->d_ops->sf_put_ino(sfp, sfep,
					      be64_to_cpu(dep->inumber));
			dp->d_ops->sf_put_ftype(sfep,
					dp->d_ops->data_get_ftype(dep));

			sfep = dp->d_ops->sf_nextentry(sfp, sfep);
		}
		ptr += dp->d_ops->data_entsize(dep->namelen);
	}
	ASSERT((char *)sfep - (char *)sfp == size);

	/* now we are done with the block, we can shrink the inode */
	logflags = SCXFS_ILOG_CORE;
	error = scxfs_dir2_shrink_inode(args, args->geo->datablk, bp);
	if (error) {
		ASSERT(error != -ENOSPC);
		goto out;
	}

	/*
	 * The buffer is now unconditionally gone, whether
	 * scxfs_dir2_shrink_inode worked or not.
	 *
	 * Convert the inode to local format and copy the data in.
	 */
	ASSERT(dp->i_df.if_bytes == 0);
	scxfs_init_local_fork(dp, SCXFS_DATA_FORK, dst, size);
	dp->i_d.di_format = SCXFS_DINODE_FMT_LOCAL;
	dp->i_d.di_size = size;

	logflags |= SCXFS_ILOG_DDATA;
	scxfs_dir2_sf_check(args);
out:
	scxfs_trans_log_inode(args->trans, dp, logflags);
	kmem_free(dst);
	return error;
}

/*
 * Add a name to a shortform directory.
 * There are two algorithms, "easy" and "hard" which we decide on
 * before changing anything.
 * Convert to block form if necessary, if the new entry won't fit.
 */
int						/* error */
scxfs_dir2_sf_addname(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return value */
	int			incr_isize;	/* total change in size */
	int			new_isize;	/* di_size after adding name */
	int			objchange;	/* changing to 8-byte inodes */
	scxfs_dir2_data_aoff_t	offset = 0;	/* offset for new entry */
	int			pick;		/* which algorithm to use */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */
	scxfs_dir2_sf_entry_t	*sfep = NULL;	/* shortform entry */

	trace_scxfs_dir2_sf_addname(args);

	ASSERT(scxfs_dir2_sf_lookup(args) == -ENOENT);
	dp = args->dp;
	ASSERT(dp->i_df.if_flags & SCXFS_IFINLINE);
	/*
	 * Make sure the shortform value has some of its header.
	 */
	if (dp->i_d.di_size < offsetof(scxfs_dir2_sf_hdr_t, parent)) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(dp->i_mount));
		return -EIO;
	}
	ASSERT(dp->i_df.if_bytes == dp->i_d.di_size);
	ASSERT(dp->i_df.if_u1.if_data != NULL);
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(dp->i_d.di_size >= scxfs_dir2_sf_hdr_size(sfp->i8count));
	/*
	 * Compute entry (and change in) size.
	 */
	incr_isize = dp->d_ops->sf_entsize(sfp, args->namelen);
	objchange = 0;

	/*
	 * Do we have to change to 8 byte inodes?
	 */
	if (args->inumber > SCXFS_DIR2_MAX_SHORT_INUM && sfp->i8count == 0) {
		/*
		 * Yes, adjust the inode size.  old count + (parent + new)
		 */
		incr_isize += (sfp->count + 2) * SCXFS_INO64_DIFF;
		objchange = 1;
	}

	new_isize = (int)dp->i_d.di_size + incr_isize;
	/*
	 * Won't fit as shortform any more (due to size),
	 * or the pick routine says it won't (due to offset values).
	 */
	if (new_isize > SCXFS_IFORK_DSIZE(dp) ||
	    (pick =
	     scxfs_dir2_sf_addname_pick(args, objchange, &sfep, &offset)) == 0) {
		/*
		 * Just checking or no space reservation, it doesn't fit.
		 */
		if ((args->op_flags & SCXFS_DA_OP_JUSTCHECK) || args->total == 0)
			return -ENOSPC;
		/*
		 * Convert to block form then add the name.
		 */
		error = scxfs_dir2_sf_to_block(args);
		if (error)
			return error;
		return scxfs_dir2_block_addname(args);
	}
	/*
	 * Just checking, it fits.
	 */
	if (args->op_flags & SCXFS_DA_OP_JUSTCHECK)
		return 0;
	/*
	 * Do it the easy way - just add it at the end.
	 */
	if (pick == 1)
		scxfs_dir2_sf_addname_easy(args, sfep, offset, new_isize);
	/*
	 * Do it the hard way - look for a place to insert the new entry.
	 * Convert to 8 byte inode numbers first if necessary.
	 */
	else {
		ASSERT(pick == 2);
		if (objchange)
			scxfs_dir2_sf_toino8(args);
		scxfs_dir2_sf_addname_hard(args, objchange, new_isize);
	}
	scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_CORE | SCXFS_ILOG_DDATA);
	return 0;
}

/*
 * Add the new entry the "easy" way.
 * This is copying the old directory and adding the new entry at the end.
 * Since it's sorted by "offset" we need room after the last offset
 * that's already there, and then room to convert to a block directory.
 * This is already checked by the pick routine.
 */
static void
scxfs_dir2_sf_addname_easy(
	scxfs_da_args_t		*args,		/* operation arguments */
	scxfs_dir2_sf_entry_t	*sfep,		/* pointer to new entry */
	scxfs_dir2_data_aoff_t	offset,		/* offset to use for new ent */
	int			new_isize)	/* new directory size */
{
	int			byteoff;	/* byte offset in sf dir */
	scxfs_inode_t		*dp;		/* incore directory inode */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */

	dp = args->dp;

	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	byteoff = (int)((char *)sfep - (char *)sfp);
	/*
	 * Grow the in-inode space.
	 */
	scxfs_idata_realloc(dp, dp->d_ops->sf_entsize(sfp, args->namelen),
			  SCXFS_DATA_FORK);
	/*
	 * Need to set up again due to realloc of the inode data.
	 */
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	sfep = (scxfs_dir2_sf_entry_t *)((char *)sfp + byteoff);
	/*
	 * Fill in the new entry.
	 */
	sfep->namelen = args->namelen;
	scxfs_dir2_sf_put_offset(sfep, offset);
	memcpy(sfep->name, args->name, sfep->namelen);
	dp->d_ops->sf_put_ino(sfp, sfep, args->inumber);
	dp->d_ops->sf_put_ftype(sfep, args->filetype);

	/*
	 * Update the header and inode.
	 */
	sfp->count++;
	if (args->inumber > SCXFS_DIR2_MAX_SHORT_INUM)
		sfp->i8count++;
	dp->i_d.di_size = new_isize;
	scxfs_dir2_sf_check(args);
}

/*
 * Add the new entry the "hard" way.
 * The caller has already converted to 8 byte inode numbers if necessary,
 * in which case we need to leave the i8count at 1.
 * Find a hole that the new entry will fit into, and copy
 * the first part of the entries, the new entry, and the last part of
 * the entries.
 */
/* ARGSUSED */
static void
scxfs_dir2_sf_addname_hard(
	scxfs_da_args_t		*args,		/* operation arguments */
	int			objchange,	/* changing inode number size */
	int			new_isize)	/* new directory size */
{
	int			add_datasize;	/* data size need for new ent */
	char			*buf;		/* buffer for old */
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			eof;		/* reached end of old dir */
	int			nbytes;		/* temp for byte copies */
	scxfs_dir2_data_aoff_t	new_offset;	/* next offset value */
	scxfs_dir2_data_aoff_t	offset;		/* current offset value */
	int			old_isize;	/* previous di_size */
	scxfs_dir2_sf_entry_t	*oldsfep;	/* entry in original dir */
	scxfs_dir2_sf_hdr_t	*oldsfp;	/* original shortform dir */
	scxfs_dir2_sf_entry_t	*sfep;		/* entry in new dir */
	scxfs_dir2_sf_hdr_t	*sfp;		/* new shortform dir */

	/*
	 * Copy the old directory to the stack buffer.
	 */
	dp = args->dp;

	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	old_isize = (int)dp->i_d.di_size;
	buf = kmem_alloc(old_isize, 0);
	oldsfp = (scxfs_dir2_sf_hdr_t *)buf;
	memcpy(oldsfp, sfp, old_isize);
	/*
	 * Loop over the old directory finding the place we're going
	 * to insert the new entry.
	 * If it's going to end up at the end then oldsfep will point there.
	 */
	for (offset = dp->d_ops->data_first_offset,
	      oldsfep = scxfs_dir2_sf_firstentry(oldsfp),
	      add_datasize = dp->d_ops->data_entsize(args->namelen),
	      eof = (char *)oldsfep == &buf[old_isize];
	     !eof;
	     offset = new_offset + dp->d_ops->data_entsize(oldsfep->namelen),
	      oldsfep = dp->d_ops->sf_nextentry(oldsfp, oldsfep),
	      eof = (char *)oldsfep == &buf[old_isize]) {
		new_offset = scxfs_dir2_sf_get_offset(oldsfep);
		if (offset + add_datasize <= new_offset)
			break;
	}
	/*
	 * Get rid of the old directory, then allocate space for
	 * the new one.  We do this so scxfs_idata_realloc won't copy
	 * the data.
	 */
	scxfs_idata_realloc(dp, -old_isize, SCXFS_DATA_FORK);
	scxfs_idata_realloc(dp, new_isize, SCXFS_DATA_FORK);
	/*
	 * Reset the pointer since the buffer was reallocated.
	 */
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	/*
	 * Copy the first part of the directory, including the header.
	 */
	nbytes = (int)((char *)oldsfep - (char *)oldsfp);
	memcpy(sfp, oldsfp, nbytes);
	sfep = (scxfs_dir2_sf_entry_t *)((char *)sfp + nbytes);
	/*
	 * Fill in the new entry, and update the header counts.
	 */
	sfep->namelen = args->namelen;
	scxfs_dir2_sf_put_offset(sfep, offset);
	memcpy(sfep->name, args->name, sfep->namelen);
	dp->d_ops->sf_put_ino(sfp, sfep, args->inumber);
	dp->d_ops->sf_put_ftype(sfep, args->filetype);
	sfp->count++;
	if (args->inumber > SCXFS_DIR2_MAX_SHORT_INUM && !objchange)
		sfp->i8count++;
	/*
	 * If there's more left to copy, do that.
	 */
	if (!eof) {
		sfep = dp->d_ops->sf_nextentry(sfp, sfep);
		memcpy(sfep, oldsfep, old_isize - nbytes);
	}
	kmem_free(buf);
	dp->i_d.di_size = new_isize;
	scxfs_dir2_sf_check(args);
}

/*
 * Decide if the new entry will fit at all.
 * If it will fit, pick between adding the new entry to the end (easy)
 * or somewhere else (hard).
 * Return 0 (won't fit), 1 (easy), 2 (hard).
 */
/*ARGSUSED*/
static int					/* pick result */
scxfs_dir2_sf_addname_pick(
	scxfs_da_args_t		*args,		/* operation arguments */
	int			objchange,	/* inode # size changes */
	scxfs_dir2_sf_entry_t	**sfepp,	/* out(1): new entry ptr */
	scxfs_dir2_data_aoff_t	*offsetp)	/* out(1): new offset */
{
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			holefit;	/* found hole it will fit in */
	int			i;		/* entry number */
	scxfs_dir2_data_aoff_t	offset;		/* data block offset */
	scxfs_dir2_sf_entry_t	*sfep;		/* shortform entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */
	int			size;		/* entry's data size */
	int			used;		/* data bytes used */

	dp = args->dp;

	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	size = dp->d_ops->data_entsize(args->namelen);
	offset = dp->d_ops->data_first_offset;
	sfep = scxfs_dir2_sf_firstentry(sfp);
	holefit = 0;
	/*
	 * Loop over sf entries.
	 * Keep track of data offset and whether we've seen a place
	 * to insert the new entry.
	 */
	for (i = 0; i < sfp->count; i++) {
		if (!holefit)
			holefit = offset + size <= scxfs_dir2_sf_get_offset(sfep);
		offset = scxfs_dir2_sf_get_offset(sfep) +
			 dp->d_ops->data_entsize(sfep->namelen);
		sfep = dp->d_ops->sf_nextentry(sfp, sfep);
	}
	/*
	 * Calculate data bytes used excluding the new entry, if this
	 * was a data block (block form directory).
	 */
	used = offset +
	       (sfp->count + 3) * (uint)sizeof(scxfs_dir2_leaf_entry_t) +
	       (uint)sizeof(scxfs_dir2_block_tail_t);
	/*
	 * If it won't fit in a block form then we can't insert it,
	 * we'll go back, convert to block, then try the insert and convert
	 * to leaf.
	 */
	if (used + (holefit ? 0 : size) > args->geo->blksize)
		return 0;
	/*
	 * If changing the inode number size, do it the hard way.
	 */
	if (objchange)
		return 2;
	/*
	 * If it won't fit at the end then do it the hard way (use the hole).
	 */
	if (used + size > args->geo->blksize)
		return 2;
	/*
	 * Do it the easy way.
	 */
	*sfepp = sfep;
	*offsetp = offset;
	return 1;
}

#ifdef DEBUG
/*
 * Check consistency of shortform directory, assert if bad.
 */
static void
scxfs_dir2_sf_check(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry number */
	int			i8count;	/* number of big inode#s */
	scxfs_ino_t		ino;		/* entry inode number */
	int			offset;		/* data offset */
	scxfs_dir2_sf_entry_t	*sfep;		/* shortform dir entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */

	dp = args->dp;

	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	offset = dp->d_ops->data_first_offset;
	ino = dp->d_ops->sf_get_parent_ino(sfp);
	i8count = ino > SCXFS_DIR2_MAX_SHORT_INUM;

	for (i = 0, sfep = scxfs_dir2_sf_firstentry(sfp);
	     i < sfp->count;
	     i++, sfep = dp->d_ops->sf_nextentry(sfp, sfep)) {
		ASSERT(scxfs_dir2_sf_get_offset(sfep) >= offset);
		ino = dp->d_ops->sf_get_ino(sfp, sfep);
		i8count += ino > SCXFS_DIR2_MAX_SHORT_INUM;
		offset =
			scxfs_dir2_sf_get_offset(sfep) +
			dp->d_ops->data_entsize(sfep->namelen);
		ASSERT(dp->d_ops->sf_get_ftype(sfep) < SCXFS_DIR3_FT_MAX);
	}
	ASSERT(i8count == sfp->i8count);
	ASSERT((char *)sfep - (char *)sfp == dp->i_d.di_size);
	ASSERT(offset +
	       (sfp->count + 2) * (uint)sizeof(scxfs_dir2_leaf_entry_t) +
	       (uint)sizeof(scxfs_dir2_block_tail_t) <= args->geo->blksize);
}
#endif	/* DEBUG */

/* Verify the consistency of an inline directory. */
scxfs_failaddr_t
scxfs_dir2_sf_verify(
	struct scxfs_inode		*ip)
{
	struct scxfs_mount		*mp = ip->i_mount;
	struct scxfs_dir2_sf_hdr		*sfp;
	struct scxfs_dir2_sf_entry	*sfep;
	struct scxfs_dir2_sf_entry	*next_sfep;
	char				*endp;
	const struct scxfs_dir_ops	*dops;
	struct scxfs_ifork		*ifp;
	scxfs_ino_t			ino;
	int				i;
	int				i8count;
	int				offset;
	int64_t				size;
	int				error;
	uint8_t				filetype;

	ASSERT(ip->i_d.di_format == SCXFS_DINODE_FMT_LOCAL);
	/*
	 * scxfs_iread calls us before scxfs_setup_inode sets up ip->d_ops,
	 * so we can only trust the mountpoint to have the right pointer.
	 */
	dops = scxfs_dir_get_ops(mp, NULL);

	ifp = SCXFS_IFORK_PTR(ip, SCXFS_DATA_FORK);
	sfp = (struct scxfs_dir2_sf_hdr *)ifp->if_u1.if_data;
	size = ifp->if_bytes;

	/*
	 * Give up if the directory is way too short.
	 */
	if (size <= offsetof(struct scxfs_dir2_sf_hdr, parent) ||
	    size < scxfs_dir2_sf_hdr_size(sfp->i8count))
		return __this_address;

	endp = (char *)sfp + size;

	/* Check .. entry */
	ino = dops->sf_get_parent_ino(sfp);
	i8count = ino > SCXFS_DIR2_MAX_SHORT_INUM;
	error = scxfs_dir_ino_validate(mp, ino);
	if (error)
		return __this_address;
	offset = dops->data_first_offset;

	/* Check all reported entries */
	sfep = scxfs_dir2_sf_firstentry(sfp);
	for (i = 0; i < sfp->count; i++) {
		/*
		 * struct scxfs_dir2_sf_entry has a variable length.
		 * Check the fixed-offset parts of the structure are
		 * within the data buffer.
		 */
		if (((char *)sfep + sizeof(*sfep)) >= endp)
			return __this_address;

		/* Don't allow names with known bad length. */
		if (sfep->namelen == 0)
			return __this_address;

		/*
		 * Check that the variable-length part of the structure is
		 * within the data buffer.  The next entry starts after the
		 * name component, so nextentry is an acceptable test.
		 */
		next_sfep = dops->sf_nextentry(sfp, sfep);
		if (endp < (char *)next_sfep)
			return __this_address;

		/* Check that the offsets always increase. */
		if (scxfs_dir2_sf_get_offset(sfep) < offset)
			return __this_address;

		/* Check the inode number. */
		ino = dops->sf_get_ino(sfp, sfep);
		i8count += ino > SCXFS_DIR2_MAX_SHORT_INUM;
		error = scxfs_dir_ino_validate(mp, ino);
		if (error)
			return __this_address;

		/* Check the file type. */
		filetype = dops->sf_get_ftype(sfep);
		if (filetype >= SCXFS_DIR3_FT_MAX)
			return __this_address;

		offset = scxfs_dir2_sf_get_offset(sfep) +
				dops->data_entsize(sfep->namelen);

		sfep = next_sfep;
	}
	if (i8count != sfp->i8count)
		return __this_address;
	if ((void *)sfep != (void *)endp)
		return __this_address;

	/* Make sure this whole thing ought to be in local format. */
	if (offset + (sfp->count + 2) * (uint)sizeof(scxfs_dir2_leaf_entry_t) +
	    (uint)sizeof(scxfs_dir2_block_tail_t) > mp->m_dir_geo->blksize)
		return __this_address;

	return NULL;
}

/*
 * Create a new (shortform) directory.
 */
int					/* error, always 0 */
scxfs_dir2_sf_create(
	scxfs_da_args_t	*args,		/* operation arguments */
	scxfs_ino_t	pino)		/* parent inode number */
{
	scxfs_inode_t	*dp;		/* incore directory inode */
	int		i8count;	/* parent inode is an 8-byte number */
	scxfs_dir2_sf_hdr_t *sfp;		/* shortform structure */
	int		size;		/* directory size */

	trace_scxfs_dir2_sf_create(args);

	dp = args->dp;

	ASSERT(dp != NULL);
	ASSERT(dp->i_d.di_size == 0);
	/*
	 * If it's currently a zero-length extent file,
	 * convert it to local format.
	 */
	if (dp->i_d.di_format == SCXFS_DINODE_FMT_EXTENTS) {
		dp->i_df.if_flags &= ~SCXFS_IFEXTENTS;	/* just in case */
		dp->i_d.di_format = SCXFS_DINODE_FMT_LOCAL;
		scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_CORE);
		dp->i_df.if_flags |= SCXFS_IFINLINE;
	}
	ASSERT(dp->i_df.if_flags & SCXFS_IFINLINE);
	ASSERT(dp->i_df.if_bytes == 0);
	i8count = pino > SCXFS_DIR2_MAX_SHORT_INUM;
	size = scxfs_dir2_sf_hdr_size(i8count);
	/*
	 * Make a buffer for the data.
	 */
	scxfs_idata_realloc(dp, size, SCXFS_DATA_FORK);
	/*
	 * Fill in the header,
	 */
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	sfp->i8count = i8count;
	/*
	 * Now can put in the inode number, since i8count is set.
	 */
	dp->d_ops->sf_put_parent_ino(sfp, pino);
	sfp->count = 0;
	dp->i_d.di_size = size;
	scxfs_dir2_sf_check(args);
	scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_CORE | SCXFS_ILOG_DDATA);
	return 0;
}

/*
 * Lookup an entry in a shortform directory.
 * Returns EEXIST if found, ENOENT if not found.
 */
int						/* error */
scxfs_dir2_sf_lookup(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry index */
	int			error;
	scxfs_dir2_sf_entry_t	*sfep;		/* shortform directory entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */
	enum scxfs_dacmp		cmp;		/* comparison result */
	scxfs_dir2_sf_entry_t	*ci_sfep;	/* case-insens. entry */

	trace_scxfs_dir2_sf_lookup(args);

	scxfs_dir2_sf_check(args);
	dp = args->dp;

	ASSERT(dp->i_df.if_flags & SCXFS_IFINLINE);
	/*
	 * Bail out if the directory is way too short.
	 */
	if (dp->i_d.di_size < offsetof(scxfs_dir2_sf_hdr_t, parent)) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(dp->i_mount));
		return -EIO;
	}
	ASSERT(dp->i_df.if_bytes == dp->i_d.di_size);
	ASSERT(dp->i_df.if_u1.if_data != NULL);
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(dp->i_d.di_size >= scxfs_dir2_sf_hdr_size(sfp->i8count));
	/*
	 * Special case for .
	 */
	if (args->namelen == 1 && args->name[0] == '.') {
		args->inumber = dp->i_ino;
		args->cmpresult = SCXFS_CMP_EXACT;
		args->filetype = SCXFS_DIR3_FT_DIR;
		return -EEXIST;
	}
	/*
	 * Special case for ..
	 */
	if (args->namelen == 2 &&
	    args->name[0] == '.' && args->name[1] == '.') {
		args->inumber = dp->d_ops->sf_get_parent_ino(sfp);
		args->cmpresult = SCXFS_CMP_EXACT;
		args->filetype = SCXFS_DIR3_FT_DIR;
		return -EEXIST;
	}
	/*
	 * Loop over all the entries trying to match ours.
	 */
	ci_sfep = NULL;
	for (i = 0, sfep = scxfs_dir2_sf_firstentry(sfp); i < sfp->count;
	     i++, sfep = dp->d_ops->sf_nextentry(sfp, sfep)) {
		/*
		 * Compare name and if it's an exact match, return the inode
		 * number. If it's the first case-insensitive match, store the
		 * inode number and continue looking for an exact match.
		 */
		cmp = dp->i_mount->m_dirnameops->compname(args, sfep->name,
								sfep->namelen);
		if (cmp != SCXFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			args->inumber = dp->d_ops->sf_get_ino(sfp, sfep);
			args->filetype = dp->d_ops->sf_get_ftype(sfep);
			if (cmp == SCXFS_CMP_EXACT)
				return -EEXIST;
			ci_sfep = sfep;
		}
	}
	ASSERT(args->op_flags & SCXFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or replace).
	 * If a case-insensitive match was not found, return -ENOENT.
	 */
	if (!ci_sfep)
		return -ENOENT;
	/* otherwise process the CI match as required by the caller */
	error = scxfs_dir_cilookup_result(args, ci_sfep->name, ci_sfep->namelen);
	return error;
}

/*
 * Remove an entry from a shortform directory.
 */
int						/* error */
scxfs_dir2_sf_removename(
	scxfs_da_args_t		*args)
{
	int			byteoff;	/* offset of removed entry */
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			entsize;	/* this entry's size */
	int			i;		/* shortform entry index */
	int			newsize;	/* new inode size */
	int			oldsize;	/* old inode size */
	scxfs_dir2_sf_entry_t	*sfep;		/* shortform directory entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */

	trace_scxfs_dir2_sf_removename(args);

	dp = args->dp;

	ASSERT(dp->i_df.if_flags & SCXFS_IFINLINE);
	oldsize = (int)dp->i_d.di_size;
	/*
	 * Bail out if the directory is way too short.
	 */
	if (oldsize < offsetof(scxfs_dir2_sf_hdr_t, parent)) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(dp->i_mount));
		return -EIO;
	}
	ASSERT(dp->i_df.if_bytes == oldsize);
	ASSERT(dp->i_df.if_u1.if_data != NULL);
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(oldsize >= scxfs_dir2_sf_hdr_size(sfp->i8count));
	/*
	 * Loop over the old directory entries.
	 * Find the one we're deleting.
	 */
	for (i = 0, sfep = scxfs_dir2_sf_firstentry(sfp); i < sfp->count;
	     i++, sfep = dp->d_ops->sf_nextentry(sfp, sfep)) {
		if (scxfs_da_compname(args, sfep->name, sfep->namelen) ==
								SCXFS_CMP_EXACT) {
			ASSERT(dp->d_ops->sf_get_ino(sfp, sfep) ==
			       args->inumber);
			break;
		}
	}
	/*
	 * Didn't find it.
	 */
	if (i == sfp->count)
		return -ENOENT;
	/*
	 * Calculate sizes.
	 */
	byteoff = (int)((char *)sfep - (char *)sfp);
	entsize = dp->d_ops->sf_entsize(sfp, args->namelen);
	newsize = oldsize - entsize;
	/*
	 * Copy the part if any after the removed entry, sliding it down.
	 */
	if (byteoff + entsize < oldsize)
		memmove((char *)sfp + byteoff, (char *)sfp + byteoff + entsize,
			oldsize - (byteoff + entsize));
	/*
	 * Fix up the header and file size.
	 */
	sfp->count--;
	dp->i_d.di_size = newsize;
	/*
	 * Reallocate, making it smaller.
	 */
	scxfs_idata_realloc(dp, newsize - oldsize, SCXFS_DATA_FORK);
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	/*
	 * Are we changing inode number size?
	 */
	if (args->inumber > SCXFS_DIR2_MAX_SHORT_INUM) {
		if (sfp->i8count == 1)
			scxfs_dir2_sf_toino4(args);
		else
			sfp->i8count--;
	}
	scxfs_dir2_sf_check(args);
	scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_CORE | SCXFS_ILOG_DDATA);
	return 0;
}

/*
 * Replace the inode number of an entry in a shortform directory.
 */
int						/* error */
scxfs_dir2_sf_replace(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry index */
	scxfs_ino_t		ino=0;		/* entry old inode number */
	int			i8elevated;	/* sf_toino8 set i8count=1 */
	scxfs_dir2_sf_entry_t	*sfep;		/* shortform directory entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */

	trace_scxfs_dir2_sf_replace(args);

	dp = args->dp;

	ASSERT(dp->i_df.if_flags & SCXFS_IFINLINE);
	/*
	 * Bail out if the shortform directory is way too small.
	 */
	if (dp->i_d.di_size < offsetof(scxfs_dir2_sf_hdr_t, parent)) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(dp->i_mount));
		return -EIO;
	}
	ASSERT(dp->i_df.if_bytes == dp->i_d.di_size);
	ASSERT(dp->i_df.if_u1.if_data != NULL);
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(dp->i_d.di_size >= scxfs_dir2_sf_hdr_size(sfp->i8count));

	/*
	 * New inode number is large, and need to convert to 8-byte inodes.
	 */
	if (args->inumber > SCXFS_DIR2_MAX_SHORT_INUM && sfp->i8count == 0) {
		int	error;			/* error return value */
		int	newsize;		/* new inode size */

		newsize = dp->i_df.if_bytes + (sfp->count + 1) * SCXFS_INO64_DIFF;
		/*
		 * Won't fit as shortform, convert to block then do replace.
		 */
		if (newsize > SCXFS_IFORK_DSIZE(dp)) {
			error = scxfs_dir2_sf_to_block(args);
			if (error) {
				return error;
			}
			return scxfs_dir2_block_replace(args);
		}
		/*
		 * Still fits, convert to 8-byte now.
		 */
		scxfs_dir2_sf_toino8(args);
		i8elevated = 1;
		sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	} else
		i8elevated = 0;

	ASSERT(args->namelen != 1 || args->name[0] != '.');
	/*
	 * Replace ..'s entry.
	 */
	if (args->namelen == 2 &&
	    args->name[0] == '.' && args->name[1] == '.') {
		ino = dp->d_ops->sf_get_parent_ino(sfp);
		ASSERT(args->inumber != ino);
		dp->d_ops->sf_put_parent_ino(sfp, args->inumber);
	}
	/*
	 * Normal entry, look for the name.
	 */
	else {
		for (i = 0, sfep = scxfs_dir2_sf_firstentry(sfp); i < sfp->count;
		     i++, sfep = dp->d_ops->sf_nextentry(sfp, sfep)) {
			if (scxfs_da_compname(args, sfep->name, sfep->namelen) ==
								SCXFS_CMP_EXACT) {
				ino = dp->d_ops->sf_get_ino(sfp, sfep);
				ASSERT(args->inumber != ino);
				dp->d_ops->sf_put_ino(sfp, sfep, args->inumber);
				dp->d_ops->sf_put_ftype(sfep, args->filetype);
				break;
			}
		}
		/*
		 * Didn't find it.
		 */
		if (i == sfp->count) {
			ASSERT(args->op_flags & SCXFS_DA_OP_OKNOENT);
			if (i8elevated)
				scxfs_dir2_sf_toino4(args);
			return -ENOENT;
		}
	}
	/*
	 * See if the old number was large, the new number is small.
	 */
	if (ino > SCXFS_DIR2_MAX_SHORT_INUM &&
	    args->inumber <= SCXFS_DIR2_MAX_SHORT_INUM) {
		/*
		 * And the old count was one, so need to convert to small.
		 */
		if (sfp->i8count == 1)
			scxfs_dir2_sf_toino4(args);
		else
			sfp->i8count--;
	}
	/*
	 * See if the old number was small, the new number is large.
	 */
	if (ino <= SCXFS_DIR2_MAX_SHORT_INUM &&
	    args->inumber > SCXFS_DIR2_MAX_SHORT_INUM) {
		/*
		 * add to the i8count unless we just converted to 8-byte
		 * inodes (which does an implied i8count = 1)
		 */
		ASSERT(sfp->i8count != 0);
		if (!i8elevated)
			sfp->i8count++;
	}
	scxfs_dir2_sf_check(args);
	scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_DDATA);
	return 0;
}

/*
 * Convert from 8-byte inode numbers to 4-byte inode numbers.
 * The last 8-byte inode number is gone, but the count is still 1.
 */
static void
scxfs_dir2_sf_toino4(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	char			*buf;		/* old dir's buffer */
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry index */
	int			newsize;	/* new inode size */
	scxfs_dir2_sf_entry_t	*oldsfep;	/* old sf entry */
	scxfs_dir2_sf_hdr_t	*oldsfp;	/* old sf directory */
	int			oldsize;	/* old inode size */
	scxfs_dir2_sf_entry_t	*sfep;		/* new sf entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* new sf directory */

	trace_scxfs_dir2_sf_toino4(args);

	dp = args->dp;

	/*
	 * Copy the old directory to the buffer.
	 * Then nuke it from the inode, and add the new buffer to the inode.
	 * Don't want scxfs_idata_realloc copying the data here.
	 */
	oldsize = dp->i_df.if_bytes;
	buf = kmem_alloc(oldsize, 0);
	oldsfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(oldsfp->i8count == 1);
	memcpy(buf, oldsfp, oldsize);
	/*
	 * Compute the new inode size.
	 */
	newsize = oldsize - (oldsfp->count + 1) * SCXFS_INO64_DIFF;
	scxfs_idata_realloc(dp, -oldsize, SCXFS_DATA_FORK);
	scxfs_idata_realloc(dp, newsize, SCXFS_DATA_FORK);
	/*
	 * Reset our pointers, the data has moved.
	 */
	oldsfp = (scxfs_dir2_sf_hdr_t *)buf;
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	/*
	 * Fill in the new header.
	 */
	sfp->count = oldsfp->count;
	sfp->i8count = 0;
	dp->d_ops->sf_put_parent_ino(sfp, dp->d_ops->sf_get_parent_ino(oldsfp));
	/*
	 * Copy the entries field by field.
	 */
	for (i = 0, sfep = scxfs_dir2_sf_firstentry(sfp),
		    oldsfep = scxfs_dir2_sf_firstentry(oldsfp);
	     i < sfp->count;
	     i++, sfep = dp->d_ops->sf_nextentry(sfp, sfep),
		  oldsfep = dp->d_ops->sf_nextentry(oldsfp, oldsfep)) {
		sfep->namelen = oldsfep->namelen;
		memcpy(sfep->offset, oldsfep->offset, sizeof(sfep->offset));
		memcpy(sfep->name, oldsfep->name, sfep->namelen);
		dp->d_ops->sf_put_ino(sfp, sfep,
				      dp->d_ops->sf_get_ino(oldsfp, oldsfep));
		dp->d_ops->sf_put_ftype(sfep, dp->d_ops->sf_get_ftype(oldsfep));
	}
	/*
	 * Clean up the inode.
	 */
	kmem_free(buf);
	dp->i_d.di_size = newsize;
	scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_CORE | SCXFS_ILOG_DDATA);
}

/*
 * Convert existing entries from 4-byte inode numbers to 8-byte inode numbers.
 * The new entry w/ an 8-byte inode number is not there yet; we leave with
 * i8count set to 1, but no corresponding 8-byte entry.
 */
static void
scxfs_dir2_sf_toino8(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	char			*buf;		/* old dir's buffer */
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry index */
	int			newsize;	/* new inode size */
	scxfs_dir2_sf_entry_t	*oldsfep;	/* old sf entry */
	scxfs_dir2_sf_hdr_t	*oldsfp;	/* old sf directory */
	int			oldsize;	/* old inode size */
	scxfs_dir2_sf_entry_t	*sfep;		/* new sf entry */
	scxfs_dir2_sf_hdr_t	*sfp;		/* new sf directory */

	trace_scxfs_dir2_sf_toino8(args);

	dp = args->dp;

	/*
	 * Copy the old directory to the buffer.
	 * Then nuke it from the inode, and add the new buffer to the inode.
	 * Don't want scxfs_idata_realloc copying the data here.
	 */
	oldsize = dp->i_df.if_bytes;
	buf = kmem_alloc(oldsize, 0);
	oldsfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(oldsfp->i8count == 0);
	memcpy(buf, oldsfp, oldsize);
	/*
	 * Compute the new inode size (nb: entry count + 1 for parent)
	 */
	newsize = oldsize + (oldsfp->count + 1) * SCXFS_INO64_DIFF;
	scxfs_idata_realloc(dp, -oldsize, SCXFS_DATA_FORK);
	scxfs_idata_realloc(dp, newsize, SCXFS_DATA_FORK);
	/*
	 * Reset our pointers, the data has moved.
	 */
	oldsfp = (scxfs_dir2_sf_hdr_t *)buf;
	sfp = (scxfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	/*
	 * Fill in the new header.
	 */
	sfp->count = oldsfp->count;
	sfp->i8count = 1;
	dp->d_ops->sf_put_parent_ino(sfp, dp->d_ops->sf_get_parent_ino(oldsfp));
	/*
	 * Copy the entries field by field.
	 */
	for (i = 0, sfep = scxfs_dir2_sf_firstentry(sfp),
		    oldsfep = scxfs_dir2_sf_firstentry(oldsfp);
	     i < sfp->count;
	     i++, sfep = dp->d_ops->sf_nextentry(sfp, sfep),
		  oldsfep = dp->d_ops->sf_nextentry(oldsfp, oldsfep)) {
		sfep->namelen = oldsfep->namelen;
		memcpy(sfep->offset, oldsfep->offset, sizeof(sfep->offset));
		memcpy(sfep->name, oldsfep->name, sfep->namelen);
		dp->d_ops->sf_put_ino(sfp, sfep,
				      dp->d_ops->sf_get_ino(oldsfp, oldsfep));
		dp->d_ops->sf_put_ftype(sfep, dp->d_ops->sf_get_ftype(oldsfep));
	}
	/*
	 * Clean up the inode.
	 */
	kmem_free(buf);
	dp->i_d.di_size = newsize;
	scxfs_trans_log_inode(args->trans, dp, SCXFS_ILOG_CORE | SCXFS_ILOG_DDATA);
}
