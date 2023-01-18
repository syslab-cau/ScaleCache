// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016 Oracle.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ONDISK_H
#define __SCXFS_ONDISK_H

#define SCXFS_CHECK_STRUCT_SIZE(structname, size) \
	BUILD_BUG_ON_MSG(sizeof(structname) != (size), "SCXFS: sizeof(" \
		#structname ") is wrong, expected " #size)

#define SCXFS_CHECK_OFFSET(structname, member, off) \
	BUILD_BUG_ON_MSG(offsetof(structname, member) != (off), \
		"SCXFS: offsetof(" #structname ", " #member ") is wrong, " \
		"expected " #off)

static inline void __init
scxfs_check_ondisk_structs(void)
{
	/* ag/file structures */
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_acl,			4);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_acl_entry,		12);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_agf,			224);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_agfl,			36);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_agi,			336);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_bmbt_key,		8);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_bmbt_rec,		16);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_bmdr_block,		4);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_btree_block_shdr,	48);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_btree_block_lhdr,	64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_btree_block,		72);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dinode,		176);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_disk_dquot,		104);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dqblk,			136);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dsb,			264);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dsymlink_hdr,		56);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_inobt_key,		4);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_inobt_rec,		16);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_refcount_key,		4);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_refcount_rec,		12);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_rmap_key,		20);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_rmap_rec,		24);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_timestamp,		8);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_alloc_key_t,			8);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_alloc_ptr_t,			4);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_alloc_rec_t,			8);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_inobt_ptr_t,			4);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_refcount_ptr_t,		4);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_rmap_ptr_t,			4);

	/* dir/attr trees */
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_attr3_leaf_hdr,	80);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_attr3_leafblock,	88);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_attr3_rmt_hdr,		56);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_da3_blkinfo,		56);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_da3_intnode,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_da3_node_hdr,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dir3_blk_hdr,		48);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dir3_data_hdr,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dir3_free,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dir3_free_hdr,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dir3_leaf,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dir3_leaf_hdr,		64);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_attr_leaf_entry_t,		8);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_attr_leaf_hdr_t,		32);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_attr_leaf_map_t,		4);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_attr_leaf_name_local_t,	4);

	/*
	 * m68k has problems with scxfs_attr_leaf_name_remote_t, but we pad it to
	 * 4 bytes anyway so it's not obviously a problem.  Hence for the moment
	 * we don't check this structure. This can be re-instated when the attr
	 * definitions are updated to use c99 VLA definitions.
	 *
	SCXFS_CHECK_STRUCT_SIZE(scxfs_attr_leaf_name_remote_t,	12);
	 */

	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_local_t, valuelen,	0);
	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_local_t, namelen,	2);
	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_local_t, nameval,	3);
	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_remote_t, valueblk,	0);
	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_remote_t, valuelen,	4);
	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_remote_t, namelen,	8);
	SCXFS_CHECK_OFFSET(scxfs_attr_leaf_name_remote_t, name,	9);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_attr_leafblock_t,		40);
	SCXFS_CHECK_OFFSET(scxfs_attr_shortform_t, hdr.totsize,	0);
	SCXFS_CHECK_OFFSET(scxfs_attr_shortform_t, hdr.count,	2);
	SCXFS_CHECK_OFFSET(scxfs_attr_shortform_t, list[0].namelen,	4);
	SCXFS_CHECK_OFFSET(scxfs_attr_shortform_t, list[0].valuelen, 5);
	SCXFS_CHECK_OFFSET(scxfs_attr_shortform_t, list[0].flags,	6);
	SCXFS_CHECK_OFFSET(scxfs_attr_shortform_t, list[0].nameval,	7);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_da_blkinfo_t,			12);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_da_intnode_t,			16);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_da_node_entry_t,		8);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_da_node_hdr_t,		16);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_data_free_t,		4);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_data_hdr_t,		16);
	SCXFS_CHECK_OFFSET(scxfs_dir2_data_unused_t, freetag,	0);
	SCXFS_CHECK_OFFSET(scxfs_dir2_data_unused_t, length,	2);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_free_hdr_t,		16);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_free_t,			16);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_leaf_entry_t,		8);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_leaf_hdr_t,		16);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_leaf_t,			16);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_leaf_tail_t,		4);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_sf_entry_t,		3);
	SCXFS_CHECK_OFFSET(scxfs_dir2_sf_entry_t, namelen,		0);
	SCXFS_CHECK_OFFSET(scxfs_dir2_sf_entry_t, offset,		1);
	SCXFS_CHECK_OFFSET(scxfs_dir2_sf_entry_t, name,		3);
	SCXFS_CHECK_STRUCT_SIZE(scxfs_dir2_sf_hdr_t,		10);

	/* log structures */
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_dq_logformat,		24);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_efd_log_format_32,	28);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_efd_log_format_64,	32);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_efi_log_format_32,	28);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_efi_log_format_64,	32);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_extent_32,		12);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_extent_64,		16);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_log_dinode,		176);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_icreate_log,		28);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_ictimestamp,		8);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_inode_log_format_32,	52);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_inode_log_format,	56);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_qoff_logformat,	20);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_trans_header,		16);

	/*
	 * The v5 superblock format extended several v4 header structures with
	 * additional data. While new fields are only accessible on v5
	 * superblocks, it's important that the v5 structures place original v4
	 * fields/headers in the correct location on-disk. For example, we must
	 * be able to find magic values at the same location in certain blocks
	 * regardless of superblock version.
	 *
	 * The following checks ensure that various v5 data structures place the
	 * subset of v4 metadata associated with the same type of block at the
	 * start of the on-disk block. If there is no data structure definition
	 * for certain types of v4 blocks, traverse down to the first field of
	 * common metadata (e.g., magic value) and make sure it is at offset
	 * zero.
	 */
	SCXFS_CHECK_OFFSET(struct scxfs_dir3_leaf, hdr.info.hdr,	0);
	SCXFS_CHECK_OFFSET(struct scxfs_da3_intnode, hdr.info.hdr,	0);
	SCXFS_CHECK_OFFSET(struct scxfs_dir3_data_hdr, hdr.magic,	0);
	SCXFS_CHECK_OFFSET(struct scxfs_dir3_free, hdr.hdr.magic,	0);
	SCXFS_CHECK_OFFSET(struct scxfs_attr3_leafblock, hdr.info.hdr, 0);

	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_bulkstat,		192);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_inumbers,		24);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_bulkstat_req,		64);
	SCXFS_CHECK_STRUCT_SIZE(struct scxfs_inumbers_req,		64);
}

#endif /* __SCXFS_ONDISK_H */
