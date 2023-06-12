/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SCXFS_PNFS_H
#define _SCXFS_PNFS_H 1

#ifdef CONFIG_EXPORTFS_BLOCK_OPS
int scxfs_fs_get_uuid(struct super_block *sb, u8 *buf, u32 *len, u64 *offset);
int scxfs_fs_map_blocks(struct inode *inode, loff_t offset, u64 length,
		struct iomap *iomap, bool write, u32 *device_generation);
int scxfs_fs_commit_blocks(struct inode *inode, struct iomap *maps, int nr_maps,
		struct iattr *iattr);

int scxfs_break_leased_layouts(struct inode *inode, uint *iolock,
		bool *did_unlock);
#else
static inline int
scxfs_break_leased_layouts(struct inode *inode, uint *iolock, bool *did_unlock)
{
	return 0;
}
#endif /* CONFIG_EXPORTFS_BLOCK_OPS */
#endif /* _SCXFS_PNFS_H */
