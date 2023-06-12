/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SCXFS_DISCARD_H
#define SCXFS_DISCARD_H 1

struct fstrim_range;
struct list_head;

extern int	scxfs_ioc_trim(struct scxfs_mount *, struct fstrim_range __user *);

#endif /* SCXFS_DISCARD_H */
