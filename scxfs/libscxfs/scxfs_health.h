// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_HEALTH_H__
#define __SCXFS_HEALTH_H__

/*
 * In-Core Filesystem Health Assessments
 * =====================================
 *
 * We'd like to be able to summarize the current health status of the
 * filesystem so that the administrator knows when it's necessary to schedule
 * some downtime for repairs.  Until then, we would also like to avoid abrupt
 * shutdowns due to corrupt metadata.
 *
 * The online scrub feature evaluates the health of all filesystem metadata.
 * When scrub detects corruption in a piece of metadata it will set the
 * corresponding sickness flag, and repair will clear it if successful.  If
 * problems remain at unmount time, we can also request manual intervention by
 * logging a notice to run scxfs_repair.
 *
 * Each health tracking group uses a pair of fields for reporting.  The
 * "checked" field tell us if a given piece of metadata has ever been examined,
 * and the "sick" field tells us if that piece was found to need repairs.
 * Therefore we can conclude that for a given sick flag value:
 *
 *  - checked && sick  => metadata needs repair
 *  - checked && !sick => metadata is ok
 *  - !checked         => has not been examined since mount
 */

struct scxfs_mount;
struct scxfs_perag;
struct scxfs_inode;
struct scxfs_fsop_geom;

/* Observable health issues for metadata spanning the entire filesystem. */
#define SCXFS_SICK_FS_COUNTERS	(1 << 0)  /* summary counters */
#define SCXFS_SICK_FS_UQUOTA	(1 << 1)  /* user quota */
#define SCXFS_SICK_FS_GQUOTA	(1 << 2)  /* group quota */
#define SCXFS_SICK_FS_PQUOTA	(1 << 3)  /* project quota */

/* Observable health issues for realtime volume metadata. */
#define SCXFS_SICK_RT_BITMAP	(1 << 0)  /* realtime bitmap */
#define SCXFS_SICK_RT_SUMMARY	(1 << 1)  /* realtime summary */

/* Observable health issues for AG metadata. */
#define SCXFS_SICK_AG_SB		(1 << 0)  /* superblock */
#define SCXFS_SICK_AG_AGF		(1 << 1)  /* AGF header */
#define SCXFS_SICK_AG_AGFL	(1 << 2)  /* AGFL header */
#define SCXFS_SICK_AG_AGI		(1 << 3)  /* AGI header */
#define SCXFS_SICK_AG_BNOBT	(1 << 4)  /* free space by block */
#define SCXFS_SICK_AG_CNTBT	(1 << 5)  /* free space by length */
#define SCXFS_SICK_AG_INOBT	(1 << 6)  /* inode index */
#define SCXFS_SICK_AG_FINOBT	(1 << 7)  /* free inode index */
#define SCXFS_SICK_AG_RMAPBT	(1 << 8)  /* reverse mappings */
#define SCXFS_SICK_AG_REFCNTBT	(1 << 9)  /* reference counts */

/* Observable health issues for inode metadata. */
#define SCXFS_SICK_INO_CORE	(1 << 0)  /* inode core */
#define SCXFS_SICK_INO_BMBTD	(1 << 1)  /* data fork */
#define SCXFS_SICK_INO_BMBTA	(1 << 2)  /* attr fork */
#define SCXFS_SICK_INO_BMBTC	(1 << 3)  /* cow fork */
#define SCXFS_SICK_INO_DIR	(1 << 4)  /* directory */
#define SCXFS_SICK_INO_XATTR	(1 << 5)  /* extended attributes */
#define SCXFS_SICK_INO_SYMLINK	(1 << 6)  /* symbolic link remote target */
#define SCXFS_SICK_INO_PARENT	(1 << 7)  /* parent pointers */

/* Primary evidence of health problems in a given group. */
#define SCXFS_SICK_FS_PRIMARY	(SCXFS_SICK_FS_COUNTERS | \
				 SCXFS_SICK_FS_UQUOTA | \
				 SCXFS_SICK_FS_GQUOTA | \
				 SCXFS_SICK_FS_PQUOTA)

#define SCXFS_SICK_RT_PRIMARY	(SCXFS_SICK_RT_BITMAP | \
				 SCXFS_SICK_RT_SUMMARY)

#define SCXFS_SICK_AG_PRIMARY	(SCXFS_SICK_AG_SB | \
				 SCXFS_SICK_AG_AGF | \
				 SCXFS_SICK_AG_AGFL | \
				 SCXFS_SICK_AG_AGI | \
				 SCXFS_SICK_AG_BNOBT | \
				 SCXFS_SICK_AG_CNTBT | \
				 SCXFS_SICK_AG_INOBT | \
				 SCXFS_SICK_AG_FINOBT | \
				 SCXFS_SICK_AG_RMAPBT | \
				 SCXFS_SICK_AG_REFCNTBT)

#define SCXFS_SICK_INO_PRIMARY	(SCXFS_SICK_INO_CORE | \
				 SCXFS_SICK_INO_BMBTD | \
				 SCXFS_SICK_INO_BMBTA | \
				 SCXFS_SICK_INO_BMBTC | \
				 SCXFS_SICK_INO_DIR | \
				 SCXFS_SICK_INO_XATTR | \
				 SCXFS_SICK_INO_SYMLINK | \
				 SCXFS_SICK_INO_PARENT)

/* These functions must be provided by the scxfs implementation. */

void scxfs_fs_mark_sick(struct scxfs_mount *mp, unsigned int mask);
void scxfs_fs_mark_healthy(struct scxfs_mount *mp, unsigned int mask);
void scxfs_fs_measure_sickness(struct scxfs_mount *mp, unsigned int *sick,
		unsigned int *checked);

void scxfs_rt_mark_sick(struct scxfs_mount *mp, unsigned int mask);
void scxfs_rt_mark_healthy(struct scxfs_mount *mp, unsigned int mask);
void scxfs_rt_measure_sickness(struct scxfs_mount *mp, unsigned int *sick,
		unsigned int *checked);

void scxfs_ag_mark_sick(struct scxfs_perag *pag, unsigned int mask);
void scxfs_ag_mark_healthy(struct scxfs_perag *pag, unsigned int mask);
void scxfs_ag_measure_sickness(struct scxfs_perag *pag, unsigned int *sick,
		unsigned int *checked);

void scxfs_inode_mark_sick(struct scxfs_inode *ip, unsigned int mask);
void scxfs_inode_mark_healthy(struct scxfs_inode *ip, unsigned int mask);
void scxfs_inode_measure_sickness(struct scxfs_inode *ip, unsigned int *sick,
		unsigned int *checked);

void scxfs_health_unmount(struct scxfs_mount *mp);

/* Now some helpers. */

static inline bool
scxfs_fs_has_sickness(struct scxfs_mount *mp, unsigned int mask)
{
	unsigned int	sick, checked;

	scxfs_fs_measure_sickness(mp, &sick, &checked);
	return sick & mask;
}

static inline bool
scxfs_rt_has_sickness(struct scxfs_mount *mp, unsigned int mask)
{
	unsigned int	sick, checked;

	scxfs_rt_measure_sickness(mp, &sick, &checked);
	return sick & mask;
}

static inline bool
scxfs_ag_has_sickness(struct scxfs_perag *pag, unsigned int mask)
{
	unsigned int	sick, checked;

	scxfs_ag_measure_sickness(pag, &sick, &checked);
	return sick & mask;
}

static inline bool
scxfs_inode_has_sickness(struct scxfs_inode *ip, unsigned int mask)
{
	unsigned int	sick, checked;

	scxfs_inode_measure_sickness(ip, &sick, &checked);
	return sick & mask;
}

static inline bool
scxfs_fs_is_healthy(struct scxfs_mount *mp)
{
	return !scxfs_fs_has_sickness(mp, -1U);
}

static inline bool
scxfs_rt_is_healthy(struct scxfs_mount *mp)
{
	return !scxfs_rt_has_sickness(mp, -1U);
}

static inline bool
scxfs_ag_is_healthy(struct scxfs_perag *pag)
{
	return !scxfs_ag_has_sickness(pag, -1U);
}

static inline bool
scxfs_inode_is_healthy(struct scxfs_inode *ip)
{
	return !scxfs_inode_has_sickness(ip, -1U);
}

void scxfs_fsop_geom_health(struct scxfs_mount *mp, struct scxfs_fsop_geom *geo);
void scxfs_ag_geom_health(struct scxfs_perag *pag, struct scxfs_ag_geometry *ageo);
void scxfs_bulkstat_health(struct scxfs_inode *ip, struct scxfs_bulkstat *bs);

#endif	/* __SCXFS_HEALTH_H__ */
