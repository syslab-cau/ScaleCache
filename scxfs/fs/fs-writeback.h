
/*
 * Passed into wb_writeback(), essentially a subset of writeback_control
 */
struct wb_writeback_work {
	long nr_pages;
	struct super_block *sb;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	unsigned int for_sync:1;	/* sync(2) WB_SYNC_ALL writeback */
	unsigned int auto_free:1;	/* free on completion */
	enum wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct wb_completion *done;	/* set if the caller waits */
};

/* exported functions from fs/fs-writeback.c */
extern long wb_writeback(struct bdi_writeback *wb, struct wb_writeback_work *work);
extern void finish_writeback_work(struct bdi_writeback *wb, struct wb_writeback_work *work);
extern long wb_check_start_all(struct bdi_writeback *wb);
extern long wb_check_old_data_flush(struct bdi_writeback *wb);
extern void queue_io(struct bdi_writeback *wb, struct wb_writeback_work *work,
		     unsigned long dirtied_before);
extern long writeback_sb_inodes(struct super_block *sb,
				struct bdi_writeback *wb,
				struct wb_writeback_work *work);
extern long writeback_inodes_wb(struct bdi_writeback *wb, long nr_pages,
				enum wb_reason reason);  
extern long __writeback_inodes_wb(struct bdi_writeback *wb,
				  struct wb_writeback_work *work);
extern inline struct inode *wb_inode(struct list_head *head);
extern long wb_split_bdi_pages(struct bdi_writeback *wb, long nr_pages);
extern unsigned long get_nr_dirty_pages(void);

