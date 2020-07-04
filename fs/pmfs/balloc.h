#ifndef __PMFS_BALLOC_H
#define __PMFS_BALLOC_H

#include "inode.h"

/* DRAM structure to hold a list of free PMEM blocks */
struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct pmfs_range_node *first_node; // lowest address free range
	struct pmfs_range_node *last_node; // highest address free range

	int		index; // Which CPU do I belong to?

	/* Start and end of allocatable range, inclusive. Excludes csum and
	 * parity blocks.
	 */
	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long	num_free_blocks;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode;

	/* Statistics */
	/*
	unsigned long	alloc_log_count;
	unsigned long	alloc_data_count;
	unsigned long	free_log_count;
	unsigned long	free_data_count;
	unsigned long	alloc_log_pages;
	unsigned long	alloc_data_pages;
	unsigned long	freed_log_pages;
	unsigned long	freed_data_pages;
	*/

	u64		padding[8];	/* Cache line break.
					 * [TODO]: Need to measure this */
};

static inline
struct free_list *pmfs_get_free_list(struct super_block *sb, int cpu)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	return &sbi->free_lists[cpu];
}

enum node_type {
	NODE_BLOCK=1,
	NODE_INODE,
	NODE_DIR,
};

struct pmfs_range_node *pmfs_alloc_inode_node(struct super_block *sb);
struct pmfs_range_node *pmfs_alloc_dir_node(struct super_block *sb);
void pmfs_free_range_node(struct pmfs_range_node *node);
void pmfs_free_inode_node(struct pmfs_range_node *node);
extern void pmfs_free_dir_node(struct pmfs_range_node *bnode);
extern int pmfs_find_range_node(struct rb_root *tree, unsigned long key,
				enum node_type type, struct pmfs_range_node **ret_node);
int pmfs_search_inodetree(struct pmfs_sb_info *sbi,
			  unsigned long ino, struct pmfs_range_node **ret_node);
int pmfs_insert_inodetree(struct pmfs_sb_info *sbi,
			  struct pmfs_range_node *new_node);

extern int pmfs_insert_range_node(struct rb_root *tree,
				  struct pmfs_range_node *new_node, enum node_type type);
void pmfs_destroy_range_node_tree(struct super_block *sb,
				  struct rb_root *tree);
int pmfs_insert_blocktree(struct rb_root *tree,
			  struct pmfs_range_node *new_node);

#endif
