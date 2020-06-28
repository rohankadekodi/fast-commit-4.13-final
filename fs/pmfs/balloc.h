#ifndef __PMFS_BALLOC_H
#define __PMFS_BALLOC_H

#include "inode.h"

struct pmfs_range_node *pmfs_alloc_dir_node(struct super_block *sb);
void pmfs_free_range_node(struct pmfs_range_node *node);
extern void pmfs_free_dir_node(struct pmfs_range_node *bnode);
extern int pmfs_find_range_node(struct rb_root *tree, unsigned long key,
				struct pmfs_range_node **ret_node);
extern int pmfs_insert_range_node(struct rb_root *tree,
				  struct pmfs_range_node *new_node);
void pmfs_destroy_range_node_tree(struct super_block *sb,
				  struct rb_root *tree);
#endif
