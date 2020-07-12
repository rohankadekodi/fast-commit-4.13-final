/*
 * PMFS emulated persistence. This file contains code to 
 * handle data blocks of various sizes efficiently.
 *
 * Persistent Memory File System
 * Copyright (c) 2012-2013, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include "pmfs.h"
#include "inode.h"

int pmfs_alloc_block_free_lists(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = kcalloc(sbi->cpus, sizeof(struct free_list),
				  GFP_KERNEL);

	if (!sbi->free_lists)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		free_list->block_free_tree = RB_ROOT;
		spin_lock_init(&free_list->s_lock);
		free_list->index = i;
	}

	return 0;
}

// Initialize a free list.  Each CPU gets an equal share of the block space to
// manage.
static void pmfs_init_free_list(struct super_block *sb,
	struct free_list *free_list, int index)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long per_list_blocks;

	per_list_blocks = sbi->num_blocks / sbi->cpus;

	free_list->block_start = per_list_blocks * index;
	free_list->block_end = free_list->block_start +
					per_list_blocks - 1;
	if (index == 0)
		free_list->block_start += sbi->head_reserved_blocks;
}

void pmfs_delete_free_lists(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	/* Each tree is freed in save_blocknode_mappings */
	kfree(sbi->free_lists);
	sbi->free_lists = NULL;
}

void pmfs_init_blockmap(struct super_block *sb, unsigned long init_used_size)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct rb_root *tree;
	struct pmfs_range_node *blknode;
	struct free_list *free_list;
	int i;
	int ret;
	unsigned long num_used_block;

	num_used_block = (init_used_size + sb->s_blocksize - 1) >>
		sb->s_blocksize_bits;

	sbi->head_reserved_blocks = num_used_block;

	pmfs_dbg_verbose("%s: sbi->head_reserved_blocks = %lu\n", __func__,
			 sbi->head_reserved_blocks);

	sbi->per_list_blocks = sbi->num_blocks / sbi->cpus;
	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		pmfs_init_free_list(sb, free_list, i);

		free_list->num_free_blocks = free_list->block_end -
			free_list->block_start + 1;
		blknode = pmfs_alloc_blocknode(sb);
		if (blknode == NULL)
			PMFS_ASSERT(0);

		blknode->range_low = free_list->block_start;
		blknode->range_high = free_list->block_end;
		ret = pmfs_insert_blocktree(tree, blknode);
		if (ret) {
			pmfs_err(sb, "%s failed\n", __func__);
			pmfs_free_blocknode(blknode);
			return;
		}
		free_list->first_node = blknode;
		free_list->last_node = blknode;
		free_list->num_blocknode = 1;

		pmfs_dbg_verbose("%s: free list %d: block start %lu, end %lu, "
				 "%lu free blocks\n",
				 __func__, i,
				 free_list->block_start,
				 free_list->block_end,
				 free_list->num_free_blocks);
	}
}

static inline int pmfs_rbtree_compare_rangenode(struct pmfs_range_node *curr,
						unsigned long key, enum node_type type)
{
	if (type == NODE_DIR) {
		if (key < curr->hash)
			return -1;
		if (key > curr->hash)
			return 1;
		return 0;
	}

	/* Inode */
	if (key < curr->range_low)
		return -1;
	if (key > curr->range_high)
		return 1;

	return 0;
}

int pmfs_find_range_node(struct rb_root *tree, unsigned long key,
			 enum node_type type, struct pmfs_range_node **ret_node)
{
	struct pmfs_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct pmfs_range_node, node);
		compVal = pmfs_rbtree_compare_rangenode(curr, key, type);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}

int pmfs_insert_range_node(struct rb_root *tree,
			   struct pmfs_range_node *new_node, enum node_type type)
{
	struct pmfs_range_node *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct pmfs_range_node, node);
		compVal = pmfs_rbtree_compare_rangenode(curr,
							new_node->range_low, type);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			pmfs_dbg("%s: entry %lu - %lu already exists: "
				"%lu - %lu\n",
				 __func__, new_node->range_low,
				new_node->range_high, curr->range_low,
				curr->range_high);
			return -EINVAL;
		}
	}

	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	return 0;
}

void pmfs_destroy_range_node_tree(struct super_block *sb,
				  struct rb_root *tree)
{
	struct pmfs_range_node *curr;
	struct rb_node *temp;

	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct pmfs_range_node, node);
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		pmfs_free_range_node(curr);
	}
}

int pmfs_insert_blocktree(struct rb_root *tree,
			  struct pmfs_range_node *new_node)
{
	int ret;

	ret = pmfs_insert_range_node(tree, new_node, NODE_BLOCK);
	if (ret)
		pmfs_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

/* Return how many blocks allocated */
static long pmfs_alloc_blocks_in_free_list(struct super_block *sb,
	struct free_list *free_list, unsigned short btype,
	unsigned long num_blocks,
	unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct pmfs_range_node *curr, *next = NULL, *prev = NULL;
	struct rb_node *temp, *next_node, *prev_node;
	unsigned long curr_blocks;
	bool found = 0;
	bool found_hugeblock = 0;
	unsigned long step = 0;

	if (!free_list->first_node || free_list->num_free_blocks == 0) {
		pmfs_dbg_verbose("%s: Can't alloc. free_list->first_node=0x%p "
			  "free_list->num_free_blocks = %lu",
			  __func__, free_list->first_node,
			  free_list->num_free_blocks);
		return -ENOSPC;
	}

	tree = &(free_list->block_free_tree);
	temp = &(free_list->first_node->node);

	/* Try huge block allocation for data blocks first */
	/*
	if (IS_DATABLOCKS_2MB_ALIGNED(num_blocks, atype)) {
		found_hugeblock = pmfs_alloc_superpage(sb, free_list,
					num_blocks, new_blocknr, from_tail);
		if (found_hugeblock)
			goto success;
	}
	*/

	/* fallback to un-aglined allocation then */
	while (temp) {
		step++;
		curr = container_of(temp, struct pmfs_range_node, node);

		curr_blocks = curr->range_high - curr->range_low + 1;

		if (num_blocks >= curr_blocks) {
			/* Superpage allocation must succeed */
			if (btype > 0 && num_blocks > curr_blocks)
				goto next;

			/* Otherwise, allocate the whole blocknode */
			if (curr == free_list->first_node) {
				next_node = rb_next(temp);
				if (next_node)
					next = container_of(next_node,
						struct pmfs_range_node, node);
				free_list->first_node = next;
			}

			if (curr == free_list->last_node) {
				prev_node = rb_prev(temp);
				if (prev_node)
					prev = container_of(prev_node,
						struct pmfs_range_node, node);
				free_list->last_node = prev;
			}

			rb_erase(&curr->node, tree);
			free_list->num_blocknode--;
			num_blocks = curr_blocks;
			*new_blocknr = curr->range_low;
			pmfs_free_blocknode(curr);
			found = 1;
			break;
		}

		/* Allocate partial blocknode */
		*new_blocknr = curr->range_low;
		curr->range_low += num_blocks;

		found = 1;
		break;
next:
		temp = rb_next(temp);
	}

	if (free_list->num_free_blocks < num_blocks) {
		pmfs_dbg("%s: free list %d has %lu free blocks, "
			 "but allocated %lu blocks?\n",
			 __func__, free_list->index,
			 free_list->num_free_blocks, num_blocks);
		return -ENOSPC;
	}

success:
	if ((found == 1) || (found_hugeblock == 1))
		free_list->num_free_blocks -= num_blocks;
	else {
		pmfs_dbg_verbose("%s: Can't alloc.  found = %d", __func__, found);
		return -ENOSPC;
	}

	return num_blocks;
}

/* Used for both block free tree and inode inuse tree */
int pmfs_find_free_slot(struct rb_root *tree, unsigned long range_low,
	unsigned long range_high, struct pmfs_range_node **prev,
	struct pmfs_range_node **next)
{
	struct pmfs_range_node *ret_node = NULL;
	struct rb_node *tmp;
	int check_prev = 0, check_next = 0;
	int ret;

	ret = pmfs_find_range_node(tree, range_low, NODE_BLOCK, &ret_node);
	if (ret) {
		pmfs_dbg("%s ERROR: %lu - %lu already in free list\n",
			__func__, range_low, range_high);
		return -EINVAL;
	}

	if (!ret_node) {
		*prev = *next = NULL;
	} else if (ret_node->range_high < range_low) {
		*prev = ret_node;
		tmp = rb_next(&ret_node->node);
		if (tmp) {
			*next = container_of(tmp, struct pmfs_range_node, node);
			check_next = 1;
		} else {
			*next = NULL;
		}
	} else if (ret_node->range_low > range_high) {
		*next = ret_node;
		tmp = rb_prev(&ret_node->node);
		if (tmp) {
			*prev = container_of(tmp, struct pmfs_range_node, node);
			check_prev = 1;
		} else {
			*prev = NULL;
		}
	} else {
		pmfs_dbg("%s ERROR: %lu - %lu overlaps with existing "
			 "node %lu - %lu\n",
			 __func__, range_low, range_high, ret_node->range_low,
			ret_node->range_high);
		return -EINVAL;
	}

	return 0;
}

int pmfs_free_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct rb_root *tree;
	unsigned long block_low;
	unsigned long block_high;
	unsigned long num_blocks = 0;
	struct pmfs_range_node *prev = NULL;
	struct pmfs_range_node *next = NULL;
	struct pmfs_range_node *curr_node;
	struct free_list *free_list;
	int cpuid;
	int new_node_used = 0;
	int ret;

	if (num <= 0) {
		pmfs_dbg("%s ERROR: free %d\n", __func__, num);
		return -EINVAL;
	}

	cpuid = blocknr / sbi->per_list_blocks;

	/* Pre-allocate blocknode */
	curr_node = pmfs_alloc_blocknode(sb);
	if (curr_node == NULL) {
		/* returning without freeing the block*/
		return -ENOMEM;
	}

	free_list = pmfs_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	tree = &(free_list->block_free_tree);

	num_blocks = pmfs_get_numblocks(btype) * num;
	block_low = blocknr;
	block_high = blocknr + num_blocks - 1;

	pmfs_dbg_verbose("Free: %lu - %lu\n", block_low, block_high);

	if (blocknr < free_list->block_start ||
			blocknr + num > free_list->block_end + 1) {
		pmfs_err(sb, "free blocks %lu to %lu, free list %d, "
			 "start %lu, end %lu\n",
			 blocknr, blocknr + num - 1,
			 free_list->index,
			 free_list->block_start,
			 free_list->block_end);
		ret = -EIO;
		goto out;
	}

	ret = pmfs_find_free_slot(tree, block_low,
				  block_high, &prev, &next);

	if (ret) {
		pmfs_dbg("%s: find free slot fail: %d\n", __func__, ret);
		goto out;
	}

	if (prev && next && (block_low == prev->range_high + 1) &&
			(block_high + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		free_list->num_blocknode--;
		prev->range_high = next->range_high;
		if (free_list->last_node == next)
			free_list->last_node = prev;
		pmfs_free_blocknode(next);
		goto block_found;
	}
	if (prev && (block_low == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high += num_blocks;
		goto block_found;
	}
	if (next && (block_high + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low -= num_blocks;
		goto block_found;
	}

	/* Aligns somewhere in the middle */
	curr_node->range_low = block_low;
	curr_node->range_high = block_high;
	new_node_used = 1;
	ret = pmfs_insert_blocktree(tree, curr_node);
	if (ret) {
		new_node_used = 0;
		goto out;
	}
	if (!prev)
		free_list->first_node = curr_node;
	if (!next)
		free_list->last_node = curr_node;

	free_list->num_blocknode++;

block_found:
	free_list->num_free_blocks += num_blocks;
out:
	spin_unlock(&free_list->s_lock);
	if (new_node_used == 0)
		pmfs_free_blocknode(curr_node);

	return ret;
}

static int not_enough_blocks(struct free_list *free_list,
	unsigned long num_blocks)
{
	struct pmfs_range_node *first = free_list->first_node;
	struct pmfs_range_node *last = free_list->last_node;

	if (free_list->num_free_blocks < num_blocks || !first || !last) {
		pmfs_dbg_verbose("%s: num_free_blocks=%ld; num_blocks=%ld; "
			  "first=0x%p; last=0x%p",
			  __func__, free_list->num_free_blocks, num_blocks,
			  first, last);
		return 1;
	}

	return 0;
}

/* Find out the free list with most free blocks */
static int pmfs_get_candidate_free_list(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct free_list *free_list;
	int cpuid = 0;
	int num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		if (free_list->num_free_blocks > num_free_blocks) {
			cpuid = i;
			num_free_blocks = free_list->num_free_blocks;
		}
	}

	return cpuid;
}

int pmfs_new_blocks(struct super_block *sb, unsigned long *blocknr,
		    unsigned int num, unsigned short btype, int zero, int cpuid)
{
	struct free_list *free_list;
	void *bp;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int retried = 0;
	timing_t alloc_time;

	num_blocks = num * pmfs_get_numblocks(btype);
	if (num_blocks == 0) {
		pmfs_dbg_verbose("%s: num_blocks == 0", __func__);
		return -EINVAL;
	}

	if (cpuid == ANY_CPU)
		cpuid = pmfs_get_cpuid(sb);

retry:
	free_list = pmfs_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	if (not_enough_blocks(free_list, num_blocks)) {
		pmfs_dbg_verbose("%s: cpu %d, free_blocks %lu, required %lu, "
			  "blocknode %lu\n",
			  __func__, cpuid, free_list->num_free_blocks,
			  num_blocks, free_list->num_blocknode);

		if (retried >= 2)
			/* Allocate anyway */
			goto alloc;

		spin_unlock(&free_list->s_lock);
		cpuid = pmfs_get_candidate_free_list(sb);
		retried++;
		goto retry;
	}
alloc:
	ret_blocks = pmfs_alloc_blocks_in_free_list(sb, free_list, btype,
					num_blocks, &new_blocknr);

	spin_unlock(&free_list->s_lock);

	if (ret_blocks <= 0 || new_blocknr == 0) {
		pmfs_dbg_verbose("%s: not able to allocate %d blocks. "
			  "ret_blocks=%ld; new_blocknr=%lu",
			  __func__, num, ret_blocks, new_blocknr);
		return -ENOSPC;
	}

	if (zero) {
		bp = pmfs_get_block(sb, pmfs_get_block_off(sb,
							   new_blocknr, btype));
		pmfs_memunlock_range(sb, bp, PAGE_SIZE * ret_blocks);
		memset_nt(bp, 0, PAGE_SIZE * ret_blocks);
		pmfs_memlock_range(sb, bp, PAGE_SIZE * ret_blocks);
	}
	*blocknr = new_blocknr;

	pmfs_dbg_verbose("Alloc %lu NVMM blocks 0x%lx\n", ret_blocks, *blocknr);
	return ret_blocks / pmfs_get_numblocks(btype);
}

unsigned long pmfs_count_free_blocks(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct free_list *free_list;
	unsigned long num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		num_free_blocks += free_list->num_free_blocks;
	}

	return num_free_blocks; 
}
