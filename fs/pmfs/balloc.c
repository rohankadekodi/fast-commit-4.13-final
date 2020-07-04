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

	sbi->per_list_blocks = sbi->num_blocks / sbi->cpus;
	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		pmfs_init_free_list(sb, free_list, i);

		free_list->num_free_blocks = free_list->block_end -
			free_list->block_start + 1;
		blknode = pmfs_alloc_blocknode(sb);
		if (blocknode == NULL)
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
			ret = -1;
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

static struct pmfs_blocknode *pmfs_next_blocknode(struct pmfs_blocknode *i,
						  struct list_head *head)
{
	if (list_is_last(&i->link, head))
		return NULL;
	return list_first_entry(&i->link, typeof(*i), link);
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
	if (IS_DATABLOCKS_2MB_ALIGNED(num_blocks, atype)) {
		found_hugeblock = pmfs_alloc_superpage(sb, free_list,
					num_blocks, new_blocknr, from_tail);
		if (found_hugeblock)
			goto success;
	}

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

/* Caller must hold the super_block lock.  If start_hint is provided, it is
 * only valid until the caller releases the super_block lock. */
void __pmfs_free_block(struct super_block *sb, unsigned long blocknr,
		      unsigned short btype, struct pmfs_blocknode **start_hint)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	unsigned long new_block_low;
	unsigned long new_block_high;
	unsigned long num_blocks = 0;
	struct pmfs_blocknode *i;
	struct pmfs_blocknode *free_blocknode= NULL;
	struct pmfs_blocknode *curr_node;

	num_blocks = pmfs_get_numblocks(btype);
	new_block_low = blocknr;
	new_block_high = blocknr + num_blocks - 1;

	BUG_ON(list_empty(head));

	if (start_hint && *start_hint &&
	    new_block_low >= (*start_hint)->block_low)
		i = *start_hint;
	else
		i = list_first_entry(head, typeof(*i), link);

	list_for_each_entry_from(i, head, link) {

		if (new_block_low > i->block_high) {
			/* skip to next blocknode */
			continue;
		}

		if ((new_block_low == i->block_low) &&
			(new_block_high == i->block_high)) {
			/* fits entire datablock */
			if (start_hint)
				*start_hint = pmfs_next_blocknode(i, head);
			list_del(&i->link);
			free_blocknode = i;
			sbi->num_blocknode_allocated--;
			sbi->num_free_blocks += num_blocks;
			goto block_found;
		}
		if ((new_block_low == i->block_low) &&
			(new_block_high < i->block_high)) {
			/* Aligns left */
			i->block_low = new_block_high + 1;
			sbi->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = i;
			goto block_found;
		}
		if ((new_block_low > i->block_low) && 
			(new_block_high == i->block_high)) {
			/* Aligns right */
			i->block_high = new_block_low - 1;
			sbi->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = pmfs_next_blocknode(i, head);
			goto block_found;
		}
		if ((new_block_low > i->block_low) &&
			(new_block_high < i->block_high)) {
			/* Aligns somewhere in the middle */
			curr_node = pmfs_alloc_blocknode(sb);
			PMFS_ASSERT(curr_node);
			if (curr_node == NULL) {
				/* returning without freeing the block*/
				goto block_found;
			}
			curr_node->block_low = new_block_high + 1;
			curr_node->block_high = i->block_high;
			i->block_high = new_block_low - 1;
			list_add(&curr_node->link, &i->link);
			sbi->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = curr_node;
			goto block_found;
		}
	}

	pmfs_error_mng(sb, "Unable to free block %ld\n", blocknr);

block_found:

	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);
}

void pmfs_free_block(struct super_block *sb, unsigned long blocknr,
		      unsigned short btype)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	mutex_lock(&sbi->s_lock);
	__pmfs_free_block(sb, blocknr, btype, NULL);
	mutex_unlock(&sbi->s_lock);
}

static int not_enough_blocks(struct free_list *free_list,
	unsigned long num_blocks, enum alloc_type atype)
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
		    unsigned int num, unsigned short btype, int zero, int cpu)
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

	if (not_enough_blocks(free_list, num_blocks, atype)) {
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
					num_blocks, &new_blocknr, from_tail);

	if (ret_blocks > 0) {
		free_list->alloc_data_count++;
		free_list->alloc_data_pages += ret_blocks;
	}

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
	return sbi->num_free_blocks; 
}
