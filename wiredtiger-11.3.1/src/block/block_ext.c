/*-
 * Copyright (c) 2014-present MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

#include "wt_internal.h"

/*
 * WT_BLOCK_RET --
 *	Handle extension list errors that would normally panic the system but
 * which should fail gracefully when verifying.
 */
#define WT_BLOCK_RET(session, block, v, ...)                                        \
    do {                                                                            \
        int __ret = (v);                                                            \
        __wt_err(session, __ret, __VA_ARGS__);                                      \
        return ((block)->verify ?                                                   \
            __ret :                                                                 \
            __wt_panic(session, WT_PANIC, "block manager extension list failure")); \
    } while (0)

static int __block_append(WT_SESSION_IMPL *, WT_BLOCK *, WT_EXTLIST *, wt_off_t, wt_off_t);
static int __block_ext_overlap(
  WT_SESSION_IMPL *, WT_BLOCK *, WT_EXTLIST *, WT_EXT **, WT_EXTLIST *, WT_EXT **);
static int __block_extlist_dump(WT_SESSION_IMPL *, WT_BLOCK *, WT_EXTLIST *, const char *);
static int __block_merge(WT_SESSION_IMPL *, WT_BLOCK *, WT_EXTLIST *, wt_off_t, wt_off_t);

/*
 * __block_off_srch_last --
 *     Return the last element in the list, along with a stack for appending.
 *
 * Return a stack such that the caller can append a new entry to the skip list by inserting it after
 *     each element in the stack. For non-empty levels, this will be the last element at that level
 *     of the skip list. For a level with no entries, this will be the corresponding entry in the
 *     head stack.
 *
 * 该函数返回跳表的最后一个元素，并构建一个插入栈，用于在跳表末尾追加新元素。
 * 对于每一层，如果该层有元素，栈中保存该层最后一个元素的next指针地址；
 * 如果该层为空，栈中保存头节点中该层的指针地址。
 */
static WT_INLINE WT_EXT *
__block_off_srch_last(WT_EXT **head, WT_EXT ***stack)
{
    WT_EXT **extp, *last;
    int i;

    last = NULL; /* The list may be empty */

    /*
     * Start at the highest skip level, then go as far as possible at each level before stepping
     * down to the next.
     */
    // 从最高层开始遍历，每层都走到尽头，然后下降到下一层
    for (i = WT_SKIP_MAXDEPTH - 1, extp = &head[i]; i >= 0;)
        if (*extp != NULL) {
            // 当前层有元素，继续向后遍历
            last = *extp;
            extp = &(*extp)->next[i];
        } else
            // 当前层已到末尾，保存插入点并下降到下一层
            stack[i--] = extp--;
    return (last);
}

/*
 * __block_off_srch --
 *     Search a by-offset skiplist (either the primary by-offset list, or the by-offset list
 *     referenced by a size entry), for the specified offset.
 *
 * 在按偏移量排序的跳表中查找指定偏移量，返回插入栈。
 * 支持两种跳表：主offset跳表和size桶中的offset跳表。
 * skip_off参数用于区分这两种情况，影响next指针的偏移计算。
 */
static WT_INLINE void
__block_off_srch(WT_EXT **head, wt_off_t off, WT_EXT ***stack, bool skip_off)
{
    WT_EXT **extp;
    int i;

    /*
     * Start at the highest skip level, then go as far as possible at each level before stepping
     * down to the next.
     *
     * Return a stack for an exact match or the next-largest item.
     *
     * The WT_EXT structure contains two skiplists, the primary one and the per-size bucket one: if
     * the skip_off flag is set, offset the skiplist array by the depth specified in this particular
     * structure.
     */
    // 从最高层开始查找
    for (i = WT_SKIP_MAXDEPTH - 1, extp = &head[i]; i >= 0;)
        if (*extp != NULL && (*extp)->off < off)
            // 当前元素偏移量小于目标，继续在当前层向后查找
            // skip_off为真时，需要偏移depth个位置访问size跳表的指针
            extp = &(*extp)->next[i + (skip_off ? (*extp)->depth : 0)];
        else
            // 当前元素偏移量大于等于目标，或该层已空，保存插入点并下降
            stack[i--] = extp--;
}

/*
 * __block_first_srch --
 *     Search the skiplist for the first available slot.
 *
 * 查找第一个满足大小要求的空闲块（first-fit策略）。
 * 线性遍历所有块，找到第一个大小足够的块，然后构建插入栈。
 */
static WT_INLINE bool
__block_first_srch(WT_EXT **head, wt_off_t size, WT_EXT ***stack)
{
    WT_EXT *ext;

    /*
     * Linear walk of the available chunks in offset order; take the first one that's large enough.
     */
    // 线性遍历，找到第一个大小足够的块
    WT_EXT_FOREACH (ext, head)
        if (ext->size >= size)
            break;
    if (ext == NULL)
        return (false);

    /* Build a stack for the offset we want. */
    // 为找到的块构建插入栈
    __block_off_srch(head, ext->off, stack, false);
    return (true);
}

/*
 * __block_size_srch --
 *     Search the by-size skiplist for the specified size.
 *
 * 在按大小排序的跳表中查找指定大小，返回插入栈。
 * 用于best-fit分配策略，快速定位合适大小的空闲块。
 */
static WT_INLINE void
__block_size_srch(WT_SIZE **head, wt_off_t size, WT_SIZE ***stack)
{
    WT_SIZE **szp;
    int i;

    /*
     * Start at the highest skip level, then go as far as possible at each level before stepping
     * down to the next.
     *
     * Return a stack for an exact match or the next-largest item.
     */
    // 从最高层开始查找
    for (i = WT_SKIP_MAXDEPTH - 1, szp = &head[i]; i >= 0;)
        if (*szp != NULL && (*szp)->size < size)
            // 当前元素大小小于目标，继续在当前层向后查找
            szp = &(*szp)->next[i];
        else
            // 当前元素大小大于等于目标，或该层已空，保存插入点并下降
            stack[i--] = szp--;
}

/*
 * __block_off_srch_pair --
 *     Search a by-offset skiplist for before/after records of the specified offset.
 *
 * 在按偏移量排序的跳表中查找指定偏移量的前后元素。
 * 用于合并和重叠检测，找到可能需要合并的相邻块。
 */
static WT_INLINE void
__block_off_srch_pair(WT_EXTLIST *el, wt_off_t off, WT_EXT **beforep, WT_EXT **afterp)
{
    WT_EXT **extp, **head;
    int i;

    *beforep = *afterp = NULL;

    head = el->off;

    /*
     * Start at the highest skip level, then go as far as possible at each level before stepping
     * down to the next.
     */
    // 从最高层开始遍历
    for (i = WT_SKIP_MAXDEPTH - 1, extp = &head[i]; i >= 0;) {
        if (*extp == NULL) {
            // 当前层为空，直接下降
            --i;
            --extp;
            continue;
        }

        if ((*extp)->off < off) { /* Keep going at this level */
            // 当前元素在目标之前，更新beforep并继续在当前层查找
            *beforep = *extp;
            extp = &(*extp)->next[i];
        } else { /* Drop down a level */
            // 当前元素在目标之后，更新afterp并下降到下一层
            *afterp = *extp;
            --i;
            --extp;
        }
    }
}

/*
 * __block_ext_insert --
 *     Insert an extent into an extent list.
 *
 * 将一个extent插入到extent列表中。
 * 如果启用了size跳表（track_size为真），需要同时维护两个跳表：
 * 1. 按offset排序的主跳表
 * 2. 按size排序的跳表，每个size节点下还有一个按offset排序的子跳表
 */
static int
__block_ext_insert(WT_SESSION_IMPL *session, WT_EXTLIST *el, WT_EXT *ext)
{
    WT_EXT **astack[WT_SKIP_MAXDEPTH];
    WT_SIZE **sstack[WT_SKIP_MAXDEPTH], *szp;
    u_int i;

    /*
     * If we are inserting a new size onto the size skiplist, we'll need a new WT_SIZE structure for
     * that skiplist.
     */
    if (el->track_size) {
        // 查找size跳表中的插入位置
        __block_size_srch(el->sz, ext->size, sstack);
        szp = *sstack[0];
        // 如果该size不存在，创建新的size节点
        if (szp == NULL || szp->size != ext->size) {
            WT_RET(__wti_block_size_alloc(session, &szp));
            szp->size = ext->size;
            szp->depth = ext->depth;
            // 将新size节点插入到size跳表
            for (i = 0; i < ext->depth; ++i) {
                szp->next[i] = *sstack[i];
                *sstack[i] = szp;
            }
        }

        /*
         * Insert the new WT_EXT structure into the size element's offset skiplist.
         */
        // 将extent插入到size节点的offset子跳表中
        __block_off_srch(szp->off, ext->off, astack, true);
        for (i = 0; i < ext->depth; ++i) {
            // 使用next数组的后半部分存储size跳表的指针
            ext->next[i + ext->depth] = *astack[i];
            *astack[i] = ext;
        }
    }
#ifdef HAVE_DIAGNOSTIC
    // 诊断模式下，如果不使用size跳表，将后半部分置空
    if (!el->track_size)
        for (i = 0; i < ext->depth; ++i)
            ext->next[i + ext->depth] = NULL;
#endif

    /* Insert the new WT_EXT structure into the offset skiplist. */
    // 将extent插入到主offset跳表中
    __block_off_srch(el->off, ext->off, astack, false);
    for (i = 0; i < ext->depth; ++i) {
        // 使用next数组的前半部分存储offset跳表的指针
        ext->next[i] = *astack[i];
        *astack[i] = ext;
    }

    // 更新统计信息
    ++el->entries;
    el->bytes += (uint64_t)ext->size;

    /* Update the cached end-of-list. */
    // 如果是最后一个元素，更新缓存
    if (ext->next[0] == NULL)
        el->last = ext;

    return (0);
}

/*
 * __block_off_insert --
 *     Insert a file range into an extent list.
 *     插入一个文件范围到extent列表中。
 *     这是一个便捷包装函数，负责分配extent结构并调用底层插入函数。
 */
static int
__block_off_insert(WT_SESSION_IMPL *session, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    WT_EXT *ext;

    // 分配一个新的extent结构
    WT_RET(__wti_block_ext_alloc(session, &ext));
    // 设置extent的偏移量和大小
    ext->off = off;
    ext->size = size;

    // 调用底层函数将extent插入到列表中
    return (__block_ext_insert(session, el, ext));
}

/*
 * __wt_block_off_srch_inclusive --
 *     Search a by-offset skiplist for the extent that contains the given offset, or if there is no
 *     such extent, then get the next extent.
 *     在offset跳表中查找包含指定偏移量的extent。
 *     如果偏移量落在某个extent范围内，返回该extent；
 *     否则返回偏移量之后的第一个extent。
 */
WT_EXT *
__wt_block_off_srch_inclusive(WT_EXTLIST *el, wt_off_t off)
{
    WT_EXT *after, *before;

    // 查找指定偏移量的前驱和后继extent
    __block_off_srch_pair(el, off, &before, &after);

    /* Check if the search key is in the before extent. Otherwise return the after extent. */
    // 检查偏移量是否在前驱extent的范围内
    if (before != NULL && before->off <= off && before->off + before->size > off)
        return (before);
    else
        return (after);
}

#if defined(HAVE_DIAGNOSTIC) || defined(HAVE_UNITTEST)
/*
 * __block_off_match --
 *     Return if any part of a specified range appears on a specified extent list.
 *     检查指定范围是否与extent列表中的任何extent有重叠。
 *     用于诊断模式下的数据一致性检查。
 */
static bool
__block_off_match(WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    WT_EXT *after, *before;

    // 空范围直接返回false
    if (WT_UNLIKELY(size == 0))
        return (false);

    /* Search for before and after entries for the offset. */
    // 查找指定偏移量的前驱和后继
    __block_off_srch_pair(el, off, &before, &after);

    /* If "before" or "after" overlaps, we have a winner. */
    // 检查前驱是否与指定范围重叠（前驱的结束位置超过了指定范围的起始位置）
    if (before != NULL && before->off + before->size > off)
        return (true);
    // 检查后继是否与指定范围重叠（指定范围的结束位置超过了后继的起始位置）
    if (after != NULL && off + size > after->off)
        return (true);
    return (false);
}

/*
 * __wti_block_misplaced --
 *     Complain if a block appears on the available or discard lists.
 *     检查一个块是否错误地出现在可用列表或丢弃列表中。
 *     这是一个诊断函数，用于检测块管理器的内部一致性问题。
 */
int
__wti_block_misplaced(WT_SESSION_IMPL *session, WT_BLOCK *block, const char *list, wt_off_t offset,
  uint32_t size, bool live, const char *func, int line)
{
    const char *name;

    name = NULL;

    /*
     * Don't check during the salvage read phase, we might be reading an already freed overflow
     * page.
     */
    // 在salvage读取阶段不检查，因为可能正在读取已释放的溢出页
    if (F_ISSET(session, WT_SESSION_QUIET_CORRUPT_FILE))
        return (0);

    /*
     * Verify a block the btree engine thinks it "owns" doesn't appear on the available or discard
     * lists (it might reasonably be on the alloc list, if it was allocated since the last
     * checkpoint). The engine "owns" a block if it's trying to read or free the block, and those
     * functions make this check.
     *
     * Any block being read or freed should not be "available".
     *
     * Any block being read or freed in the live system should not be on the discard list. (A
     * checkpoint handle might be reading a block which is on the live system's discard list; any
     * attempt to free a block from a checkpoint handle has already failed.)
     */
    // 加锁检查块是否在可用列表或丢弃列表中
    __wt_spin_lock(session, &block->live_lock);
    // 检查是否在可用列表中
    if (__block_off_match(&block->live.avail, offset, size))
        name = "available";
    // 对于活跃系统，还要检查是否在丢弃列表中
    else if (live && __block_off_match(&block->live.discard, offset, size))
        name = "discard";
    __wt_spin_unlock(session, &block->live_lock);
    
    // 如果发现块在不应该出现的列表中，触发panic
    if (name != NULL)
        return (__wt_panic(session, WT_PANIC,
          "%s failed: %" PRIuMAX "/%" PRIu32 " is on the %s list (%s, %d)", list, (uintmax_t)offset,
          size, name, func, line));
    return (0);
}
#endif

/*
 * __block_off_remove --
 *     Remove a record from an extent list.
 *     从extent列表中移除指定偏移量的记录。
 *     需要同时维护offset跳表和size跳表（如果启用）。
 */
static int
__block_off_remove(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, WT_EXT **extp)
{
    WT_EXT **astack[WT_SKIP_MAXDEPTH], *ext;
    WT_SIZE **sstack[WT_SKIP_MAXDEPTH], *szp;
    u_int i;

    /* Find and remove the record from the by-offset skiplist. */
    // 在offset跳表中查找要删除的extent
    __block_off_srch(el->off, off, astack, false);
    ext = *astack[0];
    // 如果没找到或偏移量不匹配，说明数据结构损坏
    if (ext == NULL || ext->off != off)
        goto corrupt;
    // 从offset跳表的各层中移除该extent
    for (i = 0; i < ext->depth; ++i)
        *astack[i] = ext->next[i];

    /*
     * Find and remove the record from the size's offset skiplist; if that empties the by-size
     * skiplist entry, remove it as well.
     */
    // 如果启用了size跳表，也需要从size跳表中移除
    if (el->track_size) {
        // 在size跳表中查找对应的size节点
        __block_size_srch(el->sz, ext->size, sstack);
        szp = *sstack[0];
        if (szp == NULL || szp->size != ext->size)
            WT_RET_PANIC(session, EINVAL, "extent not found in by-size list during remove");
        // 在size节点的offset子跳表中查找要删除的extent
        __block_off_srch(szp->off, off, astack, true);
        ext = *astack[0];
        if (ext == NULL || ext->off != off)
            goto corrupt;
        // 从size节点的offset子跳表中移除该extent
        for (i = 0; i < ext->depth; ++i)
            *astack[i] = ext->next[i + ext->depth];
        // 如果size节点的offset子跳表为空，移除整个size节点
        if (szp->off[0] == NULL) {
            for (i = 0; i < szp->depth; ++i)
                *sstack[i] = szp->next[i];
            __wti_block_size_free(session, &szp);
        }
    }
#ifdef HAVE_DIAGNOSTIC
    // 诊断模式下，验证不使用size跳表时后半部分指针应为NULL
    if (!el->track_size) {
        bool not_null;
        for (i = 0, not_null = false; i < ext->depth; ++i)
            if (ext->next[i + ext->depth] != NULL)
                not_null = true;
        WT_ASSERT(session, not_null == false);
    }
#endif

    // 更新统计信息
    --el->entries;
    el->bytes -= (uint64_t)ext->size;

    /* Return the record if our caller wants it, otherwise free it. */
    // 如果调用者需要返回被删除的extent，则返回；否则释放它
    if (extp == NULL) {
        WT_EXT *ext_to_free = ext;
        __wti_block_ext_free(session, &ext_to_free);
    } else
        *extp = ext;

    /* Update the cached end-of-list. */
    // 如果删除的是最后一个元素，需要更新last缓存
    if (el->last == ext)
        /* To save time, update to the correct value later. */
        el->last = NULL;

    return (0);

corrupt:
    // 数据结构损坏，根据是否在验证模式决定返回错误还是panic
    WT_BLOCK_RET(
      session, block, EINVAL, "attempt to remove non-existent offset from an extent list");
}

/*
 * __wti_block_off_remove_overlap --
 *     Remove a range from an extent list, where the range may be part of an overlapping entry.
 *     从extent列表中移除一个范围，该范围可能只是某个extent的一部分。
 *     这个函数处理部分重叠的情况，会将剩余部分重新插入列表。
 */
int
__wti_block_off_remove_overlap(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    WT_EXT *after, *before, *ext;
    wt_off_t a_off, a_size, b_off, b_size;

    WT_ASSERT(session, off != WT_BLOCK_INVALID_OFFSET);

    /* Search for before and after entries for the offset. */
    // 查找指定偏移量的前驱和后继
    __block_off_srch_pair(el, off, &before, &after);

    /* If "before" or "after" overlaps, retrieve the overlapping entry. */
    // 处理前驱重叠的情况
    if (before != NULL && before->off + before->size > off) {
        // 移除重叠的extent
        WT_RET(__block_off_remove(session, block, el, before->off, &ext));

        // 确保被移除的extent完全包含要删除的范围
        WT_ASSERT(session, ext->off + ext->size >= off + size);

        /* Calculate overlapping extents. */
        // 计算剩余部分：前半部分（如果有）
        a_off = ext->off;
        a_size = off - ext->off;
        // 计算剩余部分：后半部分（如果有）
        b_off = off + size;
        b_size = ext->size - (a_size + size);

        // 记录调试信息
        if (a_size > 0) {
            __wt_verbose_debug2(session, WT_VERB_BLOCK,
              "%s: %" PRIdMAX "-%" PRIdMAX " range shrinks to %" PRIdMAX "-%" PRIdMAX, el->name,
              (intmax_t)before->off, (intmax_t)before->off + (intmax_t)before->size,
              (intmax_t)(a_off), (intmax_t)(a_off + a_size));
        }

        if (b_size > 0) {
            __wt_verbose_debug2(session, WT_VERB_BLOCK,
              "%s: %" PRIdMAX "-%" PRIdMAX " range shrinks to %" PRIdMAX "-%" PRIdMAX, el->name,
              (intmax_t)before->off, (intmax_t)before->off + (intmax_t)before->size,
              (intmax_t)(b_off), (intmax_t)(b_off + b_size));
        }
    } else if (after != NULL && off + size > after->off) {
        // 处理后继重叠的情况
        WT_RET(__block_off_remove(session, block, el, after->off, &ext));

        // 确保重叠部分的合法性
        WT_ASSERT(session, off == ext->off && off + size <= ext->off + ext->size);

        /*
         * Calculate overlapping extents. There's no initial overlap since the after extent
         * presumably cannot begin before "off".
         */
        // 只有后半部分剩余
        a_off = WT_BLOCK_INVALID_OFFSET;
        a_size = 0;
        b_off = off + size;
        b_size = ext->size - (b_off - ext->off);

        // 记录调试信息
        if (b_size > 0)
            __wt_verbose_debug2(session, WT_VERB_BLOCK,
              "%s: %" PRIdMAX "-%" PRIdMAX " range shrinks to %" PRIdMAX "-%" PRIdMAX, el->name,
              (intmax_t)after->off, (intmax_t)after->off + (intmax_t)after->size, (intmax_t)(b_off),
              (intmax_t)(b_off + b_size));

    } else
        // 没有重叠，返回未找到
        return (WT_NOTFOUND);

    /*
     * If there are overlaps, insert the item; re-use the extent structure and save the allocation
     * (we know there's no need to merge).
     */
    // 将剩余的前半部分重新插入列表
    if (a_size > 0) {
        ext->off = a_off;
        ext->size = a_size;
        WT_RET(__block_ext_insert(session, el, ext));
        ext = NULL;
    }
    // 将剩余的后半部分重新插入列表
    if (b_size > 0) {
        if (ext == NULL)
            // 需要分配新的extent结构
            WT_RET(__block_off_insert(session, el, b_off, b_size));
        else {
            // 复用已有的extent结构
            ext->off = b_off;
            ext->size = b_size;
            WT_RET(__block_ext_insert(session, el, ext));
            ext = NULL;
        }
    }
    // 如果extent结构没有被复用，释放它
    if (ext != NULL)
        __wti_block_ext_free(session, &ext);
    return (0);
}

/*
 * __block_extend --
 *     Extend the file to allocate space.
 *     扩展文件以分配新的空间，当现有空闲块不足时调用。
 *     调用者需要已经获取必要的锁。
 */
static WT_INLINE int
__block_extend(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t *offp, wt_off_t size)
{
    /*
     * Callers of this function are expected to have already acquired any locks required to extend
     * the file.
     *
     * We should never be allocating from an empty file.
     */
    // 检查文件是否已初始化（至少包含文件描述信息）
    if (block->size < block->allocsize)
        WT_RET_MSG(session, EINVAL, "file has no description information");

    /*
     * Make sure we don't allocate past the maximum file size.  There's no
     * easy way to know the maximum wt_off_t on a system, limit growth to
     * 8B bits (we currently check an wt_off_t is 8B in verify_build.h). I
     * don't think we're likely to see anything bigger for awhile.
     */
    // 检查文件大小是否会超过系统限制（INT64_MAX）
    if (block->size > (wt_off_t)INT64_MAX - size)
        WT_RET_MSG(session, WT_ERROR, "block allocation failed, file cannot grow further");

    // 分配的偏移量是当前文件末尾
    *offp = block->size;
    // 更新文件大小
    block->size += size;

    // 更新统计信息和日志
    WT_STAT_DSRC_INCR(session, block_extension);
    __wt_verbose(session, WT_VERB_BLOCK, "%s: file extend %" PRIdMAX "-%" PRIdMAX, el->name,
      (intmax_t)*offp, (intmax_t)(*offp + size));

    return (0);
}

/*
 * __wti_block_alloc --
 *     Alloc a chunk of space from the underlying file.
 *     从底层文件分配一块空间。
 *     支持first-fit（优先低偏移量）和best-fit（优先最佳大小）两种策略。
 *     如果没有合适的空闲块，会扩展文件。
 */
int
__wti_block_alloc(WT_SESSION_IMPL *session, WT_BLOCK *block, wt_off_t *offp, wt_off_t size)
{
    WT_EXT **estack[WT_SKIP_MAXDEPTH], *ext;
    WT_EXTLIST *el;
    WT_SIZE **sstack[WT_SKIP_MAXDEPTH], *szp;

    /* The live lock must be locked. */
    // 必须持有活跃系统的锁
    WT_ASSERT_SPINLOCK_OWNED(session, &block->live_lock);

    /* If a sync is running, no other sessions can allocate blocks. */
    // 如果正在同步，其他会话不能分配块
    WT_ASSERT(session, WT_SESSION_BTREE_SYNC_SAFE(session, S2BT(session)));

    /* Assert we're maintaining the by-size skiplist. */
    // 确保维护了size跳表（avail列表需要）
    WT_ASSERT(session, block->live.avail.track_size != 0);

    // 更新统计信息
    WT_STAT_DSRC_INCR(session, block_alloc);
    // 检查请求的大小是否是分配单位的整数倍
    if (size % block->allocsize != 0)
        WT_RET_MSG(session, EINVAL,
          "cannot allocate a block size %" PRIdMAX
          " that is not a multiple of the allocation size %" PRIu32,
          (intmax_t)size, block->allocsize);

    /*
     * Allocation is either first-fit (lowest offset), or best-fit (best size). If it's first-fit,
     * walk the offset list linearly until we find an entry that will work.
     *
     * If it's best-fit by size, search the by-size skiplist for the size and take the first entry
     * on the by-size offset list. This means we prefer best-fit over lower offset, but within a
     * size we'll prefer an offset appearing earlier in the file.
     *
     * If we don't have anything big enough, extend the file.
     */
    // 如果可用空间总量不足，直接扩展文件
    if (block->live.avail.bytes < (uint64_t)size)
        goto append;
    
    // first-fit策略：线性搜索第一个足够大的块
    if (block->allocfirst) {
        if (!__block_first_srch(block->live.avail.off, size, estack))
            goto append;
        ext = *estack[0];
    } else {
        // best-fit策略：在size跳表中查找最合适的大小
        __block_size_srch(block->live.avail.sz, size, sstack);
        if ((szp = *sstack[0]) == NULL) {
append:
            // 没有合适的空闲块，扩展文件
            el = &block->live.alloc;
            WT_RET(__block_extend(session, block, el, offp, size));
            // 将新分配的空间加入alloc列表
            WT_RET(__block_append(session, block, el, *offp, (wt_off_t)size));
            return (0);
        }

        /* Take the first record. */
        // 取size桶中的第一个extent（偏移量最小的）
        ext = szp->off[0];
    }

    /* Remove the record, and set the returned offset. */
    // 从avail列表中移除找到的extent
    WT_RET(__block_off_remove(session, block, &block->live.avail, ext->off, &ext));
    // 返回分配的偏移量
    *offp = ext->off;

    /* If doing a partial allocation, adjust the record and put it back. */
    // 如果extent比请求的大，只分配需要的部分
    if (ext->size > size) {
        __wt_verbose(session, WT_VERB_BLOCK,
          "%s: allocate %" PRIdMAX " from range %" PRIdMAX "-%" PRIdMAX
          ", range shrinks to %" PRIdMAX "-%" PRIdMAX,
          block->live.avail.name, (intmax_t)size, (intmax_t)ext->off,
          (intmax_t)(ext->off + ext->size), (intmax_t)(ext->off + size),
          (intmax_t)(ext->off + size + ext->size - size));

        // 调整extent的偏移量和大小，表示剩余部分
        ext->off += size;
        ext->size -= size;
        // 将剩余部分重新插入avail列表
        WT_RET(__block_ext_insert(session, &block->live.avail, ext));
    } else {
        // extent正好匹配或被完全使用
        __wt_verbose(session, WT_VERB_BLOCK, "%s: allocate range %" PRIdMAX "-%" PRIdMAX,
          block->live.avail.name, (intmax_t)ext->off, (intmax_t)(ext->off + ext->size));

        // 释放extent结构
        __wti_block_ext_free(session, &ext);
    }

    /* Add the newly allocated extent to the list of allocations. */
    // 将新分配的extent加入alloc列表，可能会与相邻块合并
    WT_RET(__block_merge(session, block, &block->live.alloc, *offp, (wt_off_t)size));
    return (0);
}

/*
 * __wt_block_free --
 *     Free a cookie-referenced chunk of space to the underlying file.
 *     释放一个由地址cookie引用的空间块到底层文件。
 *     地址cookie包含了对象ID、偏移量、大小和校验和等信息。
 */
int
__wt_block_free(WT_SESSION_IMPL *session, WT_BLOCK *block, const uint8_t *addr, size_t addr_size)
{
    WT_DECL_RET;
    wt_off_t offset;
    uint32_t checksum, objectid, size;

    // 更新块释放统计信息
    WT_STAT_DSRC_INCR(session, block_free);

    /* Crack the cookie. */
    // 解析地址cookie，提取对象ID、偏移量、大小和校验和
    WT_RET(__wt_block_addr_unpack(
      session, block, addr, addr_size, &objectid, &offset, &size, &checksum));

    /*
     * Freeing blocks in a previous object isn't possible in the current architecture. We'd like to
     * know when a previous object is either completely rewritten (or more likely, empty enough that
     * rewriting remaining blocks is worth doing). Just knowing which blocks are no longer in use
     * isn't enough to remove them (because the internal pages have to be rewritten and we don't
     * know where they are); the simplest solution is probably to keep a count of freed bytes from
     * each object in the metadata, and when enough of the object is no longer in use, perform a
     * compaction like process to do any remaining cleanup.
     */
    // 当前架构不支持释放之前对象的块，直接返回
    // 未来可能需要实现对象级别的压缩功能
    if (objectid != block->objectid)
        return (0);

    // 记录块释放的详细信息
    __wt_verbose(session, WT_VERB_BLOCK, "block free %" PRIu32 ": %" PRIdMAX "/%" PRIdMAX, objectid,
      (intmax_t)offset, (intmax_t)size);

#ifdef HAVE_DIAGNOSTIC
    // 诊断模式下，检查要释放的块是否错误地出现在可用或丢弃列表中
    WT_RET(__wti_block_misplaced(
      session, block, "free", offset, size, true, __PRETTY_FUNCTION__, __LINE__));
#endif

    // 预分配extent结构，避免在持锁期间分配失败
    WT_RET(__wti_block_ext_prealloc(session, 5));
    // 获取锁并执行实际的释放操作
    __wt_spin_lock(session, &block->live_lock);
    WT_TRET(__wti_block_off_free(session, block, objectid, offset, (wt_off_t)size));

    __wt_spin_unlock(session, &block->live_lock);
    return (ret);
}

/*
 * __wti_block_off_free --
 *     Free a file range to the underlying file.
 *     释放文件中的一个范围。
 *     根据该范围是否在当前检查点中分配，决定将其加入可用列表还是丢弃列表。
 */
int
__wti_block_off_free(
  WT_SESSION_IMPL *session, WT_BLOCK *block, uint32_t objectid, wt_off_t offset, wt_off_t size)
{
    WT_DECL_RET;

    /* The live lock must be locked, except for when we are running salvage. */
    // 除了salvage操作外，必须持有live锁
    if (!F_ISSET(S2BT(session), WT_BTREE_SALVAGE))
        WT_ASSERT_SPINLOCK_OWNED(session, &block->live_lock);

    /* If a sync is running, no other sessions can free blocks. */
    // 如果正在同步，其他会话不能释放块
    WT_ASSERT(session, WT_SESSION_BTREE_SYNC_SAFE(session, S2BT(session)));

    /* We can't reuse free space in an object. */
    // 不能重用其他对象的空闲空间
    if (objectid != block->objectid)
        return (0);

    /*
     * Callers of this function are expected to have already acquired any locks required to
     * manipulate the extent lists.
     *
     * We can reuse this extent immediately if it was allocated during this checkpoint, merge it
     * into the avail list (which slows file growth in workloads including repeated overflow record
     * modification). If this extent is referenced in a previous checkpoint, merge into the discard
     * list.
     */
    // 尝试从alloc列表中移除该范围（表示在当前检查点中分配）
    if ((ret = __wti_block_off_remove_overlap(session, block, &block->live.alloc, offset, size)) ==
      0)
        // 成功移除，说明是当前检查点分配的，可以立即重用，加入avail列表
        ret = __block_merge(session, block, &block->live.avail, offset, size);
    else if (ret == WT_NOTFOUND)
        // 不在alloc列表中，说明是之前检查点的块，加入discard列表
        // 等待检查点完成后才能重用
        ret = __block_merge(session, block, &block->live.discard, offset, size);
    return (ret);
}

#ifdef HAVE_DIAGNOSTIC
/*
 * __wti_block_extlist_check --
 *     Return if the extent lists overlap.
 *     检查两个extent列表是否有重叠。
 *     用于诊断模式下验证数据结构的正确性。
 */
int
__wti_block_extlist_check(WT_SESSION_IMPL *session, WT_EXTLIST *al, WT_EXTLIST *bl)
{
    WT_EXT *a, *b;

    // 获取两个列表的第一个元素
    a = al->off[0];
    b = bl->off[0];

    /* Walk the lists in parallel, looking for overlaps. */
    // 并行遍历两个列表，查找重叠
    while (a != NULL && b != NULL) {
        /*
         * If there's no overlap, move the lower-offset entry to the next entry in its list.
         */
        // 如果a的范围在b之前，移动a指针
        if (a->off + a->size <= b->off) {
            a = a->next[0];
            continue;
        }
        // 如果b的范围在a之前，移动b指针
        if (b->off + b->size <= a->off) {
            b = b->next[0];
            continue;
        }
        // 发现重叠，触发panic
        WT_RET_PANIC(session, EINVAL, "checkpoint merge check: %s list overlaps the %s list",
          al->name, bl->name);
    }
    return (0);
}
#endif

/*
 * __wti_block_extlist_overlap --
 *     Review a checkpoint's alloc/discard extent lists, move overlaps into the live system's
 *     checkpoint-avail list.
 *     检查检查点的alloc和discard列表之间的重叠，将重叠部分移到ckpt_avail列表。
 *     这种重叠表示在检查点期间既分配又释放的空间，可以立即重用。
 */
int
__wti_block_extlist_overlap(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_BLOCK_CKPT *ci)
{
    WT_EXT *alloc, *discard;

    // 必须持有live锁
    WT_ASSERT_SPINLOCK_OWNED(session, &block->live_lock);

    // 获取两个列表的第一个元素
    alloc = ci->alloc.off[0];
    discard = ci->discard.off[0];

    /* Walk the lists in parallel, looking for overlaps. */
    // 并行遍历两个列表，查找重叠
    while (alloc != NULL && discard != NULL) {
        /*
         * If there's no overlap, move the lower-offset entry to the next entry in its list.
         */
        // 如果alloc的范围在discard之前，移动alloc指针
        if (alloc->off + alloc->size <= discard->off) {
            alloc = alloc->next[0];
            continue;
        }
        // 如果discard的范围在alloc之前，移动discard指针
        if (discard->off + discard->size <= alloc->off) {
            discard = discard->next[0];
            continue;
        }

        /* Reconcile the overlap. */
        // 发现重叠，处理重叠部分
        // 重叠部分表示在检查点期间既分配又释放的空间
        WT_RET(__block_ext_overlap(session, block, &ci->alloc, &alloc, &ci->discard, &discard));
    }
    return (0);
}

/*
 * __block_ext_overlap --
 *     Reconcile two overlapping ranges.
 *     处理两个重叠范围的协调，将重叠部分移到ckpt_avail列表。
 *     这个函数处理检查点期间既分配又释放的空间块。
 */
static int
__block_ext_overlap(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *ael, WT_EXT **ap,
  WT_EXTLIST *bel, WT_EXT **bp)
{
    WT_EXT *a, *b, **ext;
    WT_EXTLIST *avail, *el;
    wt_off_t off, size;

    WT_ASSERT_SPINLOCK_OWNED(session, &block->live_lock);

    // 获取检查点可用列表，重叠部分将被加入这个列表
    avail = &block->live.ckpt_avail;

    /*
     * The ranges overlap, choose the range we're going to take from each.
     *
     * We can think of the overlap possibilities as 11 different cases:
     *
     *		AAAAAAAAAAAAAAAAAA
     * #1	BBBBBBBBBBBBBBBBBB		ranges are the same
     * #2  BBBBBBBBBBBBB			overlaps the beginning
     * #3		BBBBBBBBBBBBBBBB	overlaps the end
     * #4	BBBBB				B is a prefix of A
     * #5		BBBBBB			B is middle of A
     * #6		BBBBBBBBBB		B is a suffix of A
     *
     * and:
     *
     *		BBBBBBBBBBBBBBBBBB
     * #7  AAAAAAAAAAAAA			same as #3
     * #8		AAAAAAAAAAAAAAAA	same as #2
     * #9	AAAAA				A is a prefix of B
     * #10		AAAAAA			A is middle of B
     * #11		AAAAAAAAAA		A is a suffix of B
     *
     *
     * By swapping the arguments so "A" is always the lower range, we can
     * eliminate cases #2, #8, #10 and #11, and only handle 7 cases:
     *
     *		AAAAAAAAAAAAAAAAAA
     * #1	BBBBBBBBBBBBBBBBBB		ranges are the same
     * #3		BBBBBBBBBBBBBBBB	overlaps the end
     * #4	BBBBB				B is a prefix of A
     * #5		BBBBBB			B is middle of A
     * #6		BBBBBBBBBB		B is a suffix of A
     *
     * and:
     *
     *		BBBBBBBBBBBBBBBBBB
     * #7  AAAAAAAAAAAAA			same as #3
     * #9	AAAAA				A is a prefix of B
     */
    a = *ap;
    b = *bp;
    // 确保A的偏移量总是小于等于B，简化后续处理逻辑
    if (a->off > b->off) { /* Swap */
        b = *ap;
        a = *bp;
        ext = ap;
        ap = bp;
        bp = ext;
        el = ael;
        ael = bel;
        bel = el;
    }

    if (a->off == b->off) {       /* Case #1, #4, #9 - A和B起始位置相同 */
        if (a->size == b->size) { /* Case #1 - 两个范围完全相同 */
            /*
             * Move caller's A and B to the next element
             * Add that A and B range to the avail list
             * Delete A and B
             */
            // 移动调用者的指针到下一个元素
            *ap = (*ap)->next[0];
            *bp = (*bp)->next[0];
            // 将整个范围加入ckpt_avail列表（既分配又释放）
            WT_RET(__block_merge(session, block, avail, b->off, b->size));
            // 从各自的列表中删除A和B
            WT_RET(__block_off_remove(session, block, ael, a->off, NULL));
            WT_RET(__block_off_remove(session, block, bel, b->off, NULL));
        } else if (a->size > b->size) { /* Case #4 - B是A的前缀 */
            /*
             * Remove A from its list
             * Increment/Decrement A's offset/size by the size of B
             * Insert A on its list
             */
            // 从列表中移除A
            WT_RET(__block_off_remove(session, block, ael, a->off, &a));
            // 调整A的偏移和大小，去掉B覆盖的部分
            a->off += b->size;
            a->size -= b->size;
            // 将调整后的A重新插入列表
            WT_RET(__block_ext_insert(session, ael, a));

            /*
             * Move caller's B to the next element
             * Add B's range to the avail list
             * Delete B
             */
            // 移动B的指针到下一个元素
            *bp = (*bp)->next[0];
            // 将B的范围加入ckpt_avail列表
            WT_RET(__block_merge(session, block, avail, b->off, b->size));
            // 从列表中删除B
            WT_RET(__block_off_remove(session, block, bel, b->off, NULL));
        } else { /* Case #9 - A是B的前缀 */
            /*
             * Remove B from its list
             * Increment/Decrement B's offset/size by the size of A
             * Insert B on its list
             */
            // 从列表中移除B
            WT_RET(__block_off_remove(session, block, bel, b->off, &b));
            // 调整B的偏移和大小，去掉A覆盖的部分
            b->off += a->size;
            b->size -= a->size;
            // 将调整后的B重新插入列表
            WT_RET(__block_ext_insert(session, bel, b));

            /*
             * Move caller's A to the next element
             * Add A's range to the avail list
             * Delete A
             */
            // 移动A的指针到下一个元素
            *ap = (*ap)->next[0];
            // 将A的范围加入ckpt_avail列表
            WT_RET(__block_merge(session, block, avail, a->off, a->size));
            // 从列表中删除A
            WT_RET(__block_off_remove(session, block, ael, a->off, NULL));
        }
    } else if (a->off + a->size == b->off + b->size) { /* Case #6 - B是A的后缀 */
        /*
         * Remove A from its list
         * Decrement A's size by the size of B
         * Insert A on its list
         */
        // 从列表中移除A
        WT_RET(__block_off_remove(session, block, ael, a->off, &a));
        // 减少A的大小，去掉B覆盖的部分
        a->size -= b->size;
        // 将调整后的A重新插入列表
        WT_RET(__block_ext_insert(session, ael, a));

        /*
         * Move caller's B to the next element
         * Add B's range to the avail list
         * Delete B
         */
        // 移动B的指针到下一个元素
        *bp = (*bp)->next[0];
        // 将B的范围加入ckpt_avail列表
        WT_RET(__block_merge(session, block, avail, b->off, b->size));
        // 从列表中删除B
        WT_RET(__block_off_remove(session, block, bel, b->off, NULL));
    } else if /* Case #3, #7 - A和B部分重叠，重叠部分在尾部 */
      (a->off + a->size < b->off + b->size) {
        /*
         * Add overlap to the avail list
         */
        // 计算重叠部分的偏移和大小
        off = b->off;
        size = (a->off + a->size) - b->off;
        // 将重叠部分加入ckpt_avail列表
        WT_RET(__block_merge(session, block, avail, off, size));

        /*
         * Remove A from its list
         * Decrement A's size by the overlap
         * Insert A on its list
         */
        // 从列表中移除A
        WT_RET(__block_off_remove(session, block, ael, a->off, &a));
        // 减少A的大小，去掉重叠部分
        a->size -= size;
        // 将调整后的A重新插入列表
        WT_RET(__block_ext_insert(session, ael, a));

        /*
         * Remove B from its list
         * Increment/Decrement B's offset/size by the overlap
         * Insert B on its list
         */
        // 从列表中移除B
        WT_RET(__block_off_remove(session, block, bel, b->off, &b));
        // 调整B的偏移和大小，去掉重叠部分
        b->off += size;
        b->size -= size;
        // 将调整后的B重新插入列表
        WT_RET(__block_ext_insert(session, bel, b));
    } else { /* Case #5 - B在A的中间 */
        /* Calculate the offset/size of the trailing part of A. */
        // 计算A的尾部部分（B之后的部分）
        off = b->off + b->size;
        size = (a->off + a->size) - off;

        /*
         * Remove A from its list
         * Decrement A's size by trailing part of A plus B's size
         * Insert A on its list
         */
        // 从列表中移除A
        WT_RET(__block_off_remove(session, block, ael, a->off, &a));
        // 将A的大小调整为B之前的部分
        a->size = b->off - a->off;
        // 将调整后的A重新插入列表
        WT_RET(__block_ext_insert(session, ael, a));

        /* Add trailing part of A to A's list as a new element. */
        // 将A的尾部部分作为新元素加入A的列表
        WT_RET(__block_merge(session, block, ael, off, size));

        /*
         * Move caller's B to the next element
         * Add B's range to the avail list
         * Delete B
         */
        // 移动B的指针到下一个元素
        *bp = (*bp)->next[0];
        // 将B的范围加入ckpt_avail列表
        WT_RET(__block_merge(session, block, avail, b->off, b->size));
        // 从列表中删除B
        WT_RET(__block_off_remove(session, block, bel, b->off, NULL));
    }

    return (0);
}

/*
 * __wti_block_extlist_merge --
 *     Merge one extent list into another.
 *     将一个extent列表合并到另一个extent列表中。
 *     支持优化：如果源列表比目标列表大，交换两者以减少合并工作量。
 */
int
__wti_block_extlist_merge(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *a, WT_EXTLIST *b)
{
    WT_EXT *ext;
    WT_EXTLIST tmp;
    u_int i;

    /*
     * We should hold the live lock here when running on the live checkpoint. But there is no easy
     * way to determine if the checkpoint is live so we cannot assert the locking here.
     */

    __wt_verbose_debug2(session, WT_VERB_BLOCK, "merging %s into %s", a->name, b->name);

    /*
     * Sometimes the list we are merging is much bigger than the other: if so, swap the lists around
     * to reduce the amount of work we need to do during the merge. The size lists have to match as
     * well, so this is only possible if both lists are tracking sizes, or neither are.
     */
    // 优化：如果a的元素数量比b多，交换两个列表
    // 这样可以减少合并操作的次数（合并较小的列表到较大的列表）
    if (a->track_size == b->track_size && a->entries > b->entries) {
        // 保存a的内容到临时变量
        tmp = *a;
        // 交换统计信息
        a->bytes = b->bytes;
        b->bytes = tmp.bytes;
        a->entries = b->entries;
        b->entries = tmp.entries;
        // 交换跳表头指针
        for (i = 0; i < WT_SKIP_MAXDEPTH; i++) {
            a->off[i] = b->off[i];
            b->off[i] = tmp.off[i];
            a->sz[i] = b->sz[i];
            b->sz[i] = tmp.sz[i];
        }
    }

    // 遍历a中的所有extent，将它们合并到b中
    WT_EXT_FOREACH (ext, a->off)
        WT_RET(__block_merge(session, block, b, ext->off, ext->size));

    return (0);
}

/*
 * __block_append --
 *     Append a new entry to the allocation list.
 *     向分配列表追加新条目，优化用于文件扩展场景。
 *     假设新的extent要么扩展列表最后一个元素，要么成为新的最后元素。
 */
static int
__block_append(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    WT_EXT **astack[WT_SKIP_MAXDEPTH], *last_ext;
    u_int i;

    WT_UNUSED(block);
    // 确保不跟踪size（即不是avail列表）
    WT_ASSERT(session, el->track_size == 0);

    /*
     * Identical to __block_merge, when we know the file is being extended, that is, the information
     * is either going to be used to extend the last object on the list, or become a new object
     * ending the list.
     *
     * The terminating element of the list is cached, check it; otherwise, get a stack for the last
     * object in the skiplist, check for a simple extension, and otherwise append a new structure.
     */
    // 优化路径：检查缓存的最后一个元素
    if ((last_ext = el->last) != NULL && last_ext->off + last_ext->size == off)
        /* Extend the last object on the list. off is adjacent to the end of the last extent.*/
        // 新范围与最后一个元素相邻，直接扩展其大小
        last_ext->size += size;
    else {
        /* Update last_ext and, in case appending an extent, determine where to append an extent. */
        // 缓存失效或不相邻，需要查找最后一个元素
        last_ext = __block_off_srch_last(el->off, astack);
        if (last_ext != NULL && last_ext->off + last_ext->size == off)
            /* Extend the last object on the list. off is adjacent to the end of the last extent.*/
            // 找到的最后元素与新范围相邻，扩展它
            last_ext->size += size;
        else {
            // 需要创建新的extent
            if (last_ext != NULL)
                /* Assert that this is appending an extent after the last extent. */
                // 验证确实是在末尾追加（新偏移量应该大于最后元素的结束位置）
                WT_ASSERT(session, last_ext->off + last_ext->size < off);
            // 分配新的extent结构
            WT_RET(__wti_block_ext_alloc(session, &last_ext));
            last_ext->off = off;
            last_ext->size = size;

            // 将新extent插入到跳表的各层
            for (i = 0; i < last_ext->depth; ++i)
                *astack[i] = last_ext;
            ++el->entries;
        }

        /* Update the cached end-of-list */
        // 更新缓存的最后元素指针
        el->last = last_ext;
    }
    // 更新总字节数
    el->bytes += (uint64_t)size;

    return (0);
}

/*
 * __wti_block_insert_ext --
 *     Insert an extent into an extent list, merging if possible.
 *     将extent插入到extent列表中，如果可能的话进行合并。
 *     这是对外接口，实际工作由__block_merge完成。
 */
int
__wti_block_insert_ext(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    /*
     * There are currently two copies of this function (this code is a one- liner that calls the
     * internal version of the function, which means the compiler should compress out the function
     * call). It's that way because the interface is still fluid, I'm not convinced there won't be a
     * need for a functional split between the internal and external versions in the future.
     *
     * Callers of this function are expected to have already acquired any locks required to
     * manipulate the extent list.
     */
    // 直接调用内部版本，编译器应该会内联优化
    return (__block_merge(session, block, el, off, size));
}

/*
 * __block_merge --
 *     Insert an extent into an extent list, merging if possible (internal version).
 *     将extent插入到extent列表的内部实现，支持与相邻extent合并。
 *     这是extent管理的核心函数，确保列表中的extent尽可能合并以减少碎片。
 */
static int
__block_merge(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    WT_EXT *after, *before, *ext;

    /*
     * Retrieve the records preceding/following the offset. If the records are contiguous with the
     * free'd offset, combine records.
     */
    // 查找新范围的前驱和后继
    __block_off_srch_pair(el, off, &before, &after);
    
    // 检查前驱是否存在且有效
    if (before != NULL) {
        // 检查是否与前驱重叠（错误情况）
        if (before->off + before->size > off)
            WT_BLOCK_RET(session, block, EINVAL,
              "%s: existing range %" PRIdMAX "-%" PRIdMAX " overlaps with merge range %" PRIdMAX
              "-%" PRIdMAX,
              el->name, (intmax_t)before->off, (intmax_t)(before->off + before->size),
              (intmax_t)off, (intmax_t)(off + size));
        // 如果不相邻，清空before
        if (before->off + before->size != off)
            before = NULL;
    }
    
    // 检查后继是否存在且有效
    if (after != NULL) {
        // 检查是否与后继重叠（错误情况）
        if (off + size > after->off) {
            WT_BLOCK_RET(session, block, EINVAL,
              "%s: merge range %" PRIdMAX "-%" PRIdMAX " overlaps with existing range %" PRIdMAX
              "-%" PRIdMAX,
              el->name, (intmax_t)off, (intmax_t)(off + size), (intmax_t)after->off,
              (intmax_t)(after->off + after->size));
        }
        // 如果不相邻，清空after
        if (off + size != after->off)
            after = NULL;
    }
    
    // 情况1：前后都不相邻，直接插入新extent
    if (before == NULL && after == NULL) {
        __wt_verbose_debug2(session, WT_VERB_BLOCK, "%s: insert range %" PRIdMAX "-%" PRIdMAX,
          el->name, (intmax_t)off, (intmax_t)(off + size));

        return (__block_off_insert(session, el, off, size));
    }

    /*
     * If the "before" offset range abuts, we'll use it as our new record; if the "after" offset
     * range also abuts, include its size and remove it from the system. Else, only the "after"
     * offset range abuts, use the "after" offset range as our new record. In either case, remove
     * the record we're going to use, adjust it and re-insert it.
     */
    // 情况2：只与后继相邻
    if (before == NULL) {
        // 移除后继
        WT_RET(__block_off_remove(session, block, el, after->off, &ext));

        __wt_verbose_debug2(session, WT_VERB_BLOCK,
          "%s: range grows from %" PRIdMAX "-%" PRIdMAX ", to %" PRIdMAX "-%" PRIdMAX, el->name,
          (intmax_t)ext->off, (intmax_t)(ext->off + ext->size), (intmax_t)off,
          (intmax_t)(off + ext->size + size));

        // 扩展后继的范围，包含新范围
        ext->off = off;
        ext->size += size;
    } else {
        // 情况3：与前驱相邻（可能也与后继相邻）
        if (after != NULL) {
            // 三个范围合并：前驱 + 新范围 + 后继
            size += after->size;
            WT_RET(__block_off_remove(session, block, el, after->off, NULL));
        }
        // 移除前驱
        WT_RET(__block_off_remove(session, block, el, before->off, &ext));

        __wt_verbose_debug2(session, WT_VERB_BLOCK,
          "%s: range grows from %" PRIdMAX "-%" PRIdMAX ", to %" PRIdMAX "-%" PRIdMAX, el->name,
          (intmax_t)ext->off, (intmax_t)(ext->off + ext->size), (intmax_t)ext->off,
          (intmax_t)(ext->off + ext->size + size));

        // 扩展前驱的大小
        ext->size += size;
    }
    // 将合并后的extent重新插入列表
    return (__block_ext_insert(session, el, ext));
}

/*
 * __wti_block_extlist_read_avail --
 *     Read an avail extent list, includes minor special handling.
 *     读取可用空间列表，包含特殊处理逻辑。
 *     特殊之处在于需要移除存储列表本身占用的空间。
 */
int
__wti_block_extlist_read_avail(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t ckpt_size)
{
    WT_DECL_RET;

    /* If there isn't a list, we're done. */
    // 如果列表不存在，直接返回
    if (el->offset == WT_BLOCK_INVALID_OFFSET)
        return (0);

#ifdef HAVE_DIAGNOSTIC
    /*
     * In diagnostic mode, reads are checked against the available and discard lists (a block being
     * read should never appear on either). Checkpoint threads may be running in the file, don't
     * race with them.
     */
    // 诊断模式下需要加锁，防止与检查点线程竞争
    __wt_spin_lock(session, &block->live_lock);
#endif

    // 读取extent列表
    WT_ERR(__wti_block_extlist_read(session, block, el, ckpt_size));

    /*
     * Extent blocks are allocated from the available list: if reading the avail list, the extent
     * blocks might be included, remove them.
     */
    // 从可用列表中移除存储列表本身占用的空间
    // 因为extent列表是从可用空间分配的，读取时需要排除自身
    WT_ERR_NOTFOUND_OK(
      __wti_block_off_remove_overlap(session, block, el, el->offset, el->size), false);

err:
#ifdef HAVE_DIAGNOSTIC
    __wt_spin_unlock(session, &block->live_lock);
#endif

    return (ret);
}

/*
 * __wti_block_extlist_read --
 *     Read an extent list.
 */
int
__wti_block_extlist_read(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t ckpt_size)
{
    WT_DECL_ITEM(tmp);
    WT_DECL_RET;
    wt_off_t off, size;
    const uint8_t *p;
    int (*func)(WT_SESSION_IMPL *, WT_BLOCK *, WT_EXTLIST *, wt_off_t, wt_off_t);

    off = size = 0;

    /* If there isn't a list, we're done. */
    if (el->offset == WT_BLOCK_INVALID_OFFSET)
        return (0);

    WT_RET(__wt_scr_alloc(session, el->size, &tmp));
    WT_ERR(
      __wti_block_read_off(session, block, tmp, el->objectid, el->offset, el->size, el->checksum));

    p = WT_BLOCK_HEADER_BYTE(tmp->mem);
    WT_ERR(__wt_extlist_read_pair(&p, &off, &size));
    if (off != WT_BLOCK_EXTLIST_MAGIC || size != 0)
        goto corrupted;

    /*
     * If we're not creating both offset and size skiplists, use the simpler append API, otherwise
     * do a full merge. There are two reasons for the test: first, checkpoint "available" lists are
     * NOT sorted (checkpoints write two separate lists, both of which are sorted but they're not
     * merged). Second, the "available" list is sorted by size as well as by offset, and the
     * fast-path append code doesn't support that, it's limited to offset. The test of "track size"
     * is short-hand for "are we reading the available-blocks list".
     */
    func = el->track_size == 0 ? __block_append : __block_merge;
    for (;;) {
        WT_ERR(__wt_extlist_read_pair(&p, &off, &size));
        if (off == WT_BLOCK_INVALID_OFFSET)
            break;

        /*
         * We check the offset/size pairs represent valid file ranges, then insert them into the
         * list. We don't necessarily have to check for offsets past the end of the checkpoint, but
         * it's a cheap test to do here and we'd have to do the check as part of file verification,
         * regardless.
         */
        if (off < block->allocsize || off % block->allocsize != 0 || size % block->allocsize != 0 ||
          off + size > ckpt_size) {
corrupted:
            __wt_scr_free(session, &tmp);
            WT_BLOCK_RET(session, block, WT_ERROR,
              "file contains a corrupted %s extent list, range %" PRIdMAX "-%" PRIdMAX
              " past end-of-file",
              el->name, (intmax_t)off, (intmax_t)(off + size));
        }

        WT_ERR(func(session, block, el, off, size));
    }

    WT_ERR(__block_extlist_dump(session, block, el, "read"));

err:
    __wt_scr_free(session, &tmp);
    return (ret);
}

/*
 * __wti_block_extlist_write --
 *     Write an extent list at the tail of the file.
 */
int
__wti_block_extlist_write(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, WT_EXTLIST *additional)
{
    WT_DECL_ITEM(tmp);
    WT_DECL_RET;
    WT_EXT *ext;
    WT_PAGE_HEADER *dsk;
    size_t size;
    uint32_t entries;
    uint8_t *p;

    WT_RET(__block_extlist_dump(session, block, el, "write"));

    /*
     * Figure out how many entries we're writing -- if there aren't any entries, there's nothing to
     * write, unless we still have to write the extent list to include the checkpoint recovery
     * information.
     */
    entries = el->entries + (additional == NULL ? 0 : additional->entries);
    if (entries == 0 && block->final_ckpt == NULL) {
        el->offset = WT_BLOCK_INVALID_OFFSET;
        el->checksum = el->size = 0;
        return (0);
    }

    /*
     * Get a scratch buffer, clear the page's header and data, initialize the header.
     *
     * Allocate memory for the extent list entries plus two additional entries: the initial
     * WT_BLOCK_EXTLIST_MAGIC/0 pair and the list- terminating WT_BLOCK_INVALID_OFFSET/0 pair.
     */
    size = ((size_t)entries + 2) * 2 * WT_INTPACK64_MAXSIZE;
    WT_RET(__wt_block_write_size(session, block, &size));
    WT_RET(__wt_scr_alloc(session, size, &tmp));
    dsk = tmp->mem;
    memset(dsk, 0, WT_BLOCK_HEADER_BYTE_SIZE);
    dsk->type = WT_PAGE_BLOCK_MANAGER;
    dsk->version = WT_PAGE_VERSION_TS;

    /* Fill the page's data. */
    p = WT_BLOCK_HEADER_BYTE(dsk);
    /* Extent list starts */
    WT_ERR(__wt_extlist_write_pair(&p, WT_BLOCK_EXTLIST_MAGIC, 0));
    WT_EXT_FOREACH (ext, el->off) /* Free ranges */
        WT_ERR(__wt_extlist_write_pair(&p, ext->off, ext->size));
    if (additional != NULL)
        WT_EXT_FOREACH (ext, additional->off) /* Free ranges */
            WT_ERR(__wt_extlist_write_pair(&p, ext->off, ext->size));
    /* Extent list stops */
    WT_ERR(__wt_extlist_write_pair(
      &p, WT_BLOCK_INVALID_OFFSET, block->final_ckpt == NULL ? 0 : WT_BLOCK_EXTLIST_VERSION_CKPT));

    dsk->u.datalen = WT_PTRDIFF32(p, WT_BLOCK_HEADER_BYTE(dsk));
    tmp->size = dsk->mem_size = WT_PTRDIFF32(p, dsk);

#ifdef HAVE_DIAGNOSTIC
    /*
     * The extent list is written as a valid btree page because the salvage functionality might move
     * into the btree layer some day, besides, we don't need another format and this way the page
     * format can be easily verified.
     */
    WT_ERR(__wt_verify_dsk(session, "[extent list check]", tmp));
#endif

    /* Write the extent list to disk. */
    WT_ERR(__wti_block_write_off(
      session, block, tmp, &el->offset, &el->size, &el->checksum, true, true, true));
    el->objectid = block->objectid;

    /*
     * Remove the allocated blocks from the system's allocation list, extent blocks never appear on
     * any allocation list.
     */
    WT_TRET(
      __wti_block_off_remove_overlap(session, block, &block->live.alloc, el->offset, el->size));

    __wt_verbose(session, WT_VERB_BLOCK, "%s written %" PRIdMAX "/%" PRIu32, el->name,
      (intmax_t)el->offset, el->size);

err:
    __wt_scr_free(session, &tmp);
    return (ret);
}

/*
 * __wti_block_extlist_truncate --
 *     Truncate the file based on the last available extent in the list.
 */
int
__wti_block_extlist_truncate(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el)
{
    WT_EXT **astack[WT_SKIP_MAXDEPTH], *ext;
    wt_off_t size;

    /*
     * Check if the last available extent is at the end of the file, and if so, truncate the file
     * and discard the extent.
     */
    if ((ext = __block_off_srch_last(el->off, astack)) == NULL)
        return (0);
    WT_ASSERT(session, ext->off + ext->size <= block->size);
    if (ext->off + ext->size < block->size)
        return (0);

    /*
     * Remove the extent list entry. (Save the value, we need it to reset the cached file size, and
     * that can't happen until after the extent list removal succeeds.)
     */
    size = ext->off;
    WT_RET(__block_off_remove(session, block, el, size, NULL));

    /* Truncate the file. */
    return (__wti_block_truncate(session, block, size));
}

/*
 * __wti_block_extlist_init --
 *     Initialize an extent list.
 */
int
__wti_block_extlist_init(
  WT_SESSION_IMPL *session, WT_EXTLIST *el, const char *name, const char *extname, bool track_size)
{
    size_t size;

    WT_CLEAR(*el);

    size =
      (name == NULL ? 0 : strlen(name)) + strlen(".") + (extname == NULL ? 0 : strlen(extname) + 1);
    WT_RET(__wt_calloc_def(session, size, &el->name));
    WT_RET(__wt_snprintf(
      el->name, size, "%s.%s", name == NULL ? "" : name, extname == NULL ? "" : extname));

    el->offset = WT_BLOCK_INVALID_OFFSET;
    el->track_size = track_size;
    return (0);
}

/*
 * __wti_block_extlist_free --
 *     Discard an extent list.
 */
void
__wti_block_extlist_free(WT_SESSION_IMPL *session, WT_EXTLIST *el)
{
    WT_EXT *ext, *next;
    WT_SIZE *nszp, *szp;

    __wt_free(session, el->name);

    for (ext = el->off[0]; ext != NULL; ext = next) {
        next = ext->next[0];
        __wt_free(session, ext);
    }
    for (szp = el->sz[0]; szp != NULL; szp = nszp) {
        nszp = szp->next[0];
        __wt_free(session, szp);
    }

    /* Extent lists are re-used, clear them. */
    WT_CLEAR(*el);
}

/*
 * __block_extlist_dump --
 *     Dump an extent list as verbose messages.
 */
static int
__block_extlist_dump(WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, const char *tag)
{
    WT_DECL_ITEM(t1);
    WT_DECL_ITEM(t2);
    WT_DECL_RET;
    WT_EXT *ext;
    WT_VERBOSE_LEVEL level;
    uint64_t pow, sizes[64];
    u_int i;
    const char *sep;

    if (!block->verify_layout &&
      !WT_VERBOSE_LEVEL_ISSET(session, WT_VERB_BLOCK, WT_VERBOSE_DEBUG_2))
        return (0);

    WT_ERR(__wt_scr_alloc(session, 0, &t1));
    if (block->verify_layout)
        level = WT_VERBOSE_NOTICE;
    else
        level = WT_VERBOSE_DEBUG_2;
    __wt_verbose_level(session, WT_VERB_BLOCK, level,
      "%s extent list %s, %" PRIu32 " entries, %s bytes", tag, el->name, el->entries,
      __wt_buf_set_size(session, el->bytes, true, t1));

    if (el->entries == 0)
        goto done;

    memset(sizes, 0, sizeof(sizes));
    WT_EXT_FOREACH (ext, el->off)
        for (i = 9, pow = 512;; ++i, pow *= 2)
            if (ext->size <= (wt_off_t)pow) {
                ++sizes[i];
                break;
            }
    sep = "extents by bucket:";
    t1->size = 0;
    WT_ERR(__wt_scr_alloc(session, 0, &t2));
    for (i = 9, pow = 512; i < WT_ELEMENTS(sizes); ++i, pow *= 2)
        if (sizes[i] != 0) {
            WT_ERR(__wt_buf_catfmt(session, t1, "%s {%s: %" PRIu64 "}", sep,
              __wt_buf_set_size(session, pow, false, t2), sizes[i]));
            sep = ",";
        }

    __wt_verbose_level(session, WT_VERB_BLOCK, level, "%s", (char *)t1->data);

done:
err:
    __wt_scr_free(session, &t1);
    __wt_scr_free(session, &t2);
    return (ret);
}

#ifdef HAVE_UNITTEST
WT_EXT *
__ut_block_off_srch_last(WT_EXT **head, WT_EXT ***stack)
{
    return (__block_off_srch_last(head, stack));
}

void
__ut_block_off_srch(WT_EXT **head, wt_off_t off, WT_EXT ***stack, bool skip_off)
{
    __block_off_srch(head, off, stack, skip_off);
}

bool
__ut_block_first_srch(WT_EXT **head, wt_off_t size, WT_EXT ***stack)
{
    return (__block_first_srch(head, size, stack));
}

void
__ut_block_size_srch(WT_SIZE **head, wt_off_t size, WT_SIZE ***stack)
{
    __block_size_srch(head, size, stack);
}

void
__ut_block_off_srch_pair(WT_EXTLIST *el, wt_off_t off, WT_EXT **beforep, WT_EXT **afterp)
{
    __block_off_srch_pair(el, off, beforep, afterp);
}

int
__ut_block_ext_insert(WT_SESSION_IMPL *session, WT_EXTLIST *el, WT_EXT *ext)
{
    return (__block_ext_insert(session, el, ext));
}

int
__ut_block_off_insert(WT_SESSION_IMPL *session, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    return (__block_off_insert(session, el, off, size));
}

bool
__ut_block_off_match(WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    return (__block_off_match(el, off, size));
}

int
__ut_block_off_remove(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, WT_EXT **extp)
{
    return (__block_off_remove(session, block, el, off, extp));
}

int
__ut_block_extend(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t *offp, wt_off_t size)
{
    return (__block_extend(session, block, el, offp, size));
}

int
__ut_block_append(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    return (__block_append(session, block, el, off, size));
}

int
__ut_block_merge(
  WT_SESSION_IMPL *session, WT_BLOCK *block, WT_EXTLIST *el, wt_off_t off, wt_off_t size)
{
    return (__block_merge(session, block, el, off, size));
}
#endif
