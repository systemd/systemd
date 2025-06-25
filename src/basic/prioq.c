/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Priority Queue
 * The prioq object implements a priority queue. That is, it orders objects by
 * their priority and allows O(1) access to the object with the highest
 * priority. Insertion and removal are Θ(log n). Optionally, the caller can
 * provide a pointer to an index which will be kept up-to-date by the prioq.
 *
 * The underlying algorithm used in this implementation is a Heap.
 */

#include "alloc-util.h"
#include "prioq.h"

struct prioq_item {
        void *data;
        unsigned *idx;
};

struct Prioq {
        compare_func_t compare_func;
        unsigned n_items;
        struct prioq_item *items;
};

Prioq* prioq_new(compare_func_t compare_func) {
        Prioq *q;

        q = new(Prioq, 1);
        if (!q)
                return q;

        *q = (Prioq) {
                .compare_func = compare_func,
        };

        return q;
}

Prioq* prioq_free(Prioq *q) {
        if (!q)
                return NULL;

        /* Invalidate the index fields of any remaining objects */
        FOREACH_ARRAY(item, q->items, q->n_items)
                if (item->idx)
                        *(item->idx) = PRIOQ_IDX_NULL;

        free(q->items);
        return mfree(q);
}

int prioq_ensure_allocated(Prioq **q, compare_func_t compare_func) {
        assert(q);

        if (*q) {
                assert((*q)->compare_func == compare_func);
                return 0;
        }

        *q = prioq_new(compare_func);
        if (!*q)
                return -ENOMEM;

        return 0;
}

static void swap(Prioq *q, unsigned j, unsigned k) {
        assert(q);
        assert(j < q->n_items);
        assert(k < q->n_items);

        assert(!q->items[j].idx || *(q->items[j].idx) == j);
        assert(!q->items[k].idx || *(q->items[k].idx) == k);

        SWAP_TWO(q->items[j].data, q->items[k].data);
        SWAP_TWO(q->items[j].idx, q->items[k].idx);

        if (q->items[j].idx)
                *q->items[j].idx = j;

        if (q->items[k].idx)
                *q->items[k].idx = k;
}

static unsigned shuffle_up(Prioq *q, unsigned idx) {
        assert(q);
        assert(idx < q->n_items);

        while (idx > 0) {
                unsigned k;

                k = (idx-1)/2;

                if (q->compare_func(q->items[k].data, q->items[idx].data) <= 0)
                        break;

                swap(q, idx, k);
                idx = k;
        }

        return idx;
}

static unsigned shuffle_down(Prioq *q, unsigned idx) {
        assert(q);

        for (;;) {
                unsigned j, k, s;

                k = (idx+1)*2; /* right child */
                j = k-1;       /* left child */

                if (j >= q->n_items)
                        break;

                if (q->compare_func(q->items[j].data, q->items[idx].data) < 0)

                        /* So our left child is smaller than we are, let's
                         * remember this fact */
                        s = j;
                else
                        s = idx;

                if (k < q->n_items &&
                    q->compare_func(q->items[k].data, q->items[s].data) < 0)

                        /* So our right child is smaller than we are, let's
                         * remember this fact */
                        s = k;

                /* s now points to the smallest of the three items */

                if (s == idx)
                        /* No swap necessary, we're done */
                        break;

                swap(q, idx, s);
                idx = s;
        }

        return idx;
}

int prioq_put(Prioq *q, void *data, unsigned *idx) {
        unsigned k;

        assert(q);

        if (!GREEDY_REALLOC(q->items, MAX(q->n_items + 1, 16u)))
                return -ENOMEM;

        k = q->n_items++;
        q->items[k] = (struct prioq_item) {
                .data = data,
                .idx = idx,
        };

        if (idx)
                *idx = k;

        shuffle_up(q, k);

        return 0;
}

int _prioq_ensure_put(Prioq **q, compare_func_t compare_func, void *data, unsigned *idx) {
        int r;

        r = prioq_ensure_allocated(q, compare_func);
        if (r < 0)
                return r;

        return prioq_put(*q, data, idx);
}

static void remove_item(Prioq *q, struct prioq_item *i) {
        struct prioq_item *l;

        assert(q);
        assert(i);

        /* Let's invalidate the index pointer stored in the user's object to indicate the item is now removed
         * from the priority queue */
        if (i->idx)
                *(i->idx) = PRIOQ_IDX_NULL;

        l = q->items + q->n_items - 1;

        if (i == l)
                /* Last entry, let's just remove it */
                q->n_items--;
        else {
                unsigned k;

                /* Not last entry, let's replace the last entry with
                 * this one, and reshuffle */

                assert(i >= q->items);
                k = i - q->items;

                i->data = l->data;
                i->idx = l->idx;
                if (i->idx)
                        *i->idx = k;
                q->n_items--;

                k = shuffle_down(q, k);
                shuffle_up(q, k);
        }
}

static struct prioq_item* find_item(Prioq *q, void *data, unsigned *idx) {
        struct prioq_item *i;

        assert(q);

        if (q->n_items <= 0)
                return NULL;

        if (idx) {
                if (*idx == PRIOQ_IDX_NULL ||
                    *idx >= q->n_items)
                        return NULL;

                i = q->items + *idx;
                if (i->data != data)
                        return NULL;

                return i;
        } else {
                for (i = q->items; i < q->items + q->n_items; i++)
                        if (i->data == data)
                                return i;
                return NULL;
        }
}

int prioq_remove(Prioq *q, void *data, unsigned *idx) {
        struct prioq_item *i;

        if (!q)
                return 0;

        i = find_item(q, data, idx);
        if (!i)
                return 0;

        remove_item(q, i);
        return 1;
}

void prioq_reshuffle(Prioq *q, void *data, unsigned *idx) {
        struct prioq_item *i;
        unsigned k;

        assert(q);

        i = find_item(q, data, idx);
        if (!i)
                return;

        assert(i >= q->items);
        k = i - q->items;
        k = shuffle_down(q, k);
        shuffle_up(q, k);
}

void* prioq_peek_by_index(Prioq *q, unsigned idx) {
        if (!q)
                return NULL;

        if (idx >= q->n_items)
                return NULL;

        return q->items[idx].data;
}

void* prioq_pop(Prioq *q) {
        void *data;

        if (!q)
                return NULL;

        if (q->n_items <= 0)
                return NULL;

        data = q->items[0].data;
        remove_item(q, q->items);
        return data;
}

unsigned prioq_size(Prioq *q) {

        if (!q)
                return 0;

        return q->n_items;
}

bool prioq_isempty(Prioq *q) {

        if (!q)
                return true;

        return q->n_items <= 0;
}
