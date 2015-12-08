/***
  This file is part of systemd. See COPYING for details.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/*
 * Tests for RB-Tree
 */

#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include "c-rbtree.h"

/* verify that all API calls are exported */
static void test_api(void) {
        CRBTree t = {};
        CRBNode n = C_RBNODE_INIT(n);

        assert(!c_rbnode_is_linked(&n));

        /* init, is_linked, add, remove, remove_init */

        c_rbtree_add(&t, NULL, &t.root, &n);
        assert(c_rbnode_is_linked(&n));

        c_rbtree_remove_init(&t, &n);
        assert(!c_rbnode_is_linked(&n));

        c_rbtree_add(&t, NULL, &t.root, &n);
        assert(c_rbnode_is_linked(&n));

        c_rbtree_remove(&t, &n);
        assert(c_rbnode_is_linked(&n)); /* @n wasn't touched */

        c_rbnode_init(&n);
        assert(!c_rbnode_is_linked(&n));

        /* first, last, leftmost, rightmost, next, prev */

        assert(!c_rbtree_first(&t));
        assert(!c_rbtree_last(&t));
        assert(&n == c_rbnode_leftmost(&n));
        assert(&n == c_rbnode_rightmost(&n));
        assert(!c_rbnode_next(&n));
        assert(!c_rbnode_prev(&n));
}

/* copied from c-rbtree.c, relies on internal representation */
static inline _Bool c_rbnode_is_red(CRBNode *n) {
        return !((unsigned long)n->__parent_and_color & 1UL);
}

/* copied from c-rbtree.c, relies on internal representation */
static inline _Bool c_rbnode_is_black(CRBNode *n) {
        return !!((unsigned long)n->__parent_and_color & 1UL);
}

static size_t validate(CRBTree *t) {
        unsigned int i_black, n_black;
        CRBNode *n, *p, *o;
        size_t count = 0;

        assert(t);
        assert(!t->root || c_rbnode_is_black(t->root));

        /* traverse to left-most child, count black nodes */
        i_black = 0;
        n = t->root;
        while (n && n->left) {
                if (c_rbnode_is_black(n))
                        ++i_black;
                n = n->left;
        }
        n_black = i_black;

        /*
         * Traverse tree and verify correctness:
         *  1) A node is either red or black
         *  2) The root is black
         *  3) All leaves are black
         *  4) Every red node must have two black child nodes
         *  5) Every path to a leaf contains the same number of black nodes
         *
         * Note that NULL nodes are considered black, which is why we don't
         * check for 3).
         */
        o = NULL;
        while (n) {
                ++count;

                /* verify natural order */
                assert(n > o);
                o = n;

                /* verify consistency */
                assert(!n->right || c_rbnode_parent(n->right) == n);
                assert(!n->left || c_rbnode_parent(n->left) == n);

                /* verify 2) */
                if (!c_rbnode_parent(n))
                        assert(c_rbnode_is_black(n));

                if (c_rbnode_is_red(n)) {
                        /* verify 4) */
                        assert(!n->left || c_rbnode_is_black(n->left));
                        assert(!n->right || c_rbnode_is_black(n->right));
                } else {
                        /* verify 1) */
                        assert(c_rbnode_is_black(n));
                }

                /* verify 5) */
                if (!n->left && !n->right)
                        assert(i_black == n_black);

                /* get next node */
                if (n->right) {
                        n = n->right;
                        if (c_rbnode_is_black(n))
                                ++i_black;

                        while (n->left) {
                                n = n->left;
                                if (c_rbnode_is_black(n))
                                        ++i_black;
                        }
                } else {
                        while ((p = c_rbnode_parent(n)) && n == p->right) {
                                n = p;
                                if (c_rbnode_is_black(p->right))
                                        --i_black;
                        }

                        n = p;
                        if (p && c_rbnode_is_black(p->left))
                                --i_black;
                }
        }

        return count;
}

static void insert(CRBTree *t, CRBNode *n) {
        CRBNode **i, *p;

        assert(t);
        assert(n);
        assert(!c_rbnode_is_linked(n));

        i = &t->root;
        p = NULL;
        while (*i) {
                p = *i;
                if (n < *i) {
                        i = &(*i)->left;
                } else {
                        assert(n > *i);
                        i = &(*i)->right;
                }
        }

        c_rbtree_add(t, p, i, n);
}

static void shuffle(void **nodes, size_t n_memb) {
        unsigned int i, j;
        void *t;

        for (i = 0; i < n_memb; ++i) {
                j = rand() % n_memb;
                t = nodes[j];
                nodes[j] = nodes[i];
                nodes[i] = t;
        }
}

/* run some pseudo-random tests on the tree */
static void test_shuffle(void) {
        CRBNode *nodes[256];
        CRBTree t = {};
        unsigned int i, j;
        size_t n;

        /* allocate and initialize all nodes */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                nodes[i] = malloc(sizeof(*nodes[i]));
                assert(nodes[i]);
                c_rbnode_init(nodes[i]);
        }

        /* shuffle nodes and validate *empty* tree */
        shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));
        n = validate(&t);
        assert(n == 0);

        /* add all nodes and validate after each insertion */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                insert(&t, nodes[i]);
                n = validate(&t);
                assert(n == i + 1);
        }

        /* shuffle nodes again */
        shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all nodes (in different order) and validate on each round */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                c_rbtree_remove(&t, nodes[i]);
                n = validate(&t);
                assert(n == sizeof(nodes) / sizeof(*nodes) - i - 1);
                c_rbnode_init(nodes[i]);
        }

        /* shuffle nodes and validate *empty* tree again */
        shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));
        n = validate(&t);
        assert(n == 0);

        /* add all nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                insert(&t, nodes[i]);
                n = validate(&t);
                assert(n == i + 1);
        }

        /* 4 times, remove half of the nodes and add them again */
        for (j = 0; j < 4; ++j) {
                /* shuffle nodes again */
                shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));

                /* remove half of the nodes */
                for (i = 0; i < sizeof(nodes) / sizeof(*nodes) / 2; ++i) {
                        c_rbtree_remove(&t, nodes[i]);
                        n = validate(&t);
                        assert(n == sizeof(nodes) / sizeof(*nodes) - i - 1);
                        c_rbnode_init(nodes[i]);
                }

                /* shuffle the removed half */
                shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes) / 2);

                /* add the removed half again */
                for (i = 0; i < sizeof(nodes) / sizeof(*nodes) / 2; ++i) {
                        insert(&t, nodes[i]);
                        n = validate(&t);
                        assert(n == sizeof(nodes) / sizeof(*nodes) / 2 + i + 1);
                }
        }

        /* shuffle nodes again */
        shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                c_rbtree_remove(&t, nodes[i]);
                n = validate(&t);
                assert(n == sizeof(nodes) / sizeof(*nodes) - i - 1);
                c_rbnode_init(nodes[i]);
        }

        /* free nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                free(nodes[i]);
}

typedef struct {
        unsigned long key;
        CRBNode rb;
} Node;

#define node_from_rb(_rb) ((Node *)((char *)(_rb) - offsetof(Node, rb)))

static int compare(CRBTree *t, void *k, CRBNode *n) {
        unsigned long key = (unsigned long)k;
        Node *node = node_from_rb(n);

        return (key < node->key) ? -1 : (key > node->key) ? 1 : 0;
}

/* run tests against the c_rbtree_find*() helpers */
static void test_map(void) {
        CRBNode **slot, *p;
        CRBTree t = {};
        Node *nodes[2048];
        unsigned long i;

        /* allocate and initialize all nodes */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                nodes[i] = malloc(sizeof(*nodes[i]));
                assert(nodes[i]);
                nodes[i]->key = i;
                c_rbnode_init(&nodes[i]->rb);
        }

        /* shuffle nodes */
        shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));

        /* add all nodes, and verify that each node is linked */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                assert(!c_rbnode_is_linked(&nodes[i]->rb));
                assert(!c_rbtree_find_entry(&t, compare, (void *)nodes[i]->key, Node, rb));

                slot = c_rbtree_find_slot(&t, compare, (void *)nodes[i]->key, &p);
                assert(slot);
                c_rbtree_add(&t, p, slot, &nodes[i]->rb);

                assert(c_rbnode_is_linked(&nodes[i]->rb));
                assert(nodes[i] == c_rbtree_find_entry(&t, compare, (void *)nodes[i]->key, Node, rb));
        }

        /* shuffle nodes again */
        shuffle((void **)nodes, sizeof(nodes) / sizeof(*nodes));

        /* remove all nodes (in different order) */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i) {
                assert(c_rbnode_is_linked(&nodes[i]->rb));
                assert(nodes[i] == c_rbtree_find_entry(&t, compare, (void *)nodes[i]->key, Node, rb));

                c_rbtree_remove_init(&t, &nodes[i]->rb);

                assert(!c_rbnode_is_linked(&nodes[i]->rb));
                assert(!c_rbtree_find_entry(&t, compare, (void *)nodes[i]->key, Node, rb));
        }

        /* free nodes again */
        for (i = 0; i < sizeof(nodes) / sizeof(*nodes); ++i)
                free(nodes[i]);
}

int main(int argc, char **argv) {
        unsigned int i;

        /* we want stable tests, so use fixed seed */
        srand(0xdeadbeef);

        test_api();

        /*
         * The tests are pseudo random; run them multiple times, each run will
         * have different orders and thus different results.
         */
        for (i = 0; i < 4; ++i) {
                test_shuffle();
                test_map();
        }

        return 0;
}
