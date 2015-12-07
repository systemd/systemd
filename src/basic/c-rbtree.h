#pragma once

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
 * Standalone Red-Black-Tree Implementation in Standard ISO-C11
 *
 * This header provides an RB-Tree API, that is fully implemented in ISO-C11
 * and has no external dependencies. Furthermore, tree traversal, memory
 * allocations, and key comparisons a fully in control of the API user. The
 * implementation only provides the RB-Tree specific rebalancing and coloring.
 *
 * A tree is represented by the "CRBTree" structure. It contains a *singly*
 * field, which is a pointer to the root node. If NULL, the tree is empty. If
 * non-NULL, there is at least a single element in the tree.
 *
 * Each node of the tree is represented by the "CRBNode" structure. It has
 * three fields. The @left and @right members can be accessed by the API user
 * directly to traverse the tree. The third member is an implementation detail
 * and encodes the parent pointer and color of the node.
 * API users are required to embed the CRBNode object into their own objects
 * and then use offsetof() (i.e., container_of() and friends) to turn CRBNode
 * pointers into pointers to their own structure.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CRBNode CRBNode;
typedef struct CRBTree CRBTree;

/**
 * struct CRBNode - Node of a Red-Black Tree
 * @__parent_and_color:         internal state
 * @left:                       left child, or NULL
 * @right:                      right child, or NULL
 *
 * Each node in an RB-Tree must embed an CRBNode object. This object contains
 * pointers to its left and right child, which can be freely accessed by the
 * API user at any time. They are NULL, if the node does not have a left/right
 * child.
 *
 * The @__parent_and_color field must never be accessed directly. It encodes
 * the pointer to the parent node, and the color of the node. Use the accessor
 * functions instead.
 *
 * There is no reason to initialize a CRBNode object before linking it.
 * However, if you need a boolean state that tells you whether the node is
 * linked or not, you should initialize the node via c_rbnode_init() or
 * C_RBNODE_INIT.
 */
struct CRBNode {
        CRBNode *__parent_and_color;
        CRBNode *left;
        CRBNode *right;
};

#define C_RBNODE_INIT(_var) { .__parent_and_color = &(_var) }

CRBNode *c_rbnode_leftmost(CRBNode *n);
CRBNode *c_rbnode_rightmost(CRBNode *n);
CRBNode *c_rbnode_next(CRBNode *n);
CRBNode *c_rbnode_prev(CRBNode *n);

/**
 * struct CRBTree - Red-Black Tree
 * @root:       pointer to the root node, or NULL
 *
 * Each Red-Black Tree is rooted in an CRBTree object. This object contains a
 * pointer to the root node of the tree. The API user is free to access the
 * @root member at any time, and use it to traverse the tree.
 *
 * To initialize an RB-Tree, set it to NULL / all zero.
 */
struct CRBTree {
        CRBNode *root;
};

CRBNode *c_rbtree_first(CRBTree *t);
CRBNode *c_rbtree_last(CRBTree *t);

void c_rbtree_add(CRBTree *t, CRBNode *p, CRBNode **l, CRBNode *n);
void c_rbtree_remove(CRBTree *t, CRBNode *n);

/**
 * c_rbnode_init() - mark a node as unlinked
 * @n:          node to operate on
 *
 * This marks the node @n as unlinked. The node will be set to a valid state
 * that can never happen if the node is linked in a tree. Furthermore, this
 * state is fully known to the implementation, and as such handled gracefully
 * in all cases.
 *
 * You are *NOT* required to call this on your node. c_rbtree_add() can handle
 * uninitialized nodes just fine. However, calling this allows to use
 * c_rbnode_is_linked() to check for the state of a node. Furthermore,
 * iterators and accessors can be called on initialized (yet unlinked) nodes.
 *
 * Use the C_RBNODE_INIT macro if you want to initialize static variables.
 */
static inline void c_rbnode_init(CRBNode *n) {
        *n = (CRBNode)C_RBNODE_INIT(*n);
}

/**
 * c_rbnode_is_linked() - check whether a node is linked
 * @n:          node to check, or NULL
 *
 * This checks whether the passed node is linked. If you pass NULL, or if the
 * node is not linked into a tree, this will return false. Otherwise, this
 * returns true.
 *
 * Note that you must have either linked the node or initialized it, before
 * calling this function. Never call this function on uninitialized nodes.
 * Furthermore, removing a node via c_rbtree_remove() does *NOT* mark the node
 * as unlinked. You have to call c_rbnode_init() yourself after removal, or use
 * the c_rbtree_remove_init() helper.
 *
 * Return: true if the node is linked, false if not.
 */
static inline _Bool c_rbnode_is_linked(CRBNode *n) {
        return n && n->__parent_and_color != n;
}

/**
 * c_rbnode_parent() - return parent pointer
 * @n           node to access
 *
 * This returns a pointer to the parent of the given node @n. If @n does not
 * have a parent, NULL is returned. If @n is not linked, @n itself is returned.
 *
 * You should not call this on unlinked or uninitialized nodes! If you do, you
 * better know how its semantics.
 *
 * Return: Pointer to parent.
 */
static inline CRBNode *c_rbnode_parent(CRBNode *n) {
        return (CRBNode*)((unsigned long)n->__parent_and_color & ~1UL);
}

/**
 * c_rbtree_remove_init() - safely remove node from tree and reinitialize it
 * @t:          tree to operate on
 * @n:          node to remove, or NULL
 *
 * This is almost the same as c_rbtree_remove(), but extends it slightly, to be
 * more convenient to use in many cases:
 *  - if @n is unlinked or NULL, this is a no-op
 *  - @n is reinitialized after being removed
 */
static inline void c_rbtree_remove_init(CRBTree *t, CRBNode *n) {
        if (c_rbnode_is_linked(n)) {
                c_rbtree_remove(t, n);
                c_rbnode_init(n);
        }
}

/**
 * CRBCompareFunc - compare a node to a key
 * @t:          tree where the node is linked to
 * @k:          key to compare
 * @n:          node to compare
 *
 * If you use the tree-traversal helpers (which are optional), you need to
 * provide this callback so they can compare nodes in a tree to the key you
 * look for.
 *
 * The tree @t is provided as optional context to this callback. The key you
 * look for is provided as @k, the current node that should be compared to is
 * provided as @n. This function should work like strcmp(), that is, return -1
 * if @key orders before @n, 0 if both compare equal, and 1 if it orders after
 * @n.
 */
typedef int (*CRBCompareFunc) (CRBTree *t, void *k, CRBNode *n);

/**
 * c_rbtree_find_node() - find node
 * @t:          tree to search through
 * @f:          comparison function
 * @k:          key to search for
 *
 * This searches through @t for a node that compares equal to @k. The function
 * @f must be provided by the caller, which is used to compare nodes to @k. See
 * the documentation of CRBCompareFunc for details.
 *
 * If there are multiple entries that compare equal to @k, this will return a
 * pseudo-randomly picked node. If you need stable lookup functions for trees
 * where duplicate entries are allowed, you better code your own lookup.
 *
 * Return: Pointer to matching node, or NULL.
 */
static inline CRBNode *c_rbtree_find_node(CRBTree *t, CRBCompareFunc f, const void *k) {
        CRBNode *i;

        assert(t);
        assert(f);

        i = t->root;
        while (i) {
                int v = f(t, (void *)k, i);
                if (v < 0)
                        i = i->left;
                else if (v > 0)
                        i = i->right;
                else
                        return i;
        }

        return NULL;
}

/**
 * c_rbtree_find_entry() - find entry
 * @_t:         tree to search through
 * @_f:         comparison function
 * @_k:         key to search for
 * @_t:         type of the structure that embeds the nodes
 * @_o:         name of the node-member in type @_t
 *
 * This is very similar to c_rbtree_find_node(), but instead of returning a
 * pointer to the CRBNode, it returns a pointer to the surrounding object. This
 * object must embed the CRBNode object. The type of the surrounding object
 * must be given as @_t, and the name of the embedded CRBNode member as @_o.
 *
 * See c_rbtree_find_node() for more details.
 *
 * Return: Pointer to found entry, NULL if not found.
 */
#define c_rbtree_find_entry(_m, _f, _k, _t, _o) \
        ((_t *)(((char *)c_rbtree_find_node((_m), (_f), (_k)) ?: \
                (char *)NULL + offsetof(_t, _o)) - offsetof(_t, _o)))

/**
 * c_rbtree_find_slot() - find slot to insert new node
 * @t:          tree to search through
 * @f:          comparison function
 * @k:          key to search for
 * @p:          output storage for parent pointer
 *
 * This searches through @t just like c_rbtree_find_node() does. However,
 * instead of returning a pointer to a node that compares equal to @k, this
 * searches for a slot to insert a node with key @k. A pointer to the slot is
 * returned, and a pointer to the parent of the slot is stored in @p. Both
 * can be passed directly to c_rbtree_add(), together with your node to insert.
 *
 * If there already is a node in the tree, that compares equal to @k, this will
 * return NULL and store the conflicting node in @p. In all other cases,
 * this will return a pointer (non-NULL) to the empty slot to insert the node
 * at. @p will point to the parent node of that slot.
 *
 * If you want trees that allow duplicate nodes, you better code your own
 * insertion function.
 *
 * Return: Pointer to slot to insert node, or NULL on conflicts.
 */
static inline CRBNode **c_rbtree_find_slot(CRBTree *t, CRBCompareFunc f, const void *k, CRBNode **p) {
        CRBNode **i;

        assert(t);
        assert(f);
        assert(p);

        i = &t->root;
        *p = NULL;
        while (*i) {
                int v = f(t, (void *)k, *i);
                *p = *i;
                if (v < 0)
                        i = &(*i)->left;
                else if (v > 0)
                        i = &(*i)->right;
                else
                        return NULL;
        }

        return i;
}

#ifdef __cplusplus
}
#endif
