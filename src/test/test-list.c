/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "list.h"
#include "tests.h"

int main(int argc, const char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        size_t i;
        typedef struct list_item {
                LIST_FIELDS(struct list_item, item_list);
        } list_item;
        LIST_HEAD(list_item, head);
        LIST_HEAD(list_item, head2);
        list_item items[4];

        LIST_HEAD_INIT(head);
        LIST_HEAD_INIT(head2);
        ASSERT_NULL(head);
        ASSERT_NULL(head2);

        FOREACH_ELEMENT(item, items) {
                LIST_INIT(item_list, item);
                assert_se(LIST_JUST_US(item_list, item));
                assert_se(LIST_PREPEND(item_list, head, item) == item);
        }

        i = 0;
        LIST_FOREACH_OTHERS(item_list, cursor, &items[2]) {
                i++;
                assert_se(cursor != &items[2]);
        }
        assert_se(i == ELEMENTSOF(items)-1);

        i = 0;
        LIST_FOREACH_OTHERS(item_list, cursor, &items[0]) {
                i++;
                assert_se(cursor != &items[0]);
        }
        assert_se(i == ELEMENTSOF(items)-1);

        i = 0;
        LIST_FOREACH_OTHERS(item_list, cursor, &items[3]) {
                i++;
                assert_se(cursor != &items[3]);
        }
        assert_se(i == ELEMENTSOF(items)-1);

        assert_se(!LIST_JUST_US(item_list, head));

        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[1].item_list_next == &items[0]);
        assert_se(items[2].item_list_next == &items[1]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        list_item *cursor = LIST_FIND_HEAD(item_list, &items[0]);
        assert_se(cursor == &items[3]);

        cursor = LIST_FIND_TAIL(item_list, &items[3]);
        assert_se(cursor == &items[0]);

        assert_se(LIST_REMOVE(item_list, head, &items[1]) == &items[1]);
        assert_se(LIST_JUST_US(item_list, &items[1]));

        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_INSERT_AFTER(item_list, head, &items[3], &items[1]) == &items[1]);
        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_REMOVE(item_list, head, &items[1]) == &items[1]);
        assert_se(LIST_JUST_US(item_list, &items[1]));

        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_INSERT_BEFORE(item_list, head, &items[2], &items[1]) == &items[1]);
        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_REMOVE(item_list, head, &items[0]) == &items[0]);
        assert_se(LIST_JUST_US(item_list, &items[0]));

        ASSERT_NULL(items[2].item_list_next);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_INSERT_BEFORE(item_list, head, &items[3], &items[0]) == &items[0]);
        ASSERT_NULL(items[2].item_list_next);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);
        assert_se(items[0].item_list_next == &items[3]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == &items[0]);
        ASSERT_NULL(items[0].item_list_prev);
        assert_se(head == &items[0]);

        assert_se(LIST_REMOVE(item_list, head, &items[0]) == &items[0]);
        assert_se(LIST_JUST_US(item_list, &items[0]));

        ASSERT_NULL(items[2].item_list_next);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_INSERT_BEFORE(item_list, head, NULL, &items[0]) == &items[0]);
        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_REMOVE(item_list, head, &items[0]) == &items[0]);
        assert_se(LIST_JUST_US(item_list, &items[0]));

        ASSERT_NULL(items[2].item_list_next);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_REMOVE(item_list, head, &items[1]) == &items[1]);
        assert_se(LIST_JUST_US(item_list, &items[1]));

        ASSERT_NULL(items[2].item_list_next);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[2].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_REMOVE(item_list, head, &items[2]) == &items[2]);
        assert_se(LIST_JUST_US(item_list, &items[2]));
        assert_se(LIST_JUST_US(item_list, head));

        assert_se(LIST_REMOVE(item_list, head, &items[3]) == &items[3]);
        assert_se(LIST_JUST_US(item_list, &items[3]));

        ASSERT_NULL(head);

        FOREACH_ELEMENT(item, items) {
                assert_se(LIST_JUST_US(item_list, item));
                assert_se(LIST_APPEND(item_list, head, item) == item);
        }

        assert_se(!LIST_JUST_US(item_list, head));

        assert_se(items[0].item_list_next == &items[1]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[2].item_list_next == &items[3]);
        ASSERT_NULL(items[3].item_list_next);

        ASSERT_NULL(items[0].item_list_prev);
        assert_se(items[1].item_list_prev == &items[0]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[3].item_list_prev == &items[2]);

        FOREACH_ELEMENT(item, items)
                assert_se(LIST_REMOVE(item_list, head, item) == item);

        ASSERT_NULL(head);

        FOREACH_ARRAY(item, items, ELEMENTSOF(items) / 2) {
                LIST_INIT(item_list, item);
                assert_se(LIST_JUST_US(item_list, item));
                assert_se(LIST_PREPEND(item_list, head, item) == item);
        }

        for (i = ELEMENTSOF(items) / 2; i < ELEMENTSOF(items); i++) {
                LIST_INIT(item_list, &items[i]);
                assert_se(LIST_JUST_US(item_list, &items[i]));
                assert_se(LIST_PREPEND(item_list, head2, &items[i]) == &items[i]);
        }

        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[1].item_list_next == &items[0]);
        ASSERT_NULL(items[2].item_list_next);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[1]);
        ASSERT_NULL(items[1].item_list_prev);
        assert_se(items[2].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_JOIN(item_list, head2, head) == head2);
        ASSERT_NULL(head);

        ASSERT_NULL(items[0].item_list_next);
        assert_se(items[1].item_list_next == &items[0]);
        assert_se(items[2].item_list_next == &items[1]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        ASSERT_NULL(items[3].item_list_prev);

        assert_se(LIST_JOIN(item_list, head, head2) == head);
        ASSERT_NULL(head2);
        assert_se(head);

        FOREACH_ELEMENT(item, items)
                assert_se(LIST_REMOVE(item_list, head, item) == item);

        ASSERT_NULL(head);

        assert_se(LIST_PREPEND(item_list, head, items + 0) == items + 0);
        assert_se(LIST_PREPEND(item_list, head, items + 1) == items + 1);
        assert_se(LIST_PREPEND(item_list, head, items + 2) == items + 2);

        assert_se(LIST_POP(item_list, head) == items + 2);
        assert_se(LIST_POP(item_list, head) == items + 1);
        assert_se(LIST_POP(item_list, head) == items + 0);
        ASSERT_NULL(LIST_POP(item_list, head));

        /* No-op on an empty list */

        LIST_CLEAR(item_list, head, free);

        /* A non-empty list is cleared */

        assert_se(LIST_PREPEND(item_list, head, new0(list_item, 1)));
        assert_se(LIST_PREPEND(item_list, head, new0(list_item, 1)));

        LIST_CLEAR(item_list, head, free);

        ASSERT_NULL(head);

        /* A list can be cleared partially */

        assert_se(LIST_PREPEND(item_list, head, new0(list_item, 1)));
        assert_se(LIST_PREPEND(item_list, head, new0(list_item, 1)));
        assert_se(LIST_PREPEND(item_list, head, items + 0) == items + 0);

        LIST_CLEAR(item_list, head->item_list_next, free);

        assert_se(head == items + 0);
        ASSERT_NULL(head->item_list_next);

        return 0;
}
