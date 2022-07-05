/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "list.h"
#include "util.h"

int main(int argc, const char *argv[]) {
        size_t i;
        typedef struct list_item {
                LIST_FIELDS(struct list_item, item_list);
        } list_item;
        LIST_HEAD(list_item, head);
        LIST_HEAD(list_item, head2);
        list_item items[4];

        LIST_HEAD_INIT(head);
        LIST_HEAD_INIT(head2);
        assert_se(head == NULL);
        assert_se(head2 == NULL);

        for (i = 0; i < ELEMENTSOF(items); i++) {
                LIST_INIT(item_list, &items[i]);
                assert_se(LIST_JUST_US(item_list, &items[i]));
                LIST_PREPEND(item_list, head, &items[i]);
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

        assert_se(items[0].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[0]);
        assert_se(items[2].item_list_next == &items[1]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        list_item *cursor;
        LIST_FIND_HEAD(item_list, &items[0], cursor);
        assert_se(cursor == &items[3]);

        LIST_FIND_TAIL(item_list, &items[3], cursor);
        assert_se(cursor == &items[0]);

        LIST_REMOVE(item_list, head, &items[1]);
        assert_se(LIST_JUST_US(item_list, &items[1]));

        assert_se(items[0].item_list_next == NULL);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_INSERT_AFTER(item_list, head, &items[3], &items[1]);
        assert_se(items[0].item_list_next == NULL);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_REMOVE(item_list, head, &items[1]);
        assert_se(LIST_JUST_US(item_list, &items[1]));

        assert_se(items[0].item_list_next == NULL);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_INSERT_BEFORE(item_list, head, &items[2], &items[1]);
        assert_se(items[0].item_list_next == NULL);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_REMOVE(item_list, head, &items[0]);
        assert_se(LIST_JUST_US(item_list, &items[0]));

        assert_se(items[2].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_INSERT_BEFORE(item_list, head, &items[3], &items[0]);
        assert_se(items[2].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);
        assert_se(items[0].item_list_next == &items[3]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == &items[0]);
        assert_se(items[0].item_list_prev == NULL);
        assert_se(head == &items[0]);

        LIST_REMOVE(item_list, head, &items[0]);
        assert_se(LIST_JUST_US(item_list, &items[0]));

        assert_se(items[2].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_INSERT_BEFORE(item_list, head, NULL, &items[0]);
        assert_se(items[0].item_list_next == NULL);
        assert_se(items[2].item_list_next == &items[0]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[0].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_REMOVE(item_list, head, &items[0]);
        assert_se(LIST_JUST_US(item_list, &items[0]));

        assert_se(items[2].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[3].item_list_next == &items[1]);

        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_REMOVE(item_list, head, &items[1]);
        assert_se(LIST_JUST_US(item_list, &items[1]));

        assert_se(items[2].item_list_next == NULL);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[2].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_REMOVE(item_list, head, &items[2]);
        assert_se(LIST_JUST_US(item_list, &items[2]));
        assert_se(LIST_JUST_US(item_list, head));

        LIST_REMOVE(item_list, head, &items[3]);
        assert_se(LIST_JUST_US(item_list, &items[3]));

        assert_se(head == NULL);

        for (i = 0; i < ELEMENTSOF(items); i++) {
                assert_se(LIST_JUST_US(item_list, &items[i]));
                LIST_APPEND(item_list, head, &items[i]);
        }

        assert_se(!LIST_JUST_US(item_list, head));

        assert_se(items[0].item_list_next == &items[1]);
        assert_se(items[1].item_list_next == &items[2]);
        assert_se(items[2].item_list_next == &items[3]);
        assert_se(items[3].item_list_next == NULL);

        assert_se(items[0].item_list_prev == NULL);
        assert_se(items[1].item_list_prev == &items[0]);
        assert_se(items[2].item_list_prev == &items[1]);
        assert_se(items[3].item_list_prev == &items[2]);

        for (i = 0; i < ELEMENTSOF(items); i++)
                LIST_REMOVE(item_list, head, &items[i]);

        assert_se(head == NULL);

        for (i = 0; i < ELEMENTSOF(items) / 2; i++) {
                LIST_INIT(item_list, &items[i]);
                assert_se(LIST_JUST_US(item_list, &items[i]));
                LIST_PREPEND(item_list, head, &items[i]);
        }

        for (i = ELEMENTSOF(items) / 2; i < ELEMENTSOF(items); i++) {
                LIST_INIT(item_list, &items[i]);
                assert_se(LIST_JUST_US(item_list, &items[i]));
                LIST_PREPEND(item_list, head2, &items[i]);
        }

        assert_se(items[0].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[0]);
        assert_se(items[2].item_list_next == NULL);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == NULL);
        assert_se(items[2].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_JOIN(item_list, head2, head);
        assert_se(head == NULL);

        assert_se(items[0].item_list_next == NULL);
        assert_se(items[1].item_list_next == &items[0]);
        assert_se(items[2].item_list_next == &items[1]);
        assert_se(items[3].item_list_next == &items[2]);

        assert_se(items[0].item_list_prev == &items[1]);
        assert_se(items[1].item_list_prev == &items[2]);
        assert_se(items[2].item_list_prev == &items[3]);
        assert_se(items[3].item_list_prev == NULL);

        LIST_JOIN(item_list, head, head2);
        assert_se(head2 == NULL);
        assert_se(head);

        for (i = 0; i < ELEMENTSOF(items); i++)
                LIST_REMOVE(item_list, head, &items[i]);

        assert_se(head == NULL);

        LIST_PREPEND(item_list, head, items + 0);
        LIST_PREPEND(item_list, head, items + 1);
        LIST_PREPEND(item_list, head, items + 2);

        assert_se(LIST_POP(item_list, head) == items + 2);
        assert_se(LIST_POP(item_list, head) == items + 1);
        assert_se(LIST_POP(item_list, head) == items + 0);
        assert_se(LIST_POP(item_list, head) == NULL);

        return 0;
}
