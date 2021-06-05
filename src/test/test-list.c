/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Jan Janssen
***/

#include "list.h"
#include "util.h"

int main(int argc, const char *argv[]) {
        size_t i;
        typedef struct list_item {
                LIST_FIELDS(struct list_item, item);
        } list_item;
        LIST_HEAD(list_item, head);
        LIST_HEAD(list_item, head2);
        list_item items[4];
        list_item *cursor;

        LIST_HEAD_INIT(head);
        LIST_HEAD_INIT(head2);
        assert_se(head == NULL);
        assert_se(head2 == NULL);

        for (i = 0; i < ELEMENTSOF(items); i++) {
                LIST_INIT(item, &items[i]);
                assert_se(LIST_JUST_US(item, &items[i]));
                LIST_PREPEND(item, head, &items[i]);
        }

        i = 0;
        LIST_FOREACH_OTHERS(item, cursor, &items[2]) {
                i++;
                assert_se(cursor != &items[2]);
        }
        assert_se(i == ELEMENTSOF(items)-1);

        i = 0;
        LIST_FOREACH_OTHERS(item, cursor, &items[0]) {
                i++;
                assert_se(cursor != &items[0]);
        }
        assert_se(i == ELEMENTSOF(items)-1);

        i = 0;
        LIST_FOREACH_OTHERS(item, cursor, &items[3]) {
                i++;
                assert_se(cursor != &items[3]);
        }
        assert_se(i == ELEMENTSOF(items)-1);

        assert_se(!LIST_JUST_US(item, head));

        assert_se(items[0].item_next == NULL);
        assert_se(items[1].item_next == &items[0]);
        assert_se(items[2].item_next == &items[1]);
        assert_se(items[3].item_next == &items[2]);

        assert_se(items[0].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_FIND_HEAD(item, &items[0], cursor);
        assert_se(cursor == &items[3]);

        LIST_FIND_TAIL(item, &items[3], cursor);
        assert_se(cursor == &items[0]);

        LIST_REMOVE(item, head, &items[1]);
        assert_se(LIST_JUST_US(item, &items[1]));

        assert_se(items[0].item_next == NULL);
        assert_se(items[2].item_next == &items[0]);
        assert_se(items[3].item_next == &items[2]);

        assert_se(items[0].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_INSERT_AFTER(item, head, &items[3], &items[1]);
        assert_se(items[0].item_next == NULL);
        assert_se(items[2].item_next == &items[0]);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);

        assert_se(items[0].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_REMOVE(item, head, &items[1]);
        assert_se(LIST_JUST_US(item, &items[1]));

        assert_se(items[0].item_next == NULL);
        assert_se(items[2].item_next == &items[0]);
        assert_se(items[3].item_next == &items[2]);

        assert_se(items[0].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_INSERT_BEFORE(item, head, &items[2], &items[1]);
        assert_se(items[0].item_next == NULL);
        assert_se(items[2].item_next == &items[0]);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);

        assert_se(items[0].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_REMOVE(item, head, &items[0]);
        assert_se(LIST_JUST_US(item, &items[0]));

        assert_se(items[2].item_next == NULL);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);

        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_INSERT_BEFORE(item, head, &items[3], &items[0]);
        assert_se(items[2].item_next == NULL);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);
        assert_se(items[0].item_next == &items[3]);

        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == &items[0]);
        assert_se(items[0].item_prev == NULL);
        assert_se(head == &items[0]);

        LIST_REMOVE(item, head, &items[0]);
        assert_se(LIST_JUST_US(item, &items[0]));

        assert_se(items[2].item_next == NULL);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);

        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_INSERT_BEFORE(item, head, NULL, &items[0]);
        assert_se(items[0].item_next == NULL);
        assert_se(items[2].item_next == &items[0]);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);

        assert_se(items[0].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_REMOVE(item, head, &items[0]);
        assert_se(LIST_JUST_US(item, &items[0]));

        assert_se(items[2].item_next == NULL);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[3].item_next == &items[1]);

        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_REMOVE(item, head, &items[1]);
        assert_se(LIST_JUST_US(item, &items[1]));

        assert_se(items[2].item_next == NULL);
        assert_se(items[3].item_next == &items[2]);

        assert_se(items[2].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_REMOVE(item, head, &items[2]);
        assert_se(LIST_JUST_US(item, &items[2]));
        assert_se(LIST_JUST_US(item, head));

        LIST_REMOVE(item, head, &items[3]);
        assert_se(LIST_JUST_US(item, &items[3]));

        assert_se(head == NULL);

        for (i = 0; i < ELEMENTSOF(items); i++) {
                assert_se(LIST_JUST_US(item, &items[i]));
                LIST_APPEND(item, head, &items[i]);
        }

        assert_se(!LIST_JUST_US(item, head));

        assert_se(items[0].item_next == &items[1]);
        assert_se(items[1].item_next == &items[2]);
        assert_se(items[2].item_next == &items[3]);
        assert_se(items[3].item_next == NULL);

        assert_se(items[0].item_prev == NULL);
        assert_se(items[1].item_prev == &items[0]);
        assert_se(items[2].item_prev == &items[1]);
        assert_se(items[3].item_prev == &items[2]);

        for (i = 0; i < ELEMENTSOF(items); i++)
                LIST_REMOVE(item, head, &items[i]);

        assert_se(head == NULL);

        for (i = 0; i < ELEMENTSOF(items) / 2; i++) {
                LIST_INIT(item, &items[i]);
                assert_se(LIST_JUST_US(item, &items[i]));
                LIST_PREPEND(item, head, &items[i]);
        }

        for (i = ELEMENTSOF(items) / 2; i < ELEMENTSOF(items); i++) {
                LIST_INIT(item, &items[i]);
                assert_se(LIST_JUST_US(item, &items[i]));
                LIST_PREPEND(item, head2, &items[i]);
        }

        assert_se(items[0].item_next == NULL);
        assert_se(items[1].item_next == &items[0]);
        assert_se(items[2].item_next == NULL);
        assert_se(items[3].item_next == &items[2]);

        assert_se(items[0].item_prev == &items[1]);
        assert_se(items[1].item_prev == NULL);
        assert_se(items[2].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_JOIN(item, head2, head);
        assert_se(head == NULL);

        assert_se(items[0].item_next == NULL);
        assert_se(items[1].item_next == &items[0]);
        assert_se(items[2].item_next == &items[1]);
        assert_se(items[3].item_next == &items[2]);

        assert_se(items[0].item_prev == &items[1]);
        assert_se(items[1].item_prev == &items[2]);
        assert_se(items[2].item_prev == &items[3]);
        assert_se(items[3].item_prev == NULL);

        LIST_JOIN(item, head, head2);
        assert_se(head2 == NULL);
        assert_se(!LIST_IS_EMPTY(head));

        for (i = 0; i < ELEMENTSOF(items); i++)
                LIST_REMOVE(item, head, &items[i]);

        assert_se(head == NULL);

        return 0;
}
