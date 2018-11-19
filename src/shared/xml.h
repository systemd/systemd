/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

enum {
        XML_END,
        XML_TEXT,
        XML_TAG_OPEN,
        XML_TAG_CLOSE,
        XML_TAG_CLOSE_EMPTY,
        XML_ATTRIBUTE_NAME,
        XML_ATTRIBUTE_VALUE,
};

int xml_tokenize(const char **p, char **name, void **state, unsigned *line);
