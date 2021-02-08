#include "bus-message.h"
#include "json.h"

typedef enum JsonTransformFlags {
        JSON_TRANSFORM_PLAIN = 1 << 0,
        JSON_TRANSFORM_TYPE_DATA  = 1 << 1, /* Insert layer with variant type/data */

} JsonTransformFlags;

int json_transform_message(sd_bus_message *m, JsonTransformFlags transform_flags, JsonVariant **ret);
int json_transform_variant(sd_bus_message *m, const char *contents, JsonTransformFlags transform_flags, JsonVariant **ret);
