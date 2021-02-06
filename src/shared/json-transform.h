#include "bus-message.h"
#include "json.h"

int json_transform_message(sd_bus_message *m, JsonVariant **ret);