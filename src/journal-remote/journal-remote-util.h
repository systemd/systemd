#include "compress.h"
#include "conf-parser.h"

typedef struct CompressionOpts {
        Compression algorithm;
        int level;
} CompressionOpts;

typedef struct CompressionArgs {
        CompressionOpts *opts;
        size_t size;
} CompressionArgs;

CONFIG_PARSER_PROTOTYPE(config_parse_compression);
