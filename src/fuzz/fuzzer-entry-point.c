#include "fuzz.h"

int FuzzerEntrypoint(const uint8_t *data, size_t size) {
        return LLVMFuzzerTestOneInput(data, size);
}
