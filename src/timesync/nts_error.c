#include <assert.h>
#include "nts.h"

#define ERROR(kind) case kind: return &#kind[4]

const char *NTS_error_string(enum NTS_ErrorType error) {
        switch (error) {
                ERROR(NTS_SERVER_UNKNOWN_CRIT_RECORD);
                ERROR(NTS_SERVER_BAD_REQUEST);
                ERROR(NTS_SERVER_INTERNAL_ERROR);

                ERROR(NTS_UNEXPECTED_WARNING);
                ERROR(NTS_BAD_RESPONSE);
                ERROR(NTS_INTERNAL_CLIENT_ERROR);
                ERROR(NTS_NO_PROTOCOL);
                ERROR(NTS_NO_AEAD);
                ERROR(NTS_INSUFFICIENT_DATA);
                ERROR(NTS_UNKNOWN_CRIT_RECORD);
        case NTS_SUCCESS:
                return "Success?";
        }

        /* this is unreachable code */
        assert(!"Unknown error");
        return NULL;
}
