#include "login-shared.h"
#include "def.h"

bool session_id_valid(const char *id) {
        assert(id);

        return id + strspn(id, LETTERS DIGITS) == '\0';
}
