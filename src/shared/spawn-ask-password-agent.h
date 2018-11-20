/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

int ask_password_agent_open(void);
void ask_password_agent_close(void);

/* A dummy struct to make _cleanup_ type-safe */
typedef struct AskPasswordAgent {} AskPasswordAgent;
static inline void ask_password_agent_closep(AskPasswordAgent *agent) {
        ask_password_agent_close();
}
