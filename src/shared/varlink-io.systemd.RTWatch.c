/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-idl-common.h"
#include "varlink-io.systemd.RTWatch.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ThreadId,
                SD_VARLINK_FIELD_COMMENT("The process the thread belongs to. When passed to a method and not specified, the calling process is used."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(process, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Numeric kernel thread ID (as returned by gettid()). When passed to a method and not specified or zero, the main thread of the process is used."),
                SD_VARLINK_DEFINE_FIELD(tid, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("64bit inode number of the thread's pidfd (as allocated with PIDFD_THREAD) if known, valid on the boot identified by the bootId field of the process."),
                SD_VARLINK_DEFINE_FIELD(pidfdId, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                MakeThreadRealtime,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The thread to change. If not specified the main thread of the calling process is used. The process must be owned by the same user as the caller."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(thread, ThreadId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The realtime priority to set, in the range 1…maxRealtimePriority (as returned by Describe())."),
                SD_VARLINK_DEFINE_INPUT(priority, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                MakeThreadHighPriority,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The thread to change. If not specified the main thread of the calling process is used. The process must be owned by the same user as the caller."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(thread, ThreadId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The nice level to set, in the range minNiceLevel…19 (as returned by Describe())."),
                SD_VARLINK_DEFINE_INPUT(niceLevel, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResetKnown,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                ResetAll,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Suspend,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Resume,
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Describe,
                SD_VARLINK_FIELD_COMMENT("The realtime scheduling policy handed out, either 'rr' or 'fifo'."),
                SD_VARLINK_DEFINE_OUTPUT(schedulingPolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The maximum realtime priority handed out."),
                SD_VARLINK_DEFINE_OUTPUT(maxRealtimePriority, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The minimum nice level handed out."),
                SD_VARLINK_DEFINE_OUTPUT(minNiceLevel, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Clients must set the hard limit of RLIMIT_RTTIME to this value in µs or lower before they may request realtime scheduling."),
                SD_VARLINK_DEFINE_OUTPUT(maxRealtimeTimeUSec, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the service is currently suspended, i.e. has temporarily demoted all known threads, and refuses further requests."),
                SD_VARLINK_DEFINE_OUTPUT(suspended, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("If the canary based watchdog had to take action recently, the CLOCK_MONOTONIC timestamp in µs until which further requests are refused."),
                SD_VARLINK_DEFINE_OUTPUT(refuseUntilUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The number of users currently supervised."),
                SD_VARLINK_DEFINE_OUTPUT(users, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The number of processes currently supervised."),
                SD_VARLINK_DEFINE_OUTPUT(processes, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The number of threads currently supervised."),
                SD_VARLINK_DEFINE_OUTPUT(threads, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The UID of the owner of the process."),
                SD_VARLINK_DEFINE_OUTPUT(userId, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The thread, and the process it belongs to."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(thread, ThreadId, 0),
                SD_VARLINK_FIELD_COMMENT("If the thread has been made realtime: the realtime priority it has been given."),
                SD_VARLINK_DEFINE_OUTPUT(priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If the thread has been made high priority: the nice level it has been given."),
                SD_VARLINK_DEFINE_OUTPUT(niceLevel, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The system unit the process belongs to, if any."),
                SD_VARLINK_DEFINE_OUTPUT(unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The user unit the process belongs to, if any."),
                SD_VARLINK_DEFINE_OUTPUT(userUnit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The command line of the process, i.e. its argv[] array."),
                SD_VARLINK_DEFINE_OUTPUT(commandLine, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The name of the thread, i.e. its comm field."),
                SD_VARLINK_DEFINE_OUTPUT(threadName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                Event,
                SD_VARLINK_FIELD_COMMENT("The subscription is established. This is always the first message sent in reply to Watch()."),
                SD_VARLINK_DEFINE_ENUM_VALUE(ready),
                SD_VARLINK_FIELD_COMMENT("A thread has been made realtime."),
                SD_VARLINK_DEFINE_ENUM_VALUE(realtime),
                SD_VARLINK_FIELD_COMMENT("A thread has been made high priority."),
                SD_VARLINK_DEFINE_ENUM_VALUE(high_priority),
                SD_VARLINK_FIELD_COMMENT("All known threads have been demoted, via ResetKnown()."),
                SD_VARLINK_DEFINE_ENUM_VALUE(reset_known),
                SD_VARLINK_FIELD_COMMENT("All realtime threads of the system have been demoted, via ResetAll()."),
                SD_VARLINK_DEFINE_ENUM_VALUE(reset_all),
                SD_VARLINK_FIELD_COMMENT("All known threads have been temporarily demoted, via Suspend() or because the system is about to go to sleep."),
                SD_VARLINK_DEFINE_ENUM_VALUE(suspended),
                SD_VARLINK_FIELD_COMMENT("All known threads have been promoted again, via Resume() or because the system woke up from sleep."),
                SD_VARLINK_DEFINE_ENUM_VALUE(resumed),
                SD_VARLINK_FIELD_COMMENT("The canary based watchdog detected that the system is starved of CPU time by realtime threads, and demoted threads. Further requests are refused for a while."),
                SD_VARLINK_DEFINE_ENUM_VALUE(starving));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Watch,
                SD_VARLINK_REQUIRES_MORE,
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("The event that took place."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(event, Event, 0),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' and 'high_priority' events: the UID of the owner of the process."),
                SD_VARLINK_DEFINE_OUTPUT(userId, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' and 'high_priority' events: the thread, and the process it belongs to."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(thread, ThreadId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' events: the realtime priority the thread has been given."),
                SD_VARLINK_DEFINE_OUTPUT(priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'high_priority' events: the nice level the thread has been given."),
                SD_VARLINK_DEFINE_OUTPUT(niceLevel, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' and 'high_priority' events: the system unit the process belongs to, if any."),
                SD_VARLINK_DEFINE_OUTPUT(unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' and 'high_priority' events: the user unit the process belongs to, if any."),
                SD_VARLINK_DEFINE_OUTPUT(userUnit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' and 'high_priority' events: the command line of the process, i.e. its argv[] array."),
                SD_VARLINK_DEFINE_OUTPUT(commandLine, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("For 'realtime' and 'high_priority' events: the name of the thread, i.e. its comm field."),
                SD_VARLINK_DEFINE_OUTPUT(threadName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'reset_known', 'reset_all', 'suspended', 'resumed' and 'starving' events: the number of threads that have been demoted or promoted."),
                SD_VARLINK_DEFINE_OUTPUT(affectedThreads, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("For 'starving' events: the CLOCK_MONOTONIC timestamp in µs until which further requests are refused."),
                SD_VARLINK_DEFINE_OUTPUT(refuseUntilUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchProcess);
static SD_VARLINK_DEFINE_ERROR(NoSuchThread);
static SD_VARLINK_DEFINE_ERROR(RealtimeTimeLimitNotSet);
static SD_VARLINK_DEFINE_ERROR(LimitReached);
static SD_VARLINK_DEFINE_ERROR(TooManyRequests);
static SD_VARLINK_DEFINE_ERROR(Suspended);
static SD_VARLINK_DEFINE_ERROR(RecoveringFromLockup);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_RTWatch,
                "io.systemd.RTWatch",
                SD_VARLINK_INTERFACE_COMMENT("APIs for acquiring realtime and high priority scheduling for threads of unprivileged processes."),
                SD_VARLINK_SYMBOL_COMMENT("A process ID, see ProcessId in the io.systemd interface."),
                &vl_type_ProcessId,
                SD_VARLINK_SYMBOL_COMMENT("A thread ID, i.e. a kernel thread ID qualified by the process it belongs to."),
                &vl_type_ThreadId,
                SD_VARLINK_SYMBOL_COMMENT("Makes the specified thread realtime (with SCHED_RESET_ON_FORK set)."),
                &vl_method_MakeThreadRealtime,
                SD_VARLINK_SYMBOL_COMMENT("Makes the specified thread high priority, i.e. sets a negative nice level (with SCHED_RESET_ON_FORK set)."),
                &vl_method_MakeThreadHighPriority,
                SD_VARLINK_SYMBOL_COMMENT("Demotes all threads previously made realtime or high priority by this service. Privileged."),
                &vl_method_ResetKnown,
                SD_VARLINK_SYMBOL_COMMENT("Demotes all realtime threads of the system. Privileged."),
                &vl_method_ResetAll,
                SD_VARLINK_SYMBOL_COMMENT("Temporarily demotes all known threads, until Resume() is called. Privileged."),
                &vl_method_Suspend,
                SD_VARLINK_SYMBOL_COMMENT("Promotes again all threads demoted by Suspend(). Privileged."),
                &vl_method_Resume,
                SD_VARLINK_SYMBOL_COMMENT("Returns the policy the service enforces, and its current state."),
                &vl_method_Describe,
                SD_VARLINK_SYMBOL_COMMENT("Enumerates the threads currently made realtime or high priority by this service, one reply per thread. Must be called with the 'more' flag. Unprivileged callers only see threads of their own processes."),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Events reported by Watch()."),
                &vl_type_Event,
                SD_VARLINK_SYMBOL_COMMENT("Subscribes to events, such as threads being made realtime or high priority, or demoted. Must be called with the 'more' flag. Privileged."),
                &vl_method_Watch,
                SD_VARLINK_SYMBOL_COMMENT("The specified process does not exist."),
                &vl_error_NoSuchProcess,
                SD_VARLINK_SYMBOL_COMMENT("The specified thread does not exist, or is not part of the specified process."),
                &vl_error_NoSuchThread,
                SD_VARLINK_SYMBOL_COMMENT("The hard limit of RLIMIT_RTTIME of the specified process is not set, or higher than maxRealtimeTimeUSec."),
                &vl_error_RealtimeTimeLimitNotSet,
                SD_VARLINK_SYMBOL_COMMENT("The maximum number of supervised users, processes per user or threads per user has been reached."),
                &vl_error_LimitReached,
                SD_VARLINK_SYMBOL_COMMENT("The caller's user issued too many requests in the rate limiting time window."),
                &vl_error_TooManyRequests,
                SD_VARLINK_SYMBOL_COMMENT("The service is currently suspended, and refuses requests."),
                &vl_error_Suspended,
                SD_VARLINK_SYMBOL_COMMENT("The canary based watchdog recently had to demote realtime threads, and the service refuses requests for a while."),
                &vl_error_RecoveringFromLockup);
