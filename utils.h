#pragma once
#include <unistd.h>
#include <sys/ptrace.h>

const char* parse_ptrace_event(int status) {
    status = status >> 16;
    switch (status) {
        case PTRACE_EVENT_FORK:
            return "PTRACE_EVENT_FORK";
        case PTRACE_EVENT_VFORK:
            return "PTRACE_EVENT_VFORK";
        case PTRACE_EVENT_CLONE:
            return "PTRACE_EVENT_CLONE";
        case PTRACE_EVENT_EXEC:
            return "PTRACE_EVENT_EXEC";
        case PTRACE_EVENT_VFORK_DONE:
            return "PTRACE_EVENT_DONE";
        case PTRACE_EVENT_EXIT:
            return "PTRACE_EVENT_EXIT";
        case PTRACE_EVENT_SECCOMP:
            return "PTRACE_EVENT_SECCOMP";
        case PTRACE_EVENT_STOP:
            return "PTRACE_EVENT_STOP";
        default:
            return "(none)";
    }
}

#define CASE_CONST_RETURN(x) case x: return #x;

const char* parse_si_code(int si_code) {
    switch (si_code) {
        CASE_CONST_RETURN(SI_USER)
        CASE_CONST_RETURN(SI_KERNEL)
        CASE_CONST_RETURN(SI_QUEUE)
        CASE_CONST_RETURN(SI_TIMER)
        CASE_CONST_RETURN(SI_MESGQ)
        CASE_CONST_RETURN(SI_ASYNCIO)
        CASE_CONST_RETURN(SI_SIGIO)
        CASE_CONST_RETURN(SI_TKILL)
        default:
            if ((si_code & 0xff) == SIGTRAP) {
                return parse_ptrace_event(si_code << 8);
            } else {
                return "unknown";
            }
    }
}


