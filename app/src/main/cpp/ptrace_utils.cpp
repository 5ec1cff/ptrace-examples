#include "ptrace_utils.h"
#include "logging.h"

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
            return nullptr;
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
            return "unknown";
    }
}

std::string parse_status(int status) {
    std::string result;
    std::ostringstream stream{};
    int sig = 0;
    if (WIFSTOPPED(status)) {
        sig = WSTOPSIG(status);
        stream << "stopped by ";
    } else if (WIFSIGNALED(status)) {
        sig = WTERMSIG(status);
        stream << "signaled by ";
    } else if (WIFEXITED(status)) {
        stream << "exited with ";
        stream << WEXITSTATUS(status);
    }
    if (sig != 0) {
        stream << sys_signame[sig];
        stream << "(";
        stream << sig;
        stream << ")";
    }
    auto event = parse_ptrace_event(status);
    if (event != nullptr) {
        stream << " event: " << event;
    }
    result = stream.str();
    return result;
}

void dump_siginfo(int pid) {
    siginfo_t siginfo;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
        perror("get siginfo");
        return;
    }
    auto si_code = parse_si_code(siginfo.si_code);
    print("si_code: %s", si_code);
    if (siginfo.si_signo == SIGSEGV) {
        print("fault addr: %p", siginfo.si_addr);
    }
}
