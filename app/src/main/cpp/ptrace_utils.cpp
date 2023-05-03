#include "ptrace_utils.h"
#include "logging.h"

#define NOT_IMPLEMENTED { \
    print("not implemented"); \
    return false;         \
}

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


#ifdef __x86_64__
bool ptrace_get_regs(int pid, struct user_regs_struct &regs) {
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("get regs");
        return false;
    }
    return true;
}

bool ptrace_set_regs(int pid, const struct user_regs_struct &regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        perror("set regs");
        return false;
    }
    return true;
}

bool stack_push_str(
    int pid,
    struct user_regs_struct &regs,
    const char *str,
    size_t size,
    void* &addr
) {
    size++;
    print("rsp=%p", (void*) regs.rsp);
    regs.rsp -= size;
    struct iovec local{
            .iov_base = (void*) str,
            .iov_len = size
    }, remote{
            .iov_base = (void*) regs.rsp,
            .iov_len = size
    };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == -1) {
        print("failed to write to remote %p from %p size=%ld", (void*) regs.rsp, str, size);
        perror("stack push str");
        return false;
    }
    addr = (void*) regs.rsp;
    print("string pushed to %p (size=%ld)", addr, size);
    return true;
}

bool make_call(int pid, void* addr, struct user_regs_struct &regs, void** result) {
    auto orig_rip = regs.rip;
    long instruction = ptrace(PTRACE_PEEKTEXT, pid, orig_rip, nullptr);
    print("rip=%p instruction: %lx", (void*) orig_rip, instruction);
    if (ptrace(PTRACE_POKETEXT, pid, regs.rip, 0xccd0ff) == -1) {
        perror("replace code");
        return false;
    }
    regs.rsp = regs.rsp & (~0xf);
    regs.rax = (unsigned long long) addr;
    if (!ptrace_set_regs(pid, regs)) {
        perror("set regs for call");
        return false;
    }
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        perror("continue for call");
        return false;
    }
    int status;
    if (waitpid(pid, &status, __WALL) == -1) {
        perror("waiting pre call");
        return false;
    }

    bool regs_got = ptrace_get_regs(pid, regs);
    if (!regs_got) {
        perror("get regs post call");
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        auto reason = parse_status(status);
        print("stopped by other reason: %s", reason.c_str());
        dump_siginfo(pid);
        if (regs_got) {
            print("current rsp=%p, rip=%p", (void*) regs.rsp, (void*) regs.rip);
        }
        ptrace(PTRACE_DETACH, pid, 0, WSTOPSIG(status));
        exit(1);
        // return false;
    }
    if (!regs_got) {
        return false;
    }
    if (regs.rip != orig_rip + 3) {
        print("break on wrong position rip=%lx", regs.rip);
        return false;
    }
    if (ptrace(PTRACE_POKETEXT, pid, orig_rip, instruction) == -1) {
        perror("restore code");
        return false;
    }
    if (result != nullptr)
        *result = (void*) regs.rax;
    return true;
}

bool put_arg(int pid, struct user_regs_struct &regs, int pos, void* arg) {
    switch (pos) {
        case 1:
            regs.rdi = (unsigned long long) arg;
            return true;
        case 2:
            regs.rsi = (unsigned long long) arg;
            return true;
        case 3:
            regs.rdx = (unsigned long long) arg;
            return true;
        case 4:
            regs.rcx = (unsigned long long) arg;
            return true;
        case 5:
            regs.r8 = (unsigned long long) arg;
            return true;
        case 6:
            regs.r9 = (unsigned long long) arg;
            return true;
        default:
            // not implemented
            return false;
    }
}

#else
bool ptrace_get_regs(int pid, struct user_regs_struct &regs) NOT_IMPLEMENTED
bool ptrace_set_regs(int pid, const struct user_regs_struct &regs) NOT_IMPLEMENTED
bool stack_push_str(
        int pid,
        struct user_regs_struct &regs,
        const char *str,
        size_t size,
        void* &addr) NOT_IMPLEMENTED

bool make_call(int pid, void* addr, struct user_regs_struct &regs, void** result) NOT_IMPLEMENTED
bool put_arg(int pid, struct user_regs_struct &regs, int pos, void* arg) NOT_IMPLEMENTED
#endif
