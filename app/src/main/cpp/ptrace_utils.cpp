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

void wait_for_signal(int pid, int sig) {
    int status;
    if (waitpid(pid, &status, __WALL) == -1) {
        perror("waiting pre call");
        ptrace(PTRACE_DETACH, pid, 0, WSTOPSIG(status));
        exit(1);
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != sig) {
        auto reason = parse_status(status);
        print("stopped by other reason: %s", reason.c_str());
        dump_siginfo(pid);
        dump_regs(pid);
        ptrace(PTRACE_DETACH, pid, 0, WSTOPSIG(status));
        exit(1);
    }
}


#if defined(__x86_64__)
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
    if (ptrace(PTRACE_POKETEXT, pid, regs.rip, 0xccd0ff) == -1) { // call *%rax; int 3
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
    wait_for_signal(pid, SIGTRAP);
    if (!ptrace_get_regs(pid, regs)) {
        perror("get regs post call");
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

bool put_syscall_arg(int pid, struct user_regs_struct &regs, int pos, void* arg) {
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
            regs.r10 = (unsigned long long) arg;
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

bool make_syscall(int pid, int nr, struct user_regs_struct &regs, void** result) {
    auto orig_rip = regs.rip;
    long instruction = ptrace(PTRACE_PEEKTEXT, pid, orig_rip, nullptr);
    print("rip=%p instruction: %lx", (void*) orig_rip, instruction);
    if (ptrace(PTRACE_POKETEXT, pid, regs.rip, 0x050f) == -1) {
        perror("replace code");
        return false;
    }
    regs.rsp = regs.rsp & (~0xf);
    regs.rax = (unsigned long long) nr;
    if (!ptrace_set_regs(pid, regs)) {
        perror("set regs for call");
        return false;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
        perror("continue for call");
        return false;
    }
    wait_for_signal(pid, SIGTRAP);
    if (!ptrace_get_regs(pid, regs)) {
        perror("get regs post call");
        return false;
    }
    if (regs.rip != orig_rip + 2) {
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

void dump_regs(int pid) {
    struct user_regs_struct regs{};
    if (!ptrace_get_regs(pid, regs)) {
        perror("failed to get regs for dump");
    } else {
        print("current rsp=%p, rip=%p", (void *) regs.rsp, (void *) regs.rip);
    }
}

#elif defined(__aarch64__)
#define NT_PRSTATUS 1

bool ptrace_get_regs(int pid, struct user_regs_struct &regs) {
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        perror("get regs");
        return false;
    }
    return true;
}

bool ptrace_set_regs(int pid, const struct user_regs_struct &regs) {
    struct iovec iov = {
        .iov_base = (void*) &regs,
        .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
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
    print("sp=%p", (void*) regs.sp);
    regs.sp -= size;
    struct iovec local{
            .iov_base = (void*) str,
            .iov_len = size
    }, remote{
            .iov_base = (void*) regs.sp,
            .iov_len = size
    };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == -1) {
        print("failed to write to remote %p from %p size=%ld", (void*) regs.sp, str, size);
        perror("stack push str");
        return false;
    }
    addr = (void*) regs.sp;
    print("string pushed to %p (size=%ld)", addr, size);
    return true;
}

bool make_call(int pid, void* addr, struct user_regs_struct &regs, void** result) {
    auto orig_pc = regs.pc;
    long instruction = ptrace(PTRACE_PEEKTEXT, pid, orig_pc, nullptr);
    print("pc=%p instruction: %lx", (void*) orig_pc, instruction);
    if (ptrace(PTRACE_POKETEXT, pid, regs.pc, 0xd4200020d63f0120) == -1) { // blr x9; brk #0x1
        perror("replace code");
        return false;
    }
    regs.sp = regs.sp & (~0xf);
    regs.regs[9] = (unsigned long long) addr;
    if (!ptrace_set_regs(pid, regs)) {
        perror("set regs for call");
        return false;
    }
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        perror("continue for call");
        return false;
    }
    wait_for_signal(pid, SIGTRAP);
    if (!ptrace_get_regs(pid, regs)) {
        perror("get regs post call");
        return false;
    }
    if (regs.pc != orig_pc + 4) {
        print("break on wrong position pc=%lx", regs.pc);
        return false;
    }
    if (ptrace(PTRACE_POKETEXT, pid, orig_pc, instruction) == -1) {
        perror("restore code");
        return false;
    }
    if (result != nullptr)
        *result = (void*) regs.regs[0];
    return true;
}

bool put_arg(int pid, struct user_regs_struct &regs, int pos, void* arg) {
    if (pos >= 1 && pos <= 8) {
        regs.regs[pos - 1] = (unsigned long long) arg;
        return true;
    }
    return false;
}

bool put_syscall_arg(int pid, struct user_regs_struct &regs, int pos, void* arg) {
    if (pos >= 1 && pos <= 6) {
        regs.regs[pos - 1] = (unsigned long long) arg;
        return true;
    }
    return false;
}

bool make_syscall(int pid, int nr, struct user_regs_struct &regs, void** result) {
    auto orig_pc = regs.pc;
    long instruction = ptrace(PTRACE_PEEKTEXT, pid, orig_pc, nullptr);
    print("pc=%p instruction: %lx", (void*) orig_pc, instruction);
    if (ptrace(PTRACE_POKETEXT, pid, regs.pc, 0xd4000001) == -1) { // svc 0
        perror("replace code");
        return false;
    }
    regs.sp = regs.sp & (~0xf);
    regs.regs[8] = (unsigned long long) nr;
    if (!ptrace_set_regs(pid, regs)) {
        perror("set regs for call");
        return false;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
        perror("continue for call");
        return false;
    }
    wait_for_signal(pid, SIGTRAP);
    if (!ptrace_get_regs(pid, regs)) {
        perror("get regs post call");
        return false;
    }
    if (regs.pc != orig_pc + 4) {
        print("break on wrong position pc=%lx", regs.pc);
        return false;
    }
    if (ptrace(PTRACE_POKETEXT, pid, orig_pc, instruction) == -1) {
        perror("restore code");
        return false;
    }
    if (result != nullptr)
        *result = (void*) regs.regs[0];
    return true;
}

void dump_regs(int pid) {
    struct user_regs_struct regs{};
    if (!ptrace_get_regs(pid, regs)) {
        perror("failed to get regs for dump");
    } else {
        print("current sp=%p, pc=%p", (void *) regs.sp, (void *) regs.pc);
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
bool put_syscall_arg(int pid, struct user_regs_struct &regs, int pos, void* arg) NOT_IMPLEMENTED
bool make_syscall(int pid, int nr, struct user_regs_struct &regs, void** result) NOT_IMPLEMENTED
void dump_regs(int pid) {}
#endif
