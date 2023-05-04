#include "trace.h"

#define NT_PRSTATUS 1

bool TracedProcess::attach(int pid) {
    pid_ = pid;
    if (ptrace(PTRACE_ATTACH, pid_, 0, 0) == -1) {
        perror("attach");
        return false;
    }
    return true;
}

bool TracedProcess::detach() {
    if (ptrace(PTRACE_DETACH, pid_, 0, 0) == -1) {
        perror("attach");
        return false;
    }
    pid_ = -1;
    return true;
}

bool TracedProcess::attach_and_wait(int pid) {
    if (!attach(pid)) return false;
    if (!wait_for_signal(SIGSTOP)) return false;
    return true;
}

bool TracedProcess::get_regs() {
#if defined(__x86_64__)
    if (ptrace(PTRACE_GETREGS, pid_, 0, &regs_) == -1) {
        return false;
    }
    return true;
#elif defined(__aarch64__)

    struct iovec iov = {
            .iov_base = &regs_,
            .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_GETREGSET, pid_, NT_PRSTATUS, &iov) == -1) {
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool TracedProcess::set_regs(struct user_regs_struct &new_regs) {
    regs_ = new_regs;
    return set_regs();
}

bool TracedProcess::set_regs() {
#if defined(__x86_64__)
    if (ptrace(PTRACE_SETREGS, pid_, 0, &regs_) == -1) {
        perror("set regs");
        return false;
    }
    return true;
#elif defined(__aarch64__)
    struct iovec iov = {
            .iov_base = &regs_,
            .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_SETREGSET, pid_, NT_PRSTATUS, &iov) == -1) {
        perror("set regs");
        return false;
    }
    return true;
#else
    return false;
#endif
}

#if defined(__x86_64__)
const auto CODE_FOR_CALL = 0xccd0fflu; // call *%rax; int 3
const auto CODE_FOR_SYSCALL = 0x050flu; // syscall
const auto CALL_EXPECTED_OFFSET = 3;
#define REG_FUNC_POINTER rax
#define REG_SYSCALL_NR rax
#define REG_RETVAL rax
#define REG_SYSCALL_RETVAL rax
#elif defined(__aarch64__)
const auto CODE_FOR_CALL = 0xd4200020d63f0120lu; // blr x9; brk #0x1
const auto CODE_FOR_SYSCALL = 0xd4000001lu; // svc 0
const auto CALL_EXPECTED_OFFSET = 4;
#define REG_FUNC_POINTER regs[9]
#define REG_SYSCALL_NR regs[8]
#define REG_RETVAL regs[0]
#define REG_SYSCALL_RETVAL regs[0]
#else
#endif

bool TracedProcess::stack_push_str(const std::string_view &str, void* &addr) {
    auto data = str.data();
    auto size = str.size();
    size++;
    print("sp=%p", (void*) regs_.REG_SP);
    regs_.REG_SP -= size;
    struct iovec local{
            .iov_base = (void*) data,
            .iov_len = size
    }, remote{
            .iov_base = (void*) regs_.REG_SP,
            .iov_len = size
    };
    if (process_vm_writev(pid_, &local, 1, &remote, 1, 0) == -1) {
        print("failed to write to remote %p from %p size=%ld", (void*) regs_.REG_SP, data, size);
        perror("stack push str");
        return false;
    }
    addr = (void*) regs_.REG_SP;
    print("string pushed to %p (size=%ld)", addr, size);
    return true;
}

bool TracedProcess::make_call(void* addr, void** result) {
    auto orig_pc = regs_.REG_IP;
    long instruction = ptrace(PTRACE_PEEKTEXT, pid_, orig_pc, nullptr);
    print("pc=%p instruction: %lx", (void*) orig_pc, instruction);
    if (ptrace(PTRACE_POKETEXT, pid_, regs_.REG_IP, CODE_FOR_CALL) == -1) {
        perror("replace code");
        return false;
    }
    regs_.REG_SP = regs_.REG_SP & (~0xf);
    regs_.REG_FUNC_POINTER = (unsigned long long) addr;
    if (!set_regs()) {
        perror("set regs for call");
        return false;
    }
    if (ptrace(PTRACE_CONT, pid_, 0, 0) == -1) {
        perror("continue for call");
        return false;
    }
    if (!wait_for_signal(SIGTRAP)) {
        return false;
    }
    if (!get_regs()) {
        perror("get regs post call");
        return false;
    }
    if (regs_.REG_IP != orig_pc + CALL_EXPECTED_OFFSET) {
        print("break on wrong position pc=%lx", regs_.REG_IP);
        return false;
    }
    if (ptrace(PTRACE_POKETEXT, pid_, orig_pc, instruction) == -1) {
        perror("restore code");
        return false;
    }
    if (result != nullptr)
        *result = (void*) regs_.REG_RETVAL;
    return true;
}

bool TracedProcess::put_arg(int pos, void* arg) {
#if defined(__x86_64__)
    switch (pos) {
        case 1:
            regs_.rdi = (unsigned long long) arg;
            return true;
        case 2:
            regs_.rsi = (unsigned long long) arg;
            return true;
        case 3:
            regs_.rdx = (unsigned long long) arg;
            return true;
        case 4:
            regs_.rcx = (unsigned long long) arg;
            return true;
        case 5:
            regs_.r8 = (unsigned long long) arg;
            return true;
        case 6:
            regs_.r9 = (unsigned long long) arg;
            return true;
        default:
            // not implemented
            return false;
    }
#elif defined(__aarch64__)
    if (pos >= 1 && pos <= 8) {
        regs_.regs[pos - 1] = (unsigned long long) arg;
        return true;
    }
    return false;
#endif
}

bool TracedProcess::put_syscall_arg(int pos, void* arg) {
#if defined(__x86_64__)
    switch (pos) {
        case 1:
            regs_.rdi = (unsigned long long) arg;
            return true;
        case 2:
            regs_.rsi = (unsigned long long) arg;
            return true;
        case 3:
            regs_.rdx = (unsigned long long) arg;
            return true;
        case 4:
            regs_.r10 = (unsigned long long) arg;
            return true;
        case 5:
            regs_.r8 = (unsigned long long) arg;
            return true;
        case 6:
            regs_.r9 = (unsigned long long) arg;
            return true;
        default:
            // not implemented
            return false;
    }
#elif defined(__aarch64__)
    if (pos >= 1 && pos <= 6) {
        regs_.regs[pos - 1] = (unsigned long long) arg;
        return true;
    }
    return false;
#endif
}

bool TracedProcess::make_syscall(int nr, void** result) {
    auto orig_pc = regs_.REG_IP;
    long instruction = ptrace(PTRACE_PEEKTEXT, pid_, orig_pc, nullptr);
    print("pc=%p instruction: %lx", (void*) orig_pc, instruction);
    if (ptrace(PTRACE_POKETEXT, pid_, regs_.REG_IP, CODE_FOR_SYSCALL) == -1) {
        perror("replace code");
        return false;
    }
    regs_.REG_SP = regs_.REG_SP & (~0xf);
    regs_.REG_SYSCALL_NR = (unsigned long long) nr;
    if (!set_regs()) {
        perror("set regs for call");
        return false;
    }
    if (ptrace(PTRACE_SINGLESTEP, pid_, 0, 0) == -1) {
        perror("continue for call");
        return false;
    }
    if (!wait_for_signal(SIGTRAP)) {
        return false;
    }
    if (!get_regs()) {
        return false;
    }
    if (ptrace(PTRACE_POKETEXT, pid_, orig_pc, instruction) == -1) {
        perror("restore code");
        return false;
    }
    if (result != nullptr)
        *result = (void*) regs_.REG_SYSCALL_RETVAL;
    return true;
}

void TracedProcess::dump_regs()  {
    if (!get_regs()) {
        perror("failed to get regs for dump");
    } else {
        print("current sp=%p, pc=%p", (void *) regs_.REG_SP, (void *) regs_.REG_IP);
    }
}

bool TracedProcess::wait_internal(bool no_hang) {
    int flags = __WALL;
    if (no_hang) flags |= WNOHANG;
    if (waitpid(pid_, &status_, flags) == -1) {
        perror("waiting");
        return false;
    }
    return true;
}

bool TracedProcess::wait_for_signal(int sig, bool no_hang) {
    if (!wait_internal(no_hang)) return false;
    if (!WIFSTOPPED(status_) || WSTOPSIG(status_) != sig) {
        auto reason = parse_status(status_);
        print("stopped by other reason: %s", reason.c_str());
        dump_siginfo(pid_);
        dump_regs();
        return false;
    }
    return true;
}
