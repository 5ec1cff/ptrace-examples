#define _GNU_SOURCE

#include <iostream>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstring>
#include <sys/uio.h>
#include <csignal>

const unsigned char code[] = {
        0x48, 0xc7, 0xc0, 0x1, 0x0, 0x0, 0x0, 0x48,
        0xc7, 0xc7, 0x1, 0x0, 0x0, 0x0, 0x48, 0x8d,
        0x35, 0xa, 0x0, 0x0, 0x0, 0x48, 0xc7, 0xc2,
        0xd, 0x0, 0x0, 0x0, 0xf, 0x5, 0xcc, 0x48,
        0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f,
        0x72, 0x6c, 0x64, 0xa
};

using namespace std;

#define ON_ERROR_KILL(d, x) if ((x) == -1) { perror(d); kill(pid, SIGKILL); return; }

void inject(int pid) {
    struct user_regs_struct regs{}, regs_backup{};
    int status;
    ON_ERROR_KILL("execve single step", ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr));
    ON_ERROR_KILL("waitpid", waitpid(pid, &status, __WALL));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        cout << "stopped by other signal SIG" << sigabbrev_np(WSTOPSIG(status))  << endl;
        kill(pid, SIGKILL);
        return;
    }

    ON_ERROR_KILL("set options", ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD));

    ON_ERROR_KILL("next syscall", ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr));
    ON_ERROR_KILL("waitpid", waitpid(pid, &status, __WALL));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
        cout << "stopped by other non-syscall stop signal SIG" << sigabbrev_np(WSTOPSIG(status)) << endl;
        kill(pid, SIGKILL);
        return;
    }
    ON_ERROR_KILL("get regs", ptrace(PTRACE_GETREGS, pid, nullptr, &regs));
    memcpy(&regs_backup, &regs, sizeof(struct user_regs_struct));
    cout << "rip=" << hex << regs.rip << " rax=" << hex << regs.rax << " orig_rax=" << dec << regs.orig_rax << endl;
    cin.get();

    cout << "exec mmap" << endl;
    regs.orig_rax = SYS_mmap;
    regs.rdi = 0;
    regs.rsi = sizeof(code);
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;
    regs.r8 = 0xffffffff; // -1
    regs.r9 = 0;
    ON_ERROR_KILL("set regs", ptrace(PTRACE_SETREGS, pid, nullptr, &regs));
    ON_ERROR_KILL("next syscall", ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr));
    ON_ERROR_KILL("waitpid", waitpid(pid, &status, __WALL));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
        cout << "stopped by other non-syscall stop signal SIG" << sigabbrev_np(WSTOPSIG(status)) << endl;
        kill(pid, SIGKILL);
        return;
    }
    ON_ERROR_KILL("get regs", ptrace(PTRACE_GETREGS, pid, nullptr, &regs));
    cout << "mmap return:" << hex << regs.rax << endl;
    cin.get();

    cout << "write code and run" << endl;
    struct iovec local{
            .iov_base = (void*) code,
            .iov_len = sizeof(code)
    }, remote{
            .iov_base = (void*) regs.rax,
            .iov_len = sizeof(code)
    };
    ON_ERROR_KILL("write memory", process_vm_writev(pid, &local, 1, &remote, 1, 0));
    regs.rip = regs.rax;
    ON_ERROR_KILL("set regs", ptrace(PTRACE_SETREGS, pid, nullptr, &regs));
    ON_ERROR_KILL("cont", ptrace(PTRACE_CONT, pid, nullptr, nullptr));
    ON_ERROR_KILL("waitpid", waitpid(pid, &status, __WALL));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        cout << "stopped by other signal SIG" << sigabbrev_np(WSTOPSIG(status))  << endl;
        kill(pid, SIGKILL);
        return;
    }
    cin.get();


    cout << "replay syscall" << endl;
    regs_backup.rip -= 2;
    regs_backup.rax = regs_backup.orig_rax;
    ON_ERROR_KILL("set regs", ptrace(PTRACE_SETREGS, pid, nullptr, &regs_backup));

    int i = 2;
    while (i--) {
        ON_ERROR_KILL("next syscall", ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr));
        ON_ERROR_KILL("waitpid", waitpid(pid, &status, __WALL));
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            cout << "stopped by other non-syscall stop signal SIG" << sigabbrev_np(WSTOPSIG(status)) << endl;
            kill(pid, SIGKILL);
            return;
        }
        ON_ERROR_KILL("get regs", ptrace(PTRACE_GETREGS, pid, nullptr, &regs));
        cout << "rip=" << hex << regs.rip << " rax=" << hex << regs.rax << " orig_rax=" << dec << regs.orig_rax << endl;
    }

    ON_ERROR_KILL("cont", ptrace(PTRACE_CONT, pid, nullptr, nullptr));
}

int main() {
    auto pid = fork();
    int status;
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        ptrace(PTRACE_TRACEME);
        cout << "child forked" << endl;
        raise(SIGTRAP);
        cout << "trapped" << endl;
        execlp("ls", "ls", nullptr);
        perror("execve");
        return 1;
    }
    cout << "forked pid " << pid << endl;
    bool first_stop = true;
    for (;;) {
        if (waitpid(pid, &status, __WALL) == -1) {
            if (errno != EINTR) {
                perror("waitpid");
                return 1;
            }
        }
        if (WIFSTOPPED(status)) {
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
                cout << "stopped at execve" << endl;
                inject(pid);
                continue;
            } else {
                cout << "stopped by SIG" << sigabbrev_np(WSTOPSIG(status)) << "(" << WSTOPSIG(status) << ")" << endl;
                if (first_stop) {
                    ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEEXEC);
                    first_stop = false;
                }
            }
            cin.get();
            cout << "continue" << endl;
            ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        } else if (WIFEXITED(status)) {
            cout << "exited with " << WEXITSTATUS(status) << endl;
            break;
        } else {
            cout << "unknown status " << status << endl;
        }
    }
    return 0;
}
