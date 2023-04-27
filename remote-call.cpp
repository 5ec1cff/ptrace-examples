#include <iostream>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cstring>
#include <string_view>
#include <sys/user.h>
#include <sys/uio.h>

#include "pmparser.h"
#include <dlfcn.h>

using namespace std;

const char MSG[] = "Hello world!";

#define ON_ERROR_KILL(d, x) if ((x) == -1) { perror(d); kill(pid, SIGKILL); return; }

void remote_call(int pid) {
    void* libc_base = nullptr;
    auto puts_off = 0x80ed0;
    auto addr = dlsym(RTLD_NEXT, "puts");
    cout << addr << endl;
    cin.get();
    procmaps_iterator* maps = pmparser_parse(pid);
    if (maps == nullptr){
        cerr << "cannot parse the memory map of " << pid << endl;
        return;
    }
    procmaps_struct* maps_tmp;
    while ((maps_tmp = pmparser_next(maps)) != nullptr) {
        if (string_view(maps_tmp->pathname).find("libc.so.6") != string_view::npos && maps_tmp->offset == 0) {
            libc_base = maps_tmp->addr_start;
            cout << "found libc in maps, base=" << hex << libc_base << endl;
            break;
        }
    }
    pmparser_free(maps);
    if (!libc_base) {
        cout << "libc not found" << endl;
        return;
    }

    cin.get();

    struct user_regs_struct regs{}, regs_backup{};
    long ins_back;
    int status;

    ON_ERROR_KILL("get regs", ptrace(PTRACE_GETREGS, pid, nullptr, &regs))
    memcpy(&regs_backup, &regs, sizeof(struct user_regs_struct));
    ins_back = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, nullptr);
    cout << "rsp=" << hex << regs.rsp << ",rip=" << hex << regs.rip << ",backup instructions:" << hex << ins_back << endl;
    cin.get();
    ON_ERROR_KILL("poke", ptrace(PTRACE_POKETEXT, pid, regs.rip, 0xccd0ff));
    auto arg = (void*) (regs.rsp - sizeof(MSG));
    struct iovec local{
            .iov_base = (void*) MSG,
            .iov_len = sizeof(MSG)
    }, remote{
            .iov_base = arg,
            .iov_len = sizeof(MSG)
    };
    ON_ERROR_KILL("write memory", process_vm_writev(pid, &local, 1, &remote, 1, 0))
    cin.get();
    regs.rax = (long long int) libc_base + puts_off;
    regs.rdi = (long long int) arg;
    regs.rsp -= sizeof(MSG);
    ON_ERROR_KILL("set regs", ptrace(PTRACE_SETREGS, pid, nullptr, &regs));
    ON_ERROR_KILL("cont", ptrace(PTRACE_CONT, pid, nullptr, nullptr));
    ON_ERROR_KILL("waitpid", waitpid(pid, &status, __WALL));
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        cout << "stopped by other signal SIG" << sigabbrev_np(WSTOPSIG(status))  << endl;
        ON_ERROR_KILL("get regs", ptrace(PTRACE_GETREGS, pid, nullptr, &regs))
        cout << "rip=" << hex << regs.rip << "rsp=" << hex << regs.rsp << endl;
        if (WSTOPSIG(status) == SIGSEGV) {
            siginfo_t siginfo;
            ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
            cout << "fault addr:" << hex << siginfo.si_addr << endl;
        }
        kill(pid, SIGKILL);
        return;
    }
    ON_ERROR_KILL("get regs", ptrace(PTRACE_GETREGS, pid, nullptr, &regs))
    cout << "rip=" << hex << regs.rip << endl;
    ON_ERROR_KILL("restore text", ptrace(PTRACE_POKETEXT, pid, regs_backup.rip, ins_back));
    ON_ERROR_KILL("restore regs", ptrace(PTRACE_SETREGS, pid, nullptr, &regs_backup));
    cin.get();
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        cerr << "usage: " << argv[0] << " <pid>" << endl;
        return 1;
    }
    auto ipid = (int) strtol(argv[1], nullptr, 0);
    cout << "tracing pid " << ipid << endl;
    int status;
    ptrace(PTRACE_ATTACH, ipid, nullptr, nullptr);
    for (;;) {
        auto pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno != EINTR) {
                perror("waitpid");
                return 1;
            }
            continue;
        }
        if (WIFSTOPPED(status)) {
            int orig_sig = WSTOPSIG(status);
            cout << pid << " stopped by SIG" << sigabbrev_np(orig_sig) << "(" << orig_sig << ")" << endl;
            remote_call(pid);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            cout << "detached" << endl;
            break;
        } else if (WIFEXITED(status)) {
            cout << pid << " exited with " << WEXITSTATUS(status) << endl;
            break;
        } else {
            cout << pid << " unknown status " << status << endl;
        }
    }
    return 0;
}
