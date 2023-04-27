#define _GNU_SOURCE

#include <iostream>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <sys/uio.h>
#include <sys/mman.h>
#include <csignal>
#include <fcntl.h>

using namespace std;

const char MSG[] = "Hello,world!";

void write_with_ptrace_pokedata(int pid, void *addr, const char *src, size_t len) {
    cout << "write " << (void*) src << ":" << len << " to " << addr << " with ptrace pokedata" << endl;
    size_t rest = len;
    while (rest > sizeof(long)) {
        if (ptrace(PTRACE_POKEDATA, pid, addr, *((long*) src)) == -1) {
            perror("poketext");
            return;
        }
        addr += sizeof(long);
        src += sizeof(long);
        rest -= sizeof(long);
    }
    long word = 0;
    memcpy(&word, src, rest);
    if (ptrace(PTRACE_POKEDATA, pid, addr, word) == -1) {
        perror("poketext");
        return;
    }
}

void write_with_process_vm_writev(int pid, void *addr, const char *src, size_t len) {
    cout << "write " << (void*) src << ":" << len << " to " << addr << " with process_vm_writev" << endl;
    struct iovec local{
            .iov_base = (void*) src,
            .iov_len = len
    }, remote{
            .iov_base = addr,
            .iov_len = len
    };
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == -1) {
        perror("process_vm_writev");
    }
}

int main() {
    auto sz = getpagesize();
    int fd = open("test", O_RDWR | O_CREAT);
    if (fd < 0) {
        perror("open rdwr");
        return 1;
    }
    ftruncate(fd, sz*3);
    close(fd);
    fd = open("test", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open rdonly");
        return 1;
    }
    char *addr1 = (char*)mmap(nullptr, sz * 3, PROT_NONE, MAP_PRIVATE, fd, 0);
    char *addr2 = addr1 + sz;
    close(fd);
    cout << "addr1=" << (void*) addr1 << endl;
    cout << "addr2=" << (void*) addr2 << endl;
    cout << "grep -E '" << hex << (long) addr1 << "-|" << hex << (long) addr2 << "' /proc/" << dec << getpid() << "/smaps -A 22" << endl;
    cin.get();
    mprotect(addr1, sz, PROT_READ);
    mprotect(addr2, sz, PROT_READ);
    auto pid = fork();
    int status;
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        ptrace(PTRACE_TRACEME);
        cout << "child forked" << endl;
        raise(SIGTRAP);
        cout << "addr1:" << addr1 << endl;
        cout << "addr2:" << addr2 << endl;
        cout << "trapped" << endl;
        return 0;
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
            cout << "stopped by " << WSTOPSIG(status) << endl;
            if (first_stop) {
                cin.get();
                write_with_ptrace_pokedata(pid, (void*)addr1, MSG, sizeof(MSG));
                write_with_process_vm_writev(pid, (void*)addr2, MSG, sizeof(MSG));
                first_stop = false;
            } else {
                if (WSTOPSIG(status) == SIGSTOP) {
                    cout << "detach" << endl;
                    ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);
                    continue;
                }
            }
            cin.get();
            cout << "continue" << endl;
            kill(pid, SIGSTOP);
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
