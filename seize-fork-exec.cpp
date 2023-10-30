#include <iostream>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <set>
#include <sys/user.h>

#include "utils.h"

using namespace std;

int main(int argc, char **argv) {
    if (argc <= 1) {
        cerr << "usage: " << argv[0] << " <pid>" << endl;
        return 1;
    }
    auto ipid = (int) strtol(argv[1], nullptr, 0);
    cout << "tracing pid " << ipid << endl;
    int status;
    ptrace(PTRACE_SEIZE, ipid, nullptr, PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC);
    set<int> pids{};
    pids.insert(ipid);
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
            int orig_sig = 0;
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
                // detach after execve and leave it stopped
                cout << pid << " stopped at execve" << endl;
                auto rip = ptrace(PTRACE_PEEKUSER, pid, 8 * REG_RIP, 0);
                cout << "current rip " << hex << rip << dec << endl;
                kill(pid, SIGSTOP);
                if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
                    perror("cont");
                }
                waitpid(pid, &status, 0);
                cout << pid << " status=" << status << endl;
                rip = ptrace(PTRACE_PEEKUSER, pid, 8 * REG_RIP, 0);
                cout << "current rip " << hex << rip << dec << endl;
                if (ptrace(PTRACE_DETACH, pid, 0, SIGSTOP)) {
                    perror("detach");
                } else {
                    cout << "detached pid " << pid << endl;
                    pids.erase(pid);
                }
                continue;
            } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
                long msg;
                ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg);
                cout << pid << " stopped at fork, child pid=" << msg << endl;
            } else {
                orig_sig = WSTOPSIG(status);
                cout << pid << " stopped by SIG" << sigabbrev_np(orig_sig) << "(" << orig_sig << ")" << endl;
                cout << "event: " << parse_ptrace_event(status) << endl;
            }
            if (pids.find(pid) == pids.end()) {
                pids.insert(pid);
                cout << "new process " << pid << " added" << endl;
                ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEEXEC);
            }
            cin.get();
            cout << pid << " continue with " << orig_sig << endl;
            ptrace(PTRACE_CONT, pid, nullptr, (void*) orig_sig);
        } else if (WIFEXITED(status)) {
            cout << pid << " exited with " << WEXITSTATUS(status) << endl;
            pids.erase(pid);
        } else {
            cout << pid << " unknown status " << status << endl;
        }
        if (pids.empty()) {
            cout << "all processes exited" << endl;
            break;
        }
    }
    return 0;
}
