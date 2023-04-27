#include <iostream>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <set>

using namespace std;

int main(int argc, char **argv) {
    if (argc <= 1) {
        cerr << "usage: " << argv[0] << " <pid>" << endl;
        return 1;
    }
    auto ipid = (int) strtol(argv[1], nullptr, 0);
    cout << "tracing pid " << ipid << endl;
    int status;
    ptrace(PTRACE_ATTACH, ipid, nullptr, nullptr);
    bool first_stop = true;
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
                cout << pid << " stopped at execve" << endl;
            } else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
                long msg;
                ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg);
                cout << pid << " stopped at fork, child pid=" << msg << endl;
            } else {
                orig_sig = WSTOPSIG(status);
                cout << pid << " stopped by SIG" << sigabbrev_np(orig_sig) << "(" << orig_sig << ")" << endl;
                if (first_stop) {
                    ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEFORK);
                    first_stop = false;
                }
            }
            if (pids.find(pid) == pids.end()) {
                pids.insert(pid);
                cout << "new process " << pid << " added" << endl;
                ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEEXEC);
            }
            cin.get();
            cout << pid << " continue" << endl;
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
