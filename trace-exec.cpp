#include <iostream>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>

using namespace std;

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
            } else {
                cout << "stopped by " << WSTOPSIG(status) << endl;
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
