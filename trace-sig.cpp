#include <iostream>

#include <sys/wait.h>
#include <unistd.h>
#include <string_view>
#include <sys/ptrace.h>
#include <cstring>
#include <string>

#include "utils.h"

using namespace std;

int fork_main(int argc, char **argv) {
    cout << "my pid=" << getpid() << endl;
    auto pid = fork();
    int status;
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        cout << "child forked" << endl;
        if (argc >= 3) {
            if (argv[2] == "pause"sv) {
                pause();
            } else if (argv[2] == "loop"sv) {
                for (;;) {
                    cout << "waiting ..." << endl;
                    sleep(1);
                }
            } else {
                cerr << "unknown arg " << argv[2] << endl;
            }
        } else {
            raise(SIGSTOP);
            // raise(SIGSTOP);
        }
        return 0;
        // exit(0xffff);
        // return 3;
    }
    cout << "forked pid " << pid << endl;
    if (waitpid(pid, &status, __WALL) == -1) {
        if (errno != EINTR) {
            perror("waitpid");
            return 1;
        }
    }
    cout << "exited status " << status << endl;
    if (WIFEXITED(status)) {
        cout << "return value " << WEXITSTATUS(status) << endl;
    } else if (WIFSIGNALED(status)) {
        cout << "exit with signal " << WTERMSIG(status) << endl;
    }
    return 0;
}

#define ON_ERROR_KILL(d, x) if ((x) == -1) { perror(d); kill(pid, SIGKILL); return 1; }
int trace_main(int pid, bool use_attach) {
    int status;
    ON_ERROR_KILL("attach", ptrace(use_attach ? PTRACE_ATTACH : PTRACE_SEIZE, pid, nullptr, nullptr))
    int stop_sig = 0;
    for (;;) {
        string cmd;
        siginfo_t siginfo;
        cout << "waiting ..." << endl;
        if (waitpid(pid, &status, __WALL) != -1) {
            if (WIFSTOPPED(status)) {
                auto sig = WSTOPSIG(status);
                cout << "process stopped by signal SIG" << sigabbrev_np(sig) << " (" << sig << "), status=" << hex << status ;
                cout << dec << ", event=" << parse_ptrace_event(status) << endl;
                bool is_stop = (status >> 16) == PTRACE_EVENT_STOP;
                if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &siginfo) == -1) {
                    perror("get siginfo");
                } else {
                    cout << "signo: " << siginfo.si_signo;
                    cout << ", si_code:" << parse_si_code(siginfo.si_code) << "(" <<  siginfo.si_code << ")" << endl;
                    stop_sig = siginfo.si_signo;
                }
                cin >> cmd;
                if (cmd == "q") {
                    cout << "exit" << endl;
                    break;
                }
                if (!is_stop) {
                    cout << "inject signal SIG" << (stop_sig > 0 ? sigabbrev_np(stop_sig) : "0") << endl;
                    if (cmd == "0") {
                        cout << "inject 0 instead" << endl;
                        stop_sig = 0;
                    } else if (cmd == "s") {
                        cout << "inject SIGSTOP instead" << endl;
                        stop_sig = SIGSTOP;
                    } else if (cmd == "n") {
                        cout << "not inject" << endl;
                        stop_sig = 0;
                        continue;
                    }
                    ON_ERROR_KILL("cont", ptrace(PTRACE_CONT, pid, nullptr, stop_sig))
                    stop_sig = 0;
                } else if ((status >> 8) == (SIGTRAP | PTRACE_EVENT_STOP << 8)) {
                    cout << "unknown trap" << endl;
                    ON_ERROR_KILL("cont", ptrace(PTRACE_CONT, pid, nullptr, 0))
                } else {
                    cout << "listen on stop" << endl;
                    ON_ERROR_KILL("listen", ptrace(PTRACE_LISTEN, pid, nullptr, nullptr))
                }
            } else if (WIFEXITED(status)) {
                cout << "exited with result " << WEXITSTATUS(status) << endl;
                return 0;
            } else if (WIFSIGNALED(status)) {
                cout << "exited with signal " << WTERMSIG(status) << endl;
                return 0;
            } else {
                cout << "unknown status " << status << endl;
            }
        } else {
            perror("waitpid");
            break;
        }
    }
    ON_ERROR_KILL("detach", ptrace(PTRACE_DETACH, pid, nullptr, stop_sig))
    return 0;
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        cerr << "usage " << argv[0] << " <fork|trace>" << endl;
        return 1;
    }
    if (argv[1] == "fork"sv) {
        return fork_main(argc, argv);
    } else if (argv[1] == "trace"sv) {
        if (argc >= 3) {
            auto pid = (int) strtol(argv[2], nullptr, 0);
            bool use_attach = argc >= 4 && argv[3] == "attach"sv;
            return trace_main(pid, use_attach);
        } else {
            cerr << "invalid argument" << endl;
            return 1;
        }
    } else {
        return 1;
    }
}
