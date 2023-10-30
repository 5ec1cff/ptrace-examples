#include <iostream>

#include <sys/wait.h>
#include <unistd.h>
#include <string_view>
#include <sys/ptrace.h>
#include <cstring>
#include <string>

#include "utils.h"

using namespace std;

static bool is_signaled = false;

static void sig_handler(int s) {
    if (s == SIGCHLD) {
        is_signaled = true;
    }
}

void parse_signal(int status, int si_code) {
    cout << "received status " << hex << status;
    if (WIFEXITED(status)) {
        cout << "(exited)" << endl;
        cout << "return=" << dec << WEXITSTATUS(status) << endl;
    } else if (WIFSIGNALED(status)) {
        cout << "(signaled)" << endl;
        cout << "signal=" << sigabbrev_np(WTERMSIG(status)) << dec << "(" << WTERMSIG(status) << ")" << endl;
    } else if (WIFSTOPPED(status)) {
        cout << "(stopped)" << endl;
        auto stop_sig = WSTOPSIG(status);
        cout << "signal=" << sigabbrev_np(stop_sig) << dec << "(" << stop_sig << ")" << endl;
        cout << "event=" << parse_ptrace_event(status) << endl;
        cout << "si_code=" << si_code << "(" << parse_si_code(si_code) << ")" << endl;
    }
}

int trace_main(int pid) {
    struct sigaction act{};
    act.sa_handler = sig_handler;
    if (sigaction(SIGINT, &act, 0) == -1) {
        perror("sigaction SIGINT");
    }
    act.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &act, 0) == -1) {
        perror("sigaction SIGCHLD");
    }
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
        perror("seize");
        return 1;
    }
    cout << "attach to " << pid << endl;
    for (;;) {
        string cmd;
        cout << pid << "> ";
        cin >> cmd;
        if (cmd == "q") {
            cout << "exit" << endl;
            return 0;
        } else if (cmd == "d") {
            int sig;
            cin >> sig;
            cout << "detach with " << sig << endl;
            if (ptrace(PTRACE_DETACH, pid, 0, sig) == -1) {
                perror("detach");
            }
            cout << "exit" << endl;
            return 0;
        } else if (cmd == "i") {
            if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
                perror("interrupt");
            } else {
                cout << pid << " has been interrupted" << endl;
            }
        } else if (cmd == "l") {
            if (ptrace(PTRACE_LISTEN, pid, 0, 0) == -1) {
                perror("listen");
            } else {
                cout << pid << " has been listened" << endl;
            }
        } else if (cmd == "c") {
            int sig;
            cin >> sig;
            cout << "continue with signal " << sig << endl;
            if (ptrace(PTRACE_CONT, pid, 0, sig) == -1) {
                perror("cont");
            } else {
                cout << pid << " has been continued" << endl;
            }
        } else if (cmd == "w") {
            cout << "waiting ..." << endl;
            int status;
            for (;;) {
                if (waitpid(pid, &status, __WALL) == -1) {
                    if (errno == EINTR) {
                        cout << "waiting has been interrupted" << endl;
                        break;
                    } else {
                        perror("wait");
                    }
                } else {
                    siginfo_t siginfo;
                    int si_code = 0;
                    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
                        perror("get siginfo");
                    } else si_code = siginfo.si_code;
                    parse_signal(status, si_code);
                    break;
                }
            }
        } else if (cmd == "W") {
            int status;
            auto wait_pid = waitpid(pid, &status, __WALL | WNOHANG);
            if (wait_pid == -1) {
                perror("wait");
            } else if (wait_pid == 0) {
                cout << "nothing to wait" << endl;
            } else {
                siginfo_t siginfo;
                int si_code = 0;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
                    perror("get siginfo");
                } else si_code = siginfo.si_code;
                parse_signal(status, si_code);
            }
        } else if (cmd == "p") {
            cout << (is_signaled ? "true" : "false") << endl;
            is_signaled = false;
        } else if (cmd == "k") {
            int sig;
            cin >> sig;
            cout << "kill with signal " << sig << endl;
            if (tgkill(pid, pid, sig) == -1) perror("tgkill");
        } else if (cmd == "C") {
            cout << "continue if stopped" << endl;
            int status;
            auto wait_pid = waitpid(pid, &status, __WALL | WNOHANG);
            if (wait_pid == -1) {
                perror("wait");
            } else if (wait_pid == 0) {
                cout << "nothing to wait, maybe process is not stopped" << endl;
            } else {
                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP && (status>>16 == PTRACE_EVENT_STOP)) {
                    cout << "inject SIGCONT" << endl;
                    if (tgkill(pid, pid, SIGCONT)) perror("tgkill cont");
                    ptrace(PTRACE_CONT, pid, 0, 0);
                    wait_pid = waitpid(pid, &status, __WALL);
                    if (wait_pid == -1) perror("wait");
                    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && (status>>16 == PTRACE_EVENT_STOP)) {
                        cout << "trap c 0" << endl;
                        ptrace(PTRACE_CONT, pid, 0, 0);
                    } else {
                        cout << "trap not received:" << WSTOPSIG(status) << endl;
                        continue;
                    }
                    wait_pid = waitpid(pid, &status, __WALL);
                    if (wait_pid == -1) perror("wait");
                    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGCONT) {
                        cout << "cont c 0" << endl;
                        ptrace(PTRACE_CONT, pid, 0, 0);
                    }
                } else {
                    cout << "process is not stopped" << endl;
                    siginfo_t siginfo;
                    int si_code = 0;
                    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
                        perror("get siginfo");
                    } else si_code = siginfo.si_code;
                    parse_signal(status, si_code);
                }
            }
        } else {
            cout << "invalid command " << cmd << endl;
        }
    }
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        cerr << "usage: " << argv[0] << " <pid>" << endl;
        return 1;
    }
    cout << "Command:" << endl;
    cout << "  d <sig>: detach with signal and exit" << endl;
    cout << "  i: interrupt" << endl;
    cout << "  l: listen" << endl;
    cout << "  w: wait (Ctrl-C to stop)" << endl;
    cout << "  c <sig>: continue with signal <sig>" << endl;
    cout << "  W: wait not hang" << endl;
    cout << "  q: exit" << endl;
    cout << "  p: peek SIGCHLD value" << endl;
    cout << "  k <sig>: kill with signal" << endl;
    cout << "  C: continue process if stopped" << endl;
    auto pid = (int) strtol(argv[1], nullptr, 0);
    return trace_main(pid);
}

/**
 * stop-before-seize:
 * ./sleeper 0
 * ./trace-repl pid
 * w -> SIGSTOP + PTRACE_EVENT_STOP
 * c 0 -> process continued during tracing (stop after detaching)
 * k 18 -> send SIGCONT
 *  c 0, w -> SIGTRAP + PTRACE_EVENT_STOP
 *  (if SIGCONT is not blocked) c 0, w -> SIGCONT
 *  c 0, w -> process continued correctly
 *
 * stop-after-seize:
 * ./sleeper 5
 * ./trace-repl pid
 * <waiting for SIGSTOP>
 * w -> SIGSTOP + SI_TKILL
 * c 0 -> process continued correctly (SIGSTOP was suppressed)
 * c 19 -> stop-before-seize
 *
 * stop and detach after exec:
 * ./sleeper 0 --exec
 * ./trace-repl pid
 * <waiting for SIGTRAP + PTRACE_EVENT_EXEC>
 * k 19
 * c 0, w -> SIGSTOP + SI_TKILL
 * d 19 -> process is stopped and detached
 */
