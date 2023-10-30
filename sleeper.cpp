#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <csignal>
#include <string_view>

using namespace std::string_view_literals;

int main(int argc, char **argv) {
    if (argc <= 1) {
        printf("usage: %s [time]", argv[0]);
        return 1;
    }
    if (argc >= 3 && argv[2] == "--block-cont"sv) {
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGCONT);
        sigprocmask(SIG_BLOCK, &sigset, nullptr);
        printf("blocked SIGCONT\n");
    }
    auto t = strtol(argv[1], nullptr, 0);
    printf("pid=%d sleep for %ld s and stop\n", getpid(), t);
    sleep(t);
    printf("slept\n");
    raise(SIGSTOP);
    for (int i = 0; i < 10; i++) {
        printf("print %d\n", i);
        sleep(1);
    }
    printf("exit\n");
    return 0;
}
