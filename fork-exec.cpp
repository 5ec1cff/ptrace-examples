#include <iostream>

#include <sys/wait.h>
#include <unistd.h>

using namespace std;

int main() {
    cout << "my pid=" << getpid() << ",press enter to fork and exec" << endl;
    cin.get();
    auto pid = fork();
    int status;
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        cout << "child forked" << endl;
        execlp("ls", "ls", nullptr);
        perror("execve");
        return 1;
    }
    cout << "forked pid " << pid << endl;
    if (waitpid(pid, &status, __WALL) == -1) {
        if (errno != EINTR) {
            perror("waitpid");
            return 1;
        }
    }
    if (WIFEXITED(status)) {
        cout << "exited with " << WEXITSTATUS(status) << endl;
    } else {
        cout << "unknown status " << status << endl;
    }
    return 0;
}
