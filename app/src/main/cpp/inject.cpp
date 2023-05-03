#include <string>
#include <string_view>
#include <cstdio>

#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <sys/wait.h>

#include "elf_util.h"
#include "pmparser.h"
#include "ptrace_utils.h"
#include "logging.h"

using namespace std::literals::string_view_literals;

bool find_linker(int pid, void* &base, std::string &path) {
    procmaps_iterator* maps = pmparser_parse(pid);
    if (maps == nullptr){
        printf("cannot parse the memory map of %d\n", pid);
        return false;
    }
    procmaps_struct* maps_tmp;
    bool found = false;
    while ((maps_tmp = pmparser_next(maps)) != nullptr) {
        if (std::string_view(maps_tmp->pathname).find("/linker") != std::string_view::npos && maps_tmp->offset == 0) {
            found = true;
            base = maps_tmp->addr_start;
            path = maps_tmp->pathname;
            print("found linker in maps, base=%p,path=%s", base, maps_tmp->pathname);
            break;
        }
    }
    pmparser_free(maps);
    return found;
}

void remote_dlopen(int pid, const std::string_view path) {
    print("dlopen %s on %d\n", path.data(), pid);
    void* linker_base;
    struct user_regs_struct regs{}, regs_backup{};
    std::string linker_path;
    if (!find_linker(pid, linker_base, linker_path)) {
        print("failed to find linker");
        return;
    }
    SandHook::ElfImg elfImg{linker_path, linker_base};
    auto dlopen_addr = elfImg.getSymbAddress("__loader_dlopen");
    print("dlopen_addr: %p", dlopen_addr);
    if (!ptrace_get_regs(pid, regs)) return;
    memcpy(&regs_backup, &regs, sizeof(struct user_regs_struct));
    void* str_addr = nullptr;
    if (!stack_push_str(pid, regs, path.data(), path.size(), str_addr)) return;
    put_arg(pid, regs, 1, str_addr);
    put_arg(pid, regs, 2, (void*) RTLD_NOW);
    put_arg(pid, regs, 3, nullptr);
    void* result = nullptr;
    if (!make_call(pid, dlopen_addr, regs, &result)) {
        print("call dlopen failed");
        return;
    }
    print("handle: %p", result);
    if (!ptrace_set_regs(pid, regs_backup)) {
        print("failed to restore regs");
    }
}

void remote_dlclose(int pid, void *handle) {
    print("dlclose %p on %d\n", handle, pid);void* linker_base;
    struct user_regs_struct regs{}, regs_backup{};
    std::string linker_path;
    if (!find_linker(pid, linker_base, linker_path)) {
        print("failed to find linker");
        return;
    }
    SandHook::ElfImg elfImg{linker_path, linker_base};
    auto dlclose_addr = elfImg.getSymbAddress("__loader_dlclose");
    print("dlclose_addr: %p", dlclose_addr);
    if (!ptrace_get_regs(pid, regs)) return;
    memcpy(&regs_backup, &regs, sizeof(struct user_regs_struct));
    put_arg(pid, regs, 1, handle);
    put_arg(pid, regs, 2, nullptr);
    if (!make_call(pid, dlclose_addr, regs, nullptr)) {
        print("call dlclose failed");
        return;
    }
    if (!ptrace_set_regs(pid, regs_backup)) {
        print("failed to restore regs");
    }
}

void print_usage() {
    print("usage:\n  open <pid> <path>\n  close <pid> <handle>");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        print_usage();
        return 1;
    }
    if (argv[1] == "open"sv) {
        auto pid = (int) strtol(argv[2], nullptr, 0);
        if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
            perror("attach");
            return 1;
        }
        remote_dlopen(pid, argv[3]);
        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
            perror("detach");
            return 1;
        }
    } else if (argv[1] == "close"sv) {
        auto pid = (int) strtol(argv[2], nullptr, 0);
        auto handle = (void*) strtoul(argv[3], nullptr, 0);
        if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
            perror("attach");
            return 1;
        }
        remote_dlclose(pid, handle);
        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
            perror("detach");
            return 1;
        }
    } else {
        print_usage();
        return 1;
    }
    return 0;
}
