#include <string>
#include <string_view>
#include <cstdio>

#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <syscall.h>
#include <sys/prctl.h>

#include "elf_util.h"
#include "pmparser.h"
#include "ptrace_utils.h"
#include "logging.h"
#include "trace.h"

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
    TracedProcess proc{};
    void* linker_base;
    if (!proc.attach_and_wait(pid)) {
        print("failed to wait");
        return;
    }
    std::string linker_path;
    if (!find_linker(pid, linker_base, linker_path)) {
        print("failed to find linker");
        return;
    }
    SandHook::ElfImg elfImg{linker_path, linker_base};
    auto dlopen_addr = elfImg.getSymbAddress("__loader_dlopen");
    print("dlopen_addr: %p", dlopen_addr);
    if (!proc.get_regs()) return;
    proc.backup_regs();
    void* str_addr = nullptr;
    if (!proc.stack_push_str(path, str_addr)) return;
    proc.put_arg(1, str_addr);
    proc.put_arg(2, (void*) RTLD_NOW);
    proc.put_arg(3, nullptr);
    void* result = nullptr;
    if (!proc.make_call(dlopen_addr, &result)) {
        print("call dlopen failed");
        return;
    }
    print("handle: %p", result);
    proc.restore_regs();
    if (!proc.set_regs()) {
        print("failed to restore regs");
    }
    if (!proc.detach()) {
        print("failed to detach");
    }
}

void remote_dlclose(int pid, void *handle) {
    print("dlclose %p on %d\n", handle, pid);void* linker_base;
    TracedProcess proc{};
    if (!proc.attach_and_wait(pid)) {
        print("failed to wait");
        return;
    }
    std::string linker_path;
    if (!find_linker(pid, linker_base, linker_path)) {
        print("failed to find linker");
        return;
    }
    SandHook::ElfImg elfImg{linker_path, linker_base};
    auto dlclose_addr = elfImg.getSymbAddress("__loader_dlclose");
    print("dlclose_addr: %p", dlclose_addr);
    if (!proc.get_regs()) return;
    proc.backup_regs();
    proc.put_arg(1, handle);
    proc.put_arg(2, nullptr);
    if (!proc.make_call(dlclose_addr, nullptr)) {
        print("call dlclose failed");
        return;
    }
    proc.restore_regs();
    if (!proc.set_regs()) {
        print("failed to restore regs");
    }
    if (!proc.detach()) {
        print("failed to detach");
    }
}

void remote_get_dumpable(int pid) {
    print("get dumpable for %d", pid);
    TracedProcess proc{};
    if (!proc.attach_and_wait(pid)) {
        print("failed to wait");
        return;
    }
    if (!proc.get_regs()) return;
    proc.backup_regs();
    proc.put_syscall_arg(1, (void*) PR_GET_DUMPABLE);
    proc.put_syscall_arg(2, nullptr);
    proc.put_syscall_arg(3, nullptr);
    proc.put_syscall_arg(4, nullptr);
    proc.put_syscall_arg(5, nullptr);
    void* result;
    if (!proc.make_syscall(SYS_prctl, &result)) {
        print("failed to prctl");
    }
    print("dumpable:%p", result);
    proc.restore_regs();
    if (!proc.set_regs()) {
        print("failed to restore regs");
    }
    if (!proc.detach()) {
        print("failed to detach");
    }
}

void remote_set_dumpable(int pid, int dumpable) {
    print("set dumpable to %d for %d", dumpable, pid);
    TracedProcess proc{};
    if (!proc.attach_and_wait(pid)) {
        print("failed to wait");
        return;
    }
    if (!proc.get_regs()) return;
    proc.backup_regs();
    proc.put_syscall_arg(1, (void*) PR_SET_DUMPABLE);
    proc.put_syscall_arg(2, (void*) dumpable);
    proc.put_syscall_arg(3, nullptr);
    proc.put_syscall_arg(4, nullptr);
    proc.put_syscall_arg(5, nullptr);
    void* result;
    if (!proc.make_syscall(SYS_prctl, &result)) {
        print("failed to prctl");
    }
    print("result:%p", result);
    proc.restore_regs();
    if (!proc.set_regs()) {
        print("failed to restore regs");
    }
    if (!proc.detach()) {
        print("failed to detach");
    }
}

void print_usage() {
    print("usage:");
    print("  open <pid> <path>");
    print("  close <pid> <handle>");
    print("  get-dumpable <pid>");
    print("  set-dumpable <pid> <dumpable>");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    if (argv[1] == "open"sv) {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        auto pid = (int) strtol(argv[2], nullptr, 0);
        remote_dlopen(pid, argv[3]);
    } else if (argv[1] == "close"sv) {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        auto pid = (int) strtol(argv[2], nullptr, 0);
        auto handle = (void *) strtoul(argv[3], nullptr, 0);
        remote_dlclose(pid, handle);
    } else if (argv[1] == "get-dumpable"sv) {
        if (argc != 3) {
            print_usage();
            return 1;
        }
        auto pid = (int) strtol(argv[2], nullptr, 0);
        remote_get_dumpable(pid);
    }  else if (argv[1] == "set-dumpable"sv) {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        auto pid = (int) strtol(argv[2], nullptr, 0);
        auto dumpable = (int) strtol(argv[3], nullptr, 0);
        remote_set_dumpable(pid, dumpable);
    } else {
        print_usage();
        return 1;
    }
    return 0;
}
