#pragma once
#include <string_view>

#include "ptrace_utils.h"
#include "logging.h"

#if defined(__x86_64__)
#define REG_SP rsp
#define REG_IP rip
#elif defined(__aarch64__)
#define REG_SP sp
#define REG_IP pc
#elif defined(__arm__)
#define REG_SP uregs[13]
#define REG_IP uregs[15]
#endif

class TracedProcess {
private:
    int pid_ = -1;
    int status_;
    struct user_regs_struct regs_backup_{};

    bool wait_internal(bool no_hang);
    bool peek_memory(void *addr, unsigned long words[], size_t size) const;
    bool poke_memory(void *addr, const unsigned long words[], size_t size) const;
public:
    struct user_regs_struct regs_{};

    int get_pid() const {
        return pid_;
    }

    int get_status() const {
        return status_;
    }

    bool attach(int pid);
    bool detach();
    bool attach_and_wait(int pid);
    bool stack_push_str(const std::string_view &str, void* &addr);
    bool make_call(void* addr, void** result);
    bool put_arg(int pos, void* arg);
    bool put_syscall_arg(int pos, void* arg);
    bool get_regs();
    bool set_regs(struct user_regs_struct &new_regs);
    bool set_regs();
    bool make_syscall(int nr, void** result);
    void dump_regs();
    void backup_regs() {
        regs_backup_ = regs_;
    }
    void restore_regs() {
        regs_ = regs_backup_;
    }
    bool wait_for_signal(int sig, bool no_hang = false);
};

