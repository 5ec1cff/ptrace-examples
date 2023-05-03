#pragma once

#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <csignal>
#include <sstream>

#ifdef __arm__
#define user_regs_struct user_regs
#endif

// --- architecture-specific functions ---
bool stack_push_str(
        int pid,
        struct user_regs_struct &regs,
        const char *str,
        size_t size,
        void* &addr);
bool make_call(int pid, void* addr, struct user_regs_struct &regs, void** result);
bool put_arg(int pid, struct user_regs_struct &regs, int pos, void* arg);
bool ptrace_get_regs(int pid, struct user_regs_struct &regs);
bool ptrace_set_regs(int pid, const struct user_regs_struct &regs);

bool put_syscall_arg(int pid, struct user_regs_struct &regs, int pos, void* arg);
bool make_syscall(int pid, int nr, struct user_regs_struct &regs, void** result);
void dump_regs(int pid);

// --- all-architecture functions ---
void dump_siginfo(int pid);
void wait_for_signal(int pid, int sig);

const char* parse_ptrace_event(int status);
const char* parse_si_code(int si_code);
std::string parse_status(int status);
