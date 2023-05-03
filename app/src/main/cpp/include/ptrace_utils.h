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

void dump_siginfo(int pid);

const char* parse_ptrace_event(int status);
const char* parse_si_code(int si_code);
std::string parse_status(int status);
