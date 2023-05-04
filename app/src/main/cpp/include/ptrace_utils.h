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
#define ARM_IS_THUMB(regs) (((regs).ARM_cpsr & (1 << 5)) != 0)
// #define ARM_SET_THUMB(regs) ((regs).ARM_cpsr |= (1 << 5))
// #define ARM_UNSET_THUMB(regs) ((regs).ARM_cpsr &= ~(1 << 5))
#endif

void dump_siginfo(int pid);

const char* parse_ptrace_event(int status);
const char* parse_si_code(int si_code);
std::string parse_status(int status);
