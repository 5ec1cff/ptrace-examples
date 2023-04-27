cmake_minimum_required(VERSION 3.22.1)
project(ptrace_learn)

set(CMAKE_CXX_STANDARD 20)

add_executable(trace-exec trace-exec.cpp)
add_executable(fork-exec fork-exec.cpp)
add_executable(trace-fork-exec trace-fork-exec.cpp)
add_executable(inject inject.cpp)
add_executable(memory-write memory-write.cpp)
add_executable(trace-syscall trace-syscall.cpp)
add_executable(remote-call remote-call.cpp pmparser.c)
add_executable(trace-sig trace-sig.cpp)
add_executable(trace-repl trace-repl.cpp)