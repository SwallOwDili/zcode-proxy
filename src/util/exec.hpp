// L0 util — 子进程执行（fork/execvp，不经 shell；claim/bind 特意走 curl 绕 TLS 指纹风控）
#pragma once
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace zproxy::util::exec {

struct ExecResult {
  int exit_code = -1;
  std::string stdout_data;
  bool timed_out = false;
  bool spawn_failed = false;
};

// argv 形式直接执行（无 shell 注入面）；读取 stdout 至进程退出或超时
inline ExecResult run(const std::vector<std::string>& argv, const int64_t timeout_ms = 25'000) {
  ExecResult out;
  int pipefd[2];
  if (::pipe(pipefd) != 0) { out.spawn_failed = true; return out; }
  pid_t pid = ::fork();
  if (pid < 0) { ::close(pipefd[0]); ::close(pipefd[1]); out.spawn_failed = true; return out; }
  if (pid == 0) {
    ::close(pipefd[0]);
    ::dup2(pipefd[1], STDOUT_FILENO);
    ::close(pipefd[1]);
    std::vector<char*> cargv;
    for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);
    ::execvp(cargv[0], cargv.data());
    ::_exit(127);
  }
  ::close(pipefd[1]);
  auto t0 = std::chrono::steady_clock::now();
  char buf[8192];
  ssize_t n;
  bool timed_out = false;
  while ((n = ::read(pipefd[0], buf, sizeof(buf))) > 0) {
    out.stdout_data.append(buf, (size_t)n);
    if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count() >
        timeout_ms) {
      timed_out = true;
      break;
    }
  }
  ::close(pipefd[0]);
  if (timed_out) {
    ::kill(pid, SIGKILL);
    out.timed_out = true;
  }
  int status = 0;
  ::waitpid(pid, &status, 0);
  out.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return out;
}

} // namespace zproxy::util::exec
