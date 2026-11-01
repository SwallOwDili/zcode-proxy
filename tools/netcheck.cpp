// netcheck — DNS/connect 逐地址诊断
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <chrono>
#include "upstream/http.hpp"

int main(int argc, char** argv) {
  const char* host = argc > 1 ? argv[1] : "zcode.z.ai";
  // 1) getaddrinfo 枚举
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  int rc = getaddrinfo(host, "443", &hints, &res);
  std::printf("getaddrinfo rc=%d\n", rc);
  for (addrinfo* p = res; p; p = p->ai_next) {
    char ip[64] = {0};
    if (p->ai_family == AF_INET) inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, ip, sizeof ip);
    else inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, ip, sizeof ip);
    auto t0 = std::chrono::steady_clock::now();
    int fd = socket(p->ai_family, SOCK_STREAM, 0);
    int cr = ::connect(fd, p->ai_addr, p->ai_addrlen);
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    std::printf("  [%s] connect=%s in %.1fms (errno=%s)\n", ip, cr == 0 ? "OK" : "FAIL", ms,
                cr == 0 ? "-" : strerror(errno));
    ::close(fd);
  }
  if (res) freeaddrinfo(res);
  // 2) httplib 客户端
  auto t0 = std::chrono::steady_clock::now();
  auto h = zproxy::upstream::make_client(std::string("https://") + host, 10, 10);
  auto r = h.cli->Get(h.prefix + "/api/v1/zcode-plan/anthropic");
  double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
  if (!r) std::printf("httplib: FAIL %s in %.1fms\n", httplib::to_string(r.error()).c_str(), ms);
  else std::printf("httplib: status=%d in %.1fms\n", r->status, ms);
  return 0;
}
