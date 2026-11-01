// L4 protocol — SSE 增量分帧解析器（逐位复刻 Node 版 sseEvents 的 CRLF 兼容怪癖）
#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace zproxy::protocol {

struct SseEvent {
  std::string event = "message";
  std::string data;
  bool has_data = false;
};

class SseParser {
public:
  // 喂入任意大小 chunk，弹出完整事件。scanned_ 记录已确认无终结符的前缀长度，
  // 免去每次 chunk 到达时对整段缓冲的重复扫描（长响应下 O(n²) → O(n)）。
  std::vector<SseEvent> feed(std::string_view chunk) {
    buf_.append(chunk);
    std::vector<SseEvent> out;
    for (;;) {
      size_t from = scanned_ > 0 ? scanned_ - 1 : 0; // -1：终结符可能跨前次边界
      if (from >= buf_.size()) break;
      size_t idx = buf_.find("\n\n", from);
      if (idx == std::string::npos) {
        size_t r = buf_.find("\r\n\r\n", from);
        if (r != std::string::npos) idx = r + 1; // 对齐 Node：slice(0, r+1) + slice(r+3)
        else { scanned_ = buf_.size(); break; }
      }
      std::string frame = buf_.substr(0, idx);
      buf_.erase(0, idx + 2); // 原地删除已消费部分（免整段拷贝）
      scanned_ = 0;
      SseEvent ev = parse_frame(frame);
      if (ev.has_data) out.push_back(std::move(ev));
    }
    return out;
  }
  // 流结束：无终止符的残余帧（Node 版会丢弃——保持一致返回空）
  std::vector<SseEvent> finish() { return {}; }

private:
  static SseEvent parse_frame(const std::string& frame) {
    SseEvent ev;
    std::string data;
    bool any = false;
    size_t pos = 0;
    while (pos <= frame.size()) {
      size_t nl = frame.find('\n', pos);
      std::string line = nl == std::string::npos ? frame.substr(pos) : frame.substr(pos, nl - pos);
      pos = nl == std::string::npos ? frame.size() + 1 : nl + 1;
      if (line.rfind("event:", 0) == 0) ev.event = trim(line.substr(6));
      else if (line.rfind("data:", 0) == 0) {
        std::string d = trim(line.substr(5)); // Node：l.slice(5).trim()
        if (any) data += "\n";
        data += d;
        any = true;
      }
    }
    ev.data = std::move(data); // data 局部变量：赋值不会隐式 move，显式移
    ev.has_data = any;
    return ev;
  }
  static std::string trim(std::string s) {
    size_t b = s.find_first_not_of(" \t\r");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
  }

  std::string buf_;
  size_t scanned_ = 0;
};

} // namespace zproxy::protocol
