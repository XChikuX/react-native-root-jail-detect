///
/// TcpProbe.cpp
///

#include "TcpProbe.hpp"
#include "SignalCatalog.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#if defined(__ANDROID__)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#if !defined(SOCK_CLOEXEC)
#define SOCK_CLOEXEC 0
#endif

namespace margelo::nitro::rootjaildetect {

  namespace {

    // RAII socket wrapper. Never expose a raw fd outside this file.
    class TcpSocket final {
    public:
      explicit TcpSocket(int descriptor) noexcept : descriptor_(descriptor) {}
      ~TcpSocket() noexcept {
        if (descriptor_ >= 0) {
          ::close(descriptor_);
        }
      }
      TcpSocket(const TcpSocket&) = delete;
      TcpSocket& operator=(const TcpSocket&) = delete;
      TcpSocket(TcpSocket&& other) noexcept : descriptor_(other.descriptor_) {
        other.descriptor_ = -1;
      }
      TcpSocket& operator=(TcpSocket&& other) noexcept {
        if (this != &other) {
          if (descriptor_ >= 0) {
            ::close(descriptor_);
          }
          descriptor_ = other.descriptor_;
          other.descriptor_ = -1;
        }
        return *this;
      }
      int get() const noexcept { return descriptor_; }
      bool valid() const noexcept { return descriptor_ >= 0; }
    private:
      int descriptor_;
    };

    bool expired(std::chrono::steady_clock::time_point deadline) noexcept {
      return std::chrono::steady_clock::now() >= deadline;
    }

    std::chrono::milliseconds remainingMs(std::chrono::steady_clock::time_point deadline) noexcept {
      if (expired(deadline)) {
        return std::chrono::milliseconds(0);
      }
      return std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()
      );
    }

#if defined(__ANDROID__) || defined(__APPLE__)

    // Attempt a non-blocking connect to 127.0.0.1:port with the given timeout.
    // Returns true if the connection succeeds within the deadline.
    bool probePort(uint16_t port, std::chrono::milliseconds timeoutMs) noexcept {
      if (timeoutMs.count() <= 0) {
        return false;
      }

      int family = AF_INET;
      struct sockaddr_in addr4 {};
      addr4.sin_family = AF_INET;
      addr4.sin_port = htons(port);
      if (inet_pton(AF_INET, "127.0.0.1", &addr4.sin_addr) != 1) {
        return false;
      }

      TcpSocket socket(::socket(family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP));
      if (!socket.valid()) {
        return false;
      }

      // Put the socket into non-blocking mode so we can bound the connect time.
      int flags = ::fcntl(socket.get(), F_GETFL, 0);
      if (flags < 0) {
        return false;
      }
      if (::fcntl(socket.get(), F_SETFL, flags | O_NONBLOCK) < 0) {
        return false;
      }

      int connectResult = ::connect(
        socket.get(),
        reinterpret_cast<struct sockaddr*>(&addr4),
        sizeof(addr4)
      );
      if (connectResult == 0) {
        return true;
      }
      // A non-blocking connect interrupted by a signal keeps connecting in the
      // background (POSIX), so EINTR is handled like EINPROGRESS.
      if (errno != EINPROGRESS && errno != EINTR) {
        return false;
      }

      // Wait for the socket to become writable (success) or an error.
      // `poll(2)`, not `select(2)`: `FD_SET` on a descriptor >= FD_SETSIZE
      // (1024) is undefined behavior and aborts under bionic's FORTIFY, which
      // would crash host apps that hold many open descriptors.
      long long ms = timeoutMs.count();
      if (ms > 1000) {
        ms = 1000; // Cap per-port timeout at 1s even if more budget remains.
      }
      const auto pollDeadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);

      for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          pollDeadline - std::chrono::steady_clock::now()
        ).count();
        if (remaining <= 0) {
          return false;
        }
        struct pollfd descriptor {};
        descriptor.fd = socket.get();
        descriptor.events = POLLOUT;
        const int pollResult = ::poll(&descriptor, 1, static_cast<int>(remaining));
        if (pollResult > 0) {
          break;
        }
        if (pollResult == 0) {
          return false; // timed out
        }
        if (errno != EINTR) {
          return false;
        }
        // Interrupted by a signal: retry with the remaining budget.
      }

      int socketError = 0;
      socklen_t errorLen = sizeof(socketError);
      if (::getsockopt(socket.get(), SOL_SOCKET, SO_ERROR, &socketError, &errorLen) < 0) {
        return false;
      }
      return socketError == 0;
    }

#else // host / unit-test builds

    bool probePort(uint16_t port, std::chrono::milliseconds timeoutMs) noexcept {
      (void) port;
      (void) timeoutMs;
      // Outside Android/iOS there is no safe way to test real loopback ports from
      // this compilation unit without pulling in platform sockets. Host-side unit
      // tests can feed synthetic findings directly if they need to stress scoring.
      return false;
    }

#endif

  } // namespace

  std::vector<ProcFinding> probeLocalTcpServices(
    const PortProbe* probes,
    size_t probeCount,
    std::chrono::steady_clock::time_point deadline
  ) noexcept {
    std::vector<ProcFinding> findings;
    std::vector<std::string_view> seen;

    for (size_t i = 0; i < probeCount; ++i) {
      if (expired(deadline)) {
        break;
      }
      const PortProbe& probe = probes[i];
      std::chrono::milliseconds timeout = remainingMs(deadline);
      if (timeout.count() <= 0) {
        break;
      }
      if (probePort(probe.port, timeout)) {
        // Deduplicate by signal id so multiple SSH ports do not inflate the score.
        if (std::find(seen.begin(), seen.end(), probe.signalId) != seen.end()) {
          continue;
        }
        seen.push_back(probe.signalId);
        findings.push_back(ProcFinding{
          probe.signalId,
          std::string(probe.description) + " port=" + std::to_string(probe.port)
        });
      }
    }
    return findings;
  }

  std::vector<ProcFinding> probeDefaultLocalTcpServices(
    std::chrono::steady_clock::time_point deadline
  ) noexcept {
    return probeLocalTcpServices(
      K_LOOPBACK_PORT_PROBES,
      sizeof(K_LOOPBACK_PORT_PROBES) / sizeof(K_LOOPBACK_PORT_PROBES[0]),
      deadline
    );
  }

} // namespace margelo::nitro::rootjaildetect
