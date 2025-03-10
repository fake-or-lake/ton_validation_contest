/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#pragma once

#include <memory>

#include "utils/port/config.h"
#include "utils/port/detail/NativeFd.h"
#include "utils/port/detail/PollableFd.h"
#include "utils/port/IoSlice.h"
#include "utils/port/IPAddress.h"
#include "utils/Slice.h"
#include "utils/Span.h"
#include "utils/Status.h"
#include "utils/Slice-decl.h"
#include "utils/int_types.h"
#include "utils/port/platform.h"
#include "utils/unique_ptr.h"

namespace td {
class IPAddress;
class NativeFd;
class PollableFdInfo;

namespace detail {
class SocketFdImpl;

class SocketFdImplDeleter {
 public:
  void operator()(SocketFdImpl *impl);
};
}  // namespace detail

class SocketFd {
 public:
  SocketFd();
  SocketFd(const SocketFd &) = delete;
  SocketFd &operator=(const SocketFd &) = delete;
  SocketFd(SocketFd &&);
  SocketFd &operator=(SocketFd &&);
  ~SocketFd();

  static Result<SocketFd> open(const IPAddress &address) TD_WARN_UNUSED_RESULT;

  PollableFdInfo &get_poll_info();
  const PollableFdInfo &get_poll_info() const;

  Status get_pending_error() TD_WARN_UNUSED_RESULT;

  Result<size_t> write(Slice slice) TD_WARN_UNUSED_RESULT;
  Result<size_t> writev(Span<IoSlice> slices) TD_WARN_UNUSED_RESULT;
  Result<size_t> read(MutableSlice slice) TD_WARN_UNUSED_RESULT;

  const NativeFd &get_native_fd() const;
  static Result<SocketFd> from_native_fd(NativeFd fd);

  void close();
  bool empty() const;

 private:
  std::unique_ptr<detail::SocketFdImpl, detail::SocketFdImplDeleter> impl_;
  explicit SocketFd(unique_ptr<detail::SocketFdImpl> impl);
};

namespace detail {
#if TD_PORT_POSIX
Status get_socket_pending_error(const NativeFd &fd);
#elif TD_PORT_WINDOWS
Status get_socket_pending_error(const NativeFd &fd, WSAOVERLAPPED *overlapped, Status iocp_error);
#endif
}  // namespace detail

}  // namespace td
