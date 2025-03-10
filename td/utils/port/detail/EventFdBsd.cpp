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
#include "utils/port/detail/EventFdBsd.h"

#include <sys/errno.h>
#include <utility>

#include "utils/Slice-decl.h"
#include "utils/Status.h"
#include "utils/int_types.h"
#include "utils/port/detail/PollableFd.h"

char disable_linker_warning_about_empty_file_event_fd_bsd_cpp TD_UNUSED;

#ifdef TD_EVENTFD_BSD

#include <poll.h>
#include <sys/socket.h>

#include "utils/logging.h"
#include "utils/port/detail/NativeFd.h"
#include "utils/port/PollFlags.h"
#include "utils/port/SocketFd.h"
#include "utils/Slice.h"

namespace td {
namespace detail {

// TODO: it is extremely non optimal on Darwin. kqueue events should be used instead
void EventFdBsd::init() {
  int fds[2];
  int err = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  auto socketpair_errno = errno;
#if TD_CYGWIN
  // it looks like CYGWIN bug
  int max_retries = 1000000;
  while (err == -1 && socketpair_errno == EADDRINUSE && max_retries-- > 0) {
    err = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    socketpair_errno = errno;
  }
// LOG_IF(ERROR, max_retries < 1000000) << max_retries;
#endif
  LOG_IF(FATAL, err == -1) << Status::PosixError(socketpair_errno, "socketpair failed");

  auto fd_a = NativeFd(fds[0]);
  auto fd_b = NativeFd(fds[1]);
  fd_a.set_is_blocking_unsafe(false).ensure();
  fd_b.set_is_blocking_unsafe(false).ensure();

  in_ = SocketFd::from_native_fd(std::move(fd_a)).move_as_ok();
  out_ = SocketFd::from_native_fd(std::move(fd_b)).move_as_ok();
}

bool EventFdBsd::empty() {
  return in_.empty();
}

void EventFdBsd::close() {
  in_.close();
  out_.close();
}

Status EventFdBsd::get_pending_error() {
  return Status::OK();
}

PollableFdInfo &EventFdBsd::get_poll_info() {
  return out_.get_poll_info();
}

void EventFdBsd::release() {
  int value = 1;
  auto result = in_.write(Slice(reinterpret_cast<const char *>(&value), sizeof(value)));
  if (result.is_error()) {
    LOG(FATAL) << "EventFdBsd write failed: " << result.error();
  }
  size_t size = result.ok();
  if (size != sizeof(value)) {
    LOG(FATAL) << "EventFdBsd write returned " << value << " instead of " << sizeof(value);
  }
}

void EventFdBsd::acquire() {
  out_.get_poll_info().add_flags(PollFlags::Read());
  while (can_read(out_)) {
    uint8 value[1024];
    auto result = out_.read(MutableSlice(value, sizeof(value)));
    if (result.is_error()) {
      LOG(FATAL) << "EventFdBsd read failed:" << result.error();
    }
  }
}

void EventFdBsd::wait(int timeout_ms) {
  pollfd fd;
  fd.fd = get_poll_info().native_fd().fd();
  fd.events = POLLIN;
  poll(&fd, 1, timeout_ms);
}

}  // namespace detail
}  // namespace td

#endif
