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

#include "utils/common.h"
#include "utils/misc.h"
#include "utils/port/EventFd.h"

#if !TD_EVENTFD_UNSUPPORTED

#include "utils/SpinLock.h"

#include <utility>

namespace td {
// interface like in PollableQueue
template <class T>
class MpscPollableQueue {
 public:
  using ValueType = T;

  int reader_wait_nonblock() {
    auto ready = reader_vector_.size() - reader_pos_;
    if (ready != 0) {
      return narrow_cast<int>(ready);
    }

    for (int i = 0; i < 2; i++) {
      auto guard = lock_.lock();
      if (writer_vector_.empty()) {
        if (i == 1) {
          wait_event_fd_ = true;
          return 0;
        }
      } else {
        reader_vector_.clear();
        reader_pos_ = 0;
        std::swap(writer_vector_, reader_vector_);
        return narrow_cast<int>(reader_vector_.size());
      }
      event_fd_.acquire();
    }
    UNREACHABLE();
  }
  ValueType reader_get_unsafe() {
    return std::move(reader_vector_[reader_pos_++]);
  }
  void reader_flush() {
    //nop
  }
  void writer_put(ValueType value) {
    auto guard = lock_.lock();
    writer_vector_.push_back(std::move(value));
    if (wait_event_fd_) {
      wait_event_fd_ = false;
      guard.reset();
      event_fd_.release();
    }
  }
  EventFd &reader_get_event_fd() {
    return event_fd_;
  }
  void writer_flush() {
    //nop
  }

  void init() {
    event_fd_.init();
  }
  void destroy() {
    if (!event_fd_.empty()) {
      event_fd_.close();
      wait_event_fd_ = false;
      writer_vector_.clear();
      reader_vector_.clear();
      reader_pos_ = 0;
    }
  }

  // Just an example of usage
  int reader_wait() {
    int res;
    while ((res = reader_wait_nonblock()) == 0) {
      reader_get_event_fd().wait(1000);
    }
    return res;
  }

 private:
  SpinLock lock_;
  bool wait_event_fd_{false};
  EventFd event_fd_;
  std::vector<ValueType> writer_vector_;
  std::vector<ValueType> reader_vector_;
  size_t reader_pos_{0};
};

}  // namespace td

#else

namespace td {

// dummy implementation which shouldn't be used

template <class T>
class MpscPollableQueue {
 public:
  using ValueType = T;

  void init() {
    UNREACHABLE();
  }

  template <class PutValueType>
  void writer_put(PutValueType &&value) {
    UNREACHABLE();
  }

  void writer_flush() {
    UNREACHABLE();
  }

  int reader_wait_nonblock() {
    UNREACHABLE();
    return 0;
  }

  ValueType reader_get_unsafe() {
    UNREACHABLE();
    return ValueType();
  }

  void reader_flush() {
    UNREACHABLE();
  }

  MpscPollableQueue() = default;
  MpscPollableQueue(const MpscPollableQueue &) = delete;
  MpscPollableQueue &operator=(const MpscPollableQueue &) = delete;
  MpscPollableQueue(MpscPollableQueue &&) = delete;
  MpscPollableQueue &operator=(MpscPollableQueue &&) = delete;
  ~MpscPollableQueue() = default;
};

}  // namespace td

#endif
