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
#include "utils/int_types.h"

namespace td {
namespace detail {
class ThreadIdGuard {
 public:
  ThreadIdGuard();
  ~ThreadIdGuard();
  ThreadIdGuard(const ThreadIdGuard &) = delete;
  ThreadIdGuard &operator=(const ThreadIdGuard &) = delete;
  ThreadIdGuard(ThreadIdGuard &&) = delete;
  ThreadIdGuard &operator=(ThreadIdGuard &&) = delete;

 private:
  int32 thread_id_;
};
}  // namespace detail
}  // namespace td
