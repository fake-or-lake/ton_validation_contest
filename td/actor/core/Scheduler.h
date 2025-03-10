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


#include <atomic>
#include <condition_variable>
#include <limits>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>
#include <cstring>
#include <vector>

#include "actor/core/ActorExecuteContext.h"
#include "actor/core/ActorExecutor.h"
#include "actor/core/Actor.h"
#include "actor/core/ActorInfo.h"
#include "actor/core/ActorInfoCreator.h"
#include "actor/core/ActorLocker.h"
#include "actor/core/ActorMailbox.h"
#include "actor/core/ActorMessage.h"
#include "actor/core/Context.h"
#include "actor/core/SchedulerContext.h"
#include "actor/core/SchedulerId.h"
#include "actor/core/SchedulerMessage.h"
#include "utils/AtomicRead.h"
#include "utils/Closure.h"
#include "utils/common.h"
#include "utils/format.h"
#include "utils/Heap.h"
#include "utils/List.h"
#include "utils/logging.h"
#include "utils/MpmcQueue.h"
#include "utils/StealingQueue.h"
#include "utils/MpmcWaiter.h"
#include "utils/MpscLinkQueue.h"
#include "utils/MpscPollableQueue.h"
#include "utils/optional.h"
#include "utils/port/Poll.h"
#include "utils/port/detail/Iocp.h"
#include "utils/port/thread.h"
#include "utils/port/thread_local.h"
#include "utils/ScopeGuard.h"
#include "utils/Slice.h"
#include "utils/Time.h"
#include "utils/type_traits.h"
#include "utils/Slice-decl.h"
#include "utils/check.h"
#include "utils/int_types.h"
#include "utils/port/platform.h"

namespace td {
namespace actor {
namespace core {
class IoWorker;

struct DebugInfo {
  bool is_active{false};
  double start_at{0};
  static constexpr size_t name_size{32};
  char name[name_size] = {};
  void set_name(td::Slice from) {
    from.truncate(name_size - 1);
    std::memcpy(name, from.data(), from.size());
    name[from.size()] = 0;
  }
};

void set_debug(bool flag);
bool need_debug();

struct Debug {
 public:
  bool is_on() const {
    return need_debug();
  }
  struct Destructor {
    void operator()(Debug *info) {
      info->info_.lock().value().is_active = false;
    }
  };

  void read(DebugInfo &info) {
    info_.read(info);
  }

  std::unique_ptr<Debug, Destructor> start(td::Slice name) {
    if (!is_on()) {
      return {};
    }
    {
      auto lock = info_.lock();
      auto &value = lock.value();
      value.is_active = true;
      value.start_at = Time::now();
      value.set_name(name);
    }
    return std::unique_ptr<Debug, Destructor>(this);
  }

 private:
  AtomicRead<DebugInfo> info_;
};

struct WorkerInfo {
  enum class Type { Io, Cpu } type{Type::Io};
  WorkerInfo() = default;
  explicit WorkerInfo(Type type, bool allow_shared, CpuWorkerId cpu_worker_id)
      : type(type), actor_info_creator(allow_shared), cpu_worker_id(cpu_worker_id) {
  }
  ActorInfoCreator actor_info_creator;
  CpuWorkerId cpu_worker_id;
  Debug debug;
};

template <class T>
struct LocalQueue {
 public:
  template <class F>
  bool push(T value, F &&overflow_f) {
    queue_.local_push(std::move(value), overflow_f);
    return true;
  }
  bool try_pop(T &message) {
    return queue_.local_pop(message);
  }
  bool steal(T &message, LocalQueue &other) {
    return queue_.steal(message, other.queue_);
  }
  size_t size() const {
    return queue_.size();
  }

 private:
  StealingQueue<T> queue_;
  char pad[TD_CONCURRENCY_PAD - sizeof(optional<T>)];
};

struct SchedulerInfo {
  SchedulerId id;
  // will be read by all workers is any thread
  std::unique_ptr<MpmcQueue<SchedulerMessage::Raw *>> cpu_queue;
  std::unique_ptr<MpmcWaiter> cpu_queue_waiter;

  std::vector<LocalQueue<SchedulerMessage::Raw *>> cpu_local_queue;
  //std::vector<td::StealingQueue<SchedulerMessage>> cpu_stealing_queue;

  // only scheduler itself may read from io_queue_
  std::unique_ptr<MpscPollableQueue<SchedulerMessage>> io_queue;
  size_t cpu_threads_count{0};

  std::unique_ptr<WorkerInfo> io_worker;
  std::vector<std::unique_ptr<WorkerInfo>> cpu_workers;
};

struct SchedulerGroupInfo {
  explicit SchedulerGroupInfo(size_t n) : schedulers(n) {
  }
  std::atomic<bool> is_stop_requested{false};

  int active_scheduler_count{0};
  std::mutex active_scheduler_count_mutex;
  std::condition_variable active_scheduler_count_condition_variable;

#if TD_PORT_WINDOWS
  td::detail::Iocp iocp;
  td::thread iocp_thread;
#endif
  std::vector<SchedulerInfo> schedulers;
};

class Scheduler {
 public:
  static constexpr int32 max_thread_count() {
    return 256;
  }

  static int32 get_thread_id() {
    auto thread_id = ::td::get_thread_id();
    CHECK(thread_id < max_thread_count());
    return thread_id;
  }

  Scheduler(std::shared_ptr<SchedulerGroupInfo> scheduler_group_info, SchedulerId id, size_t cpu_threads_count,
            bool skip_timeouts = false);

  Scheduler(const Scheduler &) = delete;
  Scheduler &operator=(const Scheduler &) = delete;
  Scheduler(Scheduler &&other) = delete;
  Scheduler &operator=(Scheduler &&other) = delete;
  ~Scheduler();

  void start();

  template <class F>
  void run_in_context(F &&f) {
    run_in_context_impl(*info_->io_worker, std::forward<F>(f));
  }

  template <class F>
  void run_in_context_external(F &&f) {
    WorkerInfo info;
    info.type = WorkerInfo::Type::Cpu;
    run_in_context_impl(*info_->io_worker, std::forward<F>(f));
  }

  bool run(double timeout);

  // Just syntactic sugar
  void stop() {
    run_in_context([] { SchedulerContext::get()->stop(); });
  }

  SchedulerId get_scheduler_id() const {
    return info_->id;
  }

 private:
  std::shared_ptr<SchedulerGroupInfo> scheduler_group_info_;
  SchedulerInfo *info_;
  std::vector<td::thread> cpu_threads_;
  bool is_stopped_{false};
  Poll poll_;
  KHeap<double> heap_;
  std::unique_ptr<IoWorker> io_worker_;
  bool skip_timeouts_{false};

  class ContextImpl : public SchedulerContext {
   public:
    ContextImpl(ActorInfoCreator *creator, SchedulerId scheduler_id, CpuWorkerId cpu_worker_id,
                SchedulerGroupInfo *scheduler_group, Poll *poll, KHeap<double> *heap, Debug *debug);

    SchedulerId get_scheduler_id() const override;
    void add_to_queue(ActorInfoPtr actor_info_ptr, SchedulerId scheduler_id, bool need_poll) override;

    ActorInfoCreator &get_actor_info_creator() override;

    bool has_poll() override;
    Poll &get_poll() override;

    bool has_heap() override;
    KHeap<double> &get_heap() override;

    Debug &get_debug() override;

    void set_alarm_timestamp(const ActorInfoPtr &actor_info_ptr) override;

    bool is_stop_requested() override;
    void stop() override;

    SchedulerGroupInfo *scheduler_group() const override {
      return scheduler_group_;
    }

   private:

    ActorInfoCreator *creator_;
    SchedulerId scheduler_id_;
    CpuWorkerId cpu_worker_id_;
    SchedulerGroupInfo *scheduler_group_;
    Poll *poll_;

    KHeap<double> *heap_;

    Debug *debug_;
  };

  template <class F>
  void run_in_context_impl(WorkerInfo &worker_info, F &&f) {
#if TD_PORT_WINDOWS
    td::detail::Iocp::Guard iocp_guard(&scheduler_group_info_->iocp);
#endif
    bool is_io_worker = worker_info.type == WorkerInfo::Type::Io;
    ContextImpl context(&worker_info.actor_info_creator, info_->id, worker_info.cpu_worker_id,
                        scheduler_group_info_.get(), is_io_worker ? &poll_ : nullptr, is_io_worker ? &heap_ : nullptr,
                        &worker_info.debug);
    SchedulerContext::Guard guard(&context);
    f();
  }

  void do_stop();

 public:
  static void close_scheduler_group(SchedulerGroupInfo &group_info);
};

// Actor messages
class ActorMessageHangup : public core::ActorMessageImpl {
 public:
  void run() override {
    ActorExecuteContext::get()->actor().hangup();
  }
};
class ActorMessageHangupShared : public core::ActorMessageImpl {
 public:
  void run() override {
    ActorExecuteContext::get()->actor().hangup_shared();
  }
};
}  // namespace core
}  // namespace actor
}  // namespace td
