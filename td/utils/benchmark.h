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

#include "utils/format.h"
#include "utils/logging.h"
#include "utils/port/Clocks.h"
#include "utils/StringBuilder.h"

#include <cmath>
#include <tuple>
#include <utility>

#define BENCH(name, desc)                          \
  class name##Bench : public ::td::Benchmark {     \
   public:                                         \
    std::string get_description() const override { \
      return (desc);                               \
    }                                              \
    void run(int n) override;                      \
  };                                               \
  void name##Bench::run(int n)

namespace td {

#if TD_MSVC

#pragma optimize("", off)
template <class T>
void do_not_optimize_away(T &&datum) {
  datum = datum;
}
#pragma optimize("", on)

#else

template <class T>
void do_not_optimize_away(T &&datum) {
  asm volatile("" : "+r"(datum));
}

#endif

class Benchmark {
 public:
  Benchmark() = default;
  Benchmark(const Benchmark &) = delete;
  Benchmark &operator=(const Benchmark &) = delete;
  Benchmark(Benchmark &&) = delete;
  Benchmark &operator=(Benchmark &&) = delete;
  virtual ~Benchmark() = default;

  virtual std::string get_description() const = 0;

  virtual void start_up() {
  }
  virtual void start_up_n(int n) {
    start_up();
  }

  virtual void tear_down() {
  }

  virtual void run(int n) = 0;
};

inline std::pair<double, double> bench_n(Benchmark &b, int n) {
  double total = -Clocks::monotonic();
  b.start_up_n(n);
  double t = -Clocks::monotonic();
  b.run(n);
  t += Clocks::monotonic();
  b.tear_down();
  total += Clocks::monotonic();

  return std::make_pair(t, total);
}

inline std::pair<double, double> bench_n(Benchmark &&b, int n) {
  return bench_n(b, n);
}

inline void bench(Benchmark &b, double max_time = 1.0) {
  int n = 1;
  double pass_time = 0;
  double total_pass_time = 0;
  while (pass_time < max_time && total_pass_time < max_time * 3 && n < (1 << 30)) {
    n *= 2;
    std::tie(pass_time, total_pass_time) = bench_n(b, n);
  }
  pass_time = n / pass_time;

  int pass_cnt = 2;
  double sum = pass_time;
  double square_sum = pass_time * pass_time;
  double min_pass_time = pass_time;
  double max_pass_time = pass_time;

  for (int i = 1; i < pass_cnt; i++) {
    pass_time = n / bench_n(b, n).first;
    sum += pass_time;
    square_sum += pass_time * pass_time;
    if (pass_time < min_pass_time) {
      min_pass_time = pass_time;
    }
    if (pass_time > max_pass_time) {
      max_pass_time = pass_time;
    }
  }
  double average = sum / pass_cnt;
  double d = sqrt(square_sum / pass_cnt - average * average);

  auto description = b.get_description();
  std::string pad;
  if (description.size() < 40) {
    pad = std::string(40 - description.size(), ' ');
  }

  LOG(ERROR) << "Bench [" << pad << description << "]: " << StringBuilder::FixedDouble(average, 3) << '['
             << StringBuilder::FixedDouble(min_pass_time, 3) << '-' << StringBuilder::FixedDouble(max_pass_time, 3)
             << "] ops/sec,\t" << format::as_time(1 / average) << " [d = " << StringBuilder::FixedDouble(d, 6) << ']';
}

inline void bench(Benchmark &&b, double max_time = 1.0) {
  bench(b, max_time);
}

}  // namespace td
