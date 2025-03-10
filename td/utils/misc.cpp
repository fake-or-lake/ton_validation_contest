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
#include "utils/misc.h"


#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <locale>

#include "utils/port/thread_local.h"
#include "utils/check.h"
#include "utils/unique_ptr.h"

namespace td {

char *str_dup(Slice str) {
  char *res = static_cast<char *>(std::malloc(str.size() + 1));
  if (res == nullptr) {
    return nullptr;
  }
  std::copy(str.begin(), str.end(), res);
  res[str.size()] = '\0';
  return res;
}

string implode(const vector<string> &v, char delimiter) {
  string result;
  for (size_t i = 0; i < v.size(); i++) {
    if (i != 0) {
      result += delimiter;
    }
    result += v[i];
  }
  return result;
}

string lpad0(string str, size_t size) {
  if (str.size() >= size) {
    return str;
  }
  return string(size - str.size(), '0') + str;
}

string oneline(Slice str) {
  string result;
  result.reserve(str.size());
  bool after_new_line = true;
  for (auto c : str) {
    if (c != '\n') {
      if (after_new_line) {
        if (c == ' ') {
          continue;
        }
        after_new_line = false;
      }
      result += c;
    } else {
      after_new_line = true;
      result += ' ';
    }
  }
  while (!result.empty() && result.back() == ' ') {
    result.pop_back();
  }
  return result;
}

double to_double(Slice str) {
  static TD_THREAD_LOCAL std::stringstream *ss;
  if (init_thread_local<std::stringstream>(ss)) {
    auto previous_locale = ss->imbue(std::locale::classic());
  } else {
    ss->str(std::string());
    ss->clear();
  }
  ss->write(str.begin(), narrow_cast<std::streamsize>(str.size()));

  double result = 0.0;
  *ss >> result;
  return result;
}

Result<string> hex_decode(Slice hex) {
  if (hex.size() % 2 != 0) {
    return Status::Error("Wrong hex string length");
  }
  string result(hex.size() / 2, '\0');
  for (size_t i = 0; i < result.size(); i++) {
    int high = hex_to_int(hex[i + i]);
    int low = hex_to_int(hex[i + i + 1]);
    if (high == 16 || low == 16) {
      return Status::Error("Wrong hex string");
    }
    result[i] = static_cast<char>(high * 16 + low);  // TODO implementation-defined
  }
  return std::move(result);
}

string hex_encode(Slice data) {
  const char *hex = "0123456789abcdef";
  string res;
  res.reserve(2 * data.size());
  for (unsigned char c : data) {
    res.push_back(hex[c >> 4]);
    res.push_back(hex[c & 15]);
  }
  return res;
}

static bool is_url_char(char c) {
  return is_alnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

string url_encode(Slice data) {
  size_t length = 3 * data.size();
  for (auto c : data) {
    length -= 2 * is_url_char(c);
  }
  if (length == data.size()) {
    return data.str();
  }
  string result;
  result.reserve(length);
  for (auto c : data) {
    if (is_url_char(c)) {
      result += c;
    } else {
      auto ch = static_cast<unsigned char>(c);
      result += '%';
      result += "0123456789ABCDEF"[ch / 16];
      result += "0123456789ABCDEF"[ch % 16];
    }
  }
  CHECK(result.size() == length);
  return result;
}

string buffer_to_hex(Slice buffer) {
  const char *hex = "0123456789ABCDEF";
  string res(2 * buffer.size(), '\0');
  for (std::size_t i = 0; i < buffer.size(); i++) {
    unsigned char c = buffer[i];
    res[2 * i] = hex[c >> 4];
    res[2 * i + 1] = hex[c & 15];
  }
  return res;
}

namespace {

template <class F>
string x_decode(Slice s, F &&f) {
  string res;
  for (size_t n = s.size(), i = 0; i < n; i++) {
    if (i + 1 < n && f(s[i])) {
      res.append(static_cast<unsigned char>(s[i + 1]), s[i]);
      i++;
      continue;
    }
    res.push_back(s[i]);
  }
  return res;
}

template <class F>
string x_encode(Slice s, F &&f) {
  string res;
  for (size_t n = s.size(), i = 0; i < n; i++) {
    res.push_back(s[i]);
    if (f(s[i])) {
      unsigned char cnt = 1;
      while (cnt < 250 && i + cnt < n && s[i + cnt] == s[i]) {
        cnt++;
      }
      res.push_back(static_cast<char>(cnt));
      i += cnt - 1;
    }
  }
  return res;
}

bool is_zero(unsigned char c) {
  return c == 0;
}

bool is_zero_or_one(unsigned char c) {
  return c == 0 || c == 0xff;
}

}  // namespace

std::string zero_encode(Slice data) {
  return x_encode(data, is_zero);
}
std::string zero_decode(Slice data) {
  return x_decode(data, is_zero);
}
std::string zero_one_encode(Slice data) {
  return x_encode(data, is_zero_or_one);
}
std::string zero_one_decode(Slice data) {
  return x_decode(data, is_zero_or_one);
}

}  // namespace td
