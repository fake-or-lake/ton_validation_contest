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

#include "utils/OptionParser.h"


#include <cstring>
#include <unordered_map>
#include <type_traits>
#include <utility>

#include "utils/Slice.h"
#include "utils/StringBuilder.h"
#include "utils/check.h"
#include "utils/int_types.h"
#include "utils/logging.h"

namespace td {

void OptionParser::set_description(string description) {
  description_ = std::move(description);
}

void OptionParser::add_option(Option::Type type, char short_key, Slice long_key, Slice description,
                              std::function<Status(Slice)> callback) {
  for (auto &option : options_) {
    if ((short_key != '\0' && option.short_key == short_key) || (!long_key.empty() && long_key == option.long_key)) {
      LOG(ERROR) << "Ignore duplicated option '" << short_key << "' '" << long_key << "'";
    }
  }
  options_.push_back(Option{type, short_key, long_key.str(), description.str(), std::move(callback)});
}

void OptionParser::add_checked_option(char short_key, Slice long_key, Slice description,
                                      std::function<Status(Slice)> callback) {
  add_option(Option::Type::Arg, short_key, long_key, description, std::move(callback));
}

void OptionParser::add_checked_option(char short_key, Slice long_key, Slice description,
                                      std::function<Status(void)> callback) {
  add_option(Option::Type::NoArg, short_key, long_key, description,
             [callback = std::move(callback)](Slice) { return callback(); });
}

void OptionParser::add_option(char short_key, Slice long_key, Slice description, std::function<void(Slice)> callback) {
  add_option(Option::Type::Arg, short_key, long_key, description, [callback = std::move(callback)](Slice parameter) {
    callback(parameter);
    return Status::OK();
  });
}

void OptionParser::add_option(char short_key, Slice long_key, Slice description, std::function<void(void)> callback) {
  add_option(Option::Type::NoArg, short_key, long_key, description, [callback = std::move(callback)](Slice) {
    callback();
    return Status::OK();
  });
}

void OptionParser::add_check(std::function<Status()> check) {
  checks_.push_back(std::move(check));
}

Result<vector<char *>> OptionParser::run(int argc, char *argv[], int expected_non_option_count) {
  std::unordered_map<char, const Option *> short_options;
  std::unordered_map<string, const Option *> long_options;
  for (auto &opt : options_) {
    if (opt.short_key != '\0') {
      short_options[opt.short_key] = &opt;
    }
    if (!opt.long_key.empty()) {
      long_options[opt.long_key] = &opt;
    }
  }

  vector<char *> non_options;
  for (int arg_pos = 1; arg_pos < argc; arg_pos++) {
    const char *arg = argv[arg_pos];
    if (arg[0] != '-' || arg[1] == '\0') {
      non_options.push_back(argv[arg_pos]);
      continue;
    }
    if (arg[1] == '-' && arg[2] == '\0') {
      // "--"; after it everything is non-option
      while (++arg_pos < argc) {
        non_options.push_back(argv[arg_pos]);
      }
      break;
    }

    if (arg[1] == '-') {
      // long option
      Slice long_arg(arg + 2, std::strlen(arg + 2));
      Slice parameter;
      auto equal_pos = long_arg.find('=');
      bool has_equal = equal_pos != Slice::npos;
      if (has_equal) {
        parameter = long_arg.substr(equal_pos + 1);
        long_arg = long_arg.substr(0, equal_pos);
      }

      auto it = long_options.find(long_arg.str());
      if (it == long_options.end()) {
        return Status::Error(PSLICE() << "Option " << long_arg << " was unrecognized");
      }

      auto option = it->second;
      switch (option->type) {
        case Option::Type::NoArg:
          if (has_equal) {
            return Status::Error(PSLICE() << "Option " << long_arg << " must not have argument");
          }
          break;
        case Option::Type::Arg:
          if (!has_equal) {
            if (++arg_pos == argc) {
              return Status::Error(PSLICE() << "Option " << long_arg << " must have argument");
            }
            parameter = Slice(argv[arg_pos], std::strlen(argv[arg_pos]));
          }
          break;
        default:
          UNREACHABLE();
      }

      TRY_STATUS(option->arg_callback(parameter));
      continue;
    }

    for (size_t opt_pos = 1; arg[opt_pos] != '\0'; opt_pos++) {
      auto it = short_options.find(arg[opt_pos]);
      if (it == short_options.end()) {
        return Status::Error(PSLICE() << "Option " << arg[opt_pos] << " was unrecognized");
      }

      auto option = it->second;
      Slice parameter;
      switch (option->type) {
        case Option::Type::NoArg:
          // nothing to do
          break;
        case Option::Type::Arg:
          if (arg[opt_pos + 1] == '\0') {
            if (++arg_pos == argc) {
              return Status::Error(PSLICE() << "Option " << arg[opt_pos] << " must have argument");
            }
            parameter = Slice(argv[arg_pos], std::strlen(argv[arg_pos]));
          } else {
            parameter = Slice(arg + opt_pos + 1, std::strlen(arg + opt_pos + 1));
            opt_pos += parameter.size();
          }
          break;
        default:
          UNREACHABLE();
      }

      TRY_STATUS(option->arg_callback(parameter));
    }
  }
  if (expected_non_option_count >= 0 && non_options.size() != static_cast<size_t>(expected_non_option_count)) {
    if (expected_non_option_count == 0) {
      return Status::Error("Unexpected non-option parameters specified");
    }
    if (non_options.size() > static_cast<size_t>(expected_non_option_count)) {
      return Status::Error("Too much non-option parameters specified");
    } else {
      return Status::Error("Too few non-option parameters specified");
    }
  }
  for (auto &check : checks_) {
    TRY_STATUS(check());
  }

  return std::move(non_options);
}

StringBuilder &operator<<(StringBuilder &sb, const OptionParser &o) {
  if (!o.description_.empty()) {
    sb << o.description_ << ". ";
  }
  sb << "Options:\n";

  size_t max_length = 0;
  for (auto &opt : o.options_) {
    bool has_short_key = opt.short_key != '\0';
    bool has_long_key = !opt.long_key.empty();
    size_t length = (has_short_key ? 2 : 0) + (has_long_key ? 2 + opt.long_key.size() + 2 * has_short_key : 0);
    if (opt.type != OptionParser::Option::Type::NoArg) {
      length += 5;
    }
    if (length > max_length) {
      max_length = length;
    }
  }
  max_length++;

  for (auto &opt : o.options_) {
    bool has_short_key = opt.short_key != '\0';
    sb << "  ";
    size_t length = max_length;
    if (has_short_key) {
      sb << '-' << opt.short_key;
      length -= 2;
    }
    if (!opt.long_key.empty()) {
      if (has_short_key) {
        sb << ", ";
        length -= 2;
      }
      sb << "--" << opt.long_key;
      length -= 2 + opt.long_key.size();
    }
    if (opt.type != OptionParser::Option::Type::NoArg) {
      sb << "<arg>";
      length -= 5;
    }
    sb << string(length, ' ') << opt.description;
    sb << '\n';
  }
  return sb;
}

}  // namespace td
