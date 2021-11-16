/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <getopt.h>
#include <stdlib.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>

#include "interceptor.h"

namespace fs = std::filesystem;

struct Options {
  std::string command_line;
  std::optional<fs::path> command_log;
};

static Options parse_args(int argc, char* argv[]) {
  Options result;

  while (1) {
    static struct option long_options[] = {{"command-log", required_argument, 0, 'l'},
                                           {0, 0, 0, 0}};
    /* getopt_long stores the option index here. */
    int option_index = 0;

    auto c = getopt_long(argc, argv, "l:", long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1) break;

    switch (c) {
      case 'l':
        result.command_log = fs::absolute(optarg);
        break;

      case '?':
        /* getopt_long already printed an error message. */
        break;

      default:
        abort();
    }
  }

  std::stringstream ss;
  if (optind < argc) {
    while (optind < argc) {
      ss << argv[optind++];
      ss << ' ';
    }
  }
  result.command_line = ss.str();

  return result;
}

static void setup_interceptor_library_path() {
  auto interceptor_library = fs::read_symlink("/proc/self/exe").parent_path().parent_path() /
                             "lib64" / "libinterceptor.so";
  while (fs::is_symlink(interceptor_library))
    interceptor_library = fs::read_symlink(interceptor_library);
  if (!fs::is_regular_file(interceptor_library)) {
    std::cerr << "Interceptor library could not be found!\n";
    exit(1);
  }
  setenv("LD_PRELOAD", interceptor_library.c_str(), 1);
}

static void setup_root_dir() {
  const auto root_dir = getenv("ROOT_DIR");
  if (root_dir != nullptr)
    setenv(ENV_root_dir, root_dir, 1);
  else
    setenv(ENV_root_dir, fs::current_path().c_str(), 1);
}

class CommandLog {
  const decltype(Options::command_log) command_log_file_;

 public:
  CommandLog(decltype(command_log_file_) command_log_file)
      : command_log_file_(std::move(command_log_file)) {
    if (command_log_file_) {
      setenv(ENV_command_log, command_log_file_->c_str(), 1);
      std::ofstream command_log(command_log_file_->c_str(), std::ios_base::trunc);
      command_log << "[\n";
    }
  }

  ~CommandLog() {
    if (command_log_file_) {
      std::ofstream command_log(command_log_file_->c_str(), std::ios_base::app);
      command_log << "]\n";
    }
  }
};

int main(int argc, char* argv[]) {
  const auto& options = parse_args(argc, argv);

  setup_interceptor_library_path();
  setup_root_dir();

  CommandLog command_log(options.command_log);

  return std::system(options.command_line.c_str());
}
