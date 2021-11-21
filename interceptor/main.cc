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
#include <sysexits.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>

#include <google/protobuf/util/delimited_message_util.h>

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
    exit(EX_CONFIG);
  }
  setenv("LD_PRELOAD", interceptor_library.c_str(), 1);
}

static fs::path setup_root_dir() {
  const auto root_dir = getenv("ROOT_DIR");
  fs::path result;
  if (root_dir != nullptr)
    result = root_dir;
  else
    result = fs::current_path();

  setenv(ENV_root_dir, result.c_str(), 1);

  return result;
}

class CommandLog {
  const decltype(Options::command_log) command_log_file_;
  const fs::path root_dir_;

 public:
  CommandLog(decltype(command_log_file_) command_log_file, const fs::path& root_dir)
      : command_log_file_(std::move(command_log_file)), root_dir_(root_dir) {
    if (command_log_file_) {
      setenv(ENV_command_log, command_log_file_->c_str(), 1);
      std::ofstream command_log(command_log_file_->c_str(), std::ios_base::trunc);
      if (!command_log) {
        std::cerr << "Could not open command log for writing: " << *command_log_file_ << "\n";
        exit(EX_CANTCREAT);
      }
    }
  }

  ~CommandLog() {
    if (command_log_file_) {
      // compact the log by re-reading the individual log::Message's to combine
      // them to a log::Log
      interceptor::log::Log log;
      log.set_root_dir(root_dir_);
      {
        std::ifstream command_log(command_log_file_->c_str(), std::ios_base::binary);

        google::protobuf::io::IstreamInputStream input_stream(&command_log);
        interceptor::log::Message message;
        while (true) {
          if (!google::protobuf::util::ParseDelimitedFromZeroCopyStream(&message, &input_stream,
                                                                        nullptr))
            break;
          if (message.has_command()) log.add_commands()->Swap(message.release_command());
        }
      }
      std::ofstream command_log(command_log_file_->c_str(), std::ios_base::binary);
      log.SerializeToOstream(&command_log);
    }
  }
};

int main(int argc, char* argv[]) {
  const auto& options = parse_args(argc, argv);

  setup_interceptor_library_path();
  const auto root_dir = setup_root_dir();

  CommandLog command_log(options.command_log, root_dir);

  // TODO: cleanly to google::protobuf::ShutdownProtobufLibrary();

  return std::system(options.command_line.c_str());
}
