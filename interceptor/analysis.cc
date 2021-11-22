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
#include <google/protobuf/text_format.h>
#include <sysexits.h>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

#include "log.pb.h"

namespace fs = std::filesystem;

enum class OutputFormat { TEXT };

struct Options {
  fs::path command_log;
  OutputFormat output_format = OutputFormat::TEXT;
  fs::path output;
};

static Options parse_args(int argc, char* argv[]) {
  Options result;

  const static option opts[] = {
      {"command-log", required_argument, nullptr, 'l'},
      {"output-type", required_argument, nullptr, 't'},
      {"output", required_argument, nullptr, 'o'},
      {nullptr, 0, nullptr, 0},
  };
  const auto usage = [&]() {
    std::cerr << "usage: " << argv[0] << '\n'
              << "  -l|--command-log filename\n"
              << "  -o|--output filename\n"
              << " [-t|--output-type (text)]\n";
    exit(EX_USAGE);
  };
  while (true) {
    int ix;
    int c = getopt_long(argc, argv, "-l:f:o:", opts, &ix);
    if (c == -1) break;
    switch (c) {
      case 'l':
        result.command_log = fs::absolute(optarg);
        break;
      case 't':
        if (strcmp(optarg, "text") == 0)
          result.output_format = OutputFormat::TEXT;
        else
          usage();
        break;
      case 'o':
        result.output = fs::absolute(optarg);
        break;
      default:
        usage();
    }
  }

  if (result.command_log.empty() || result.output.empty()) {
    usage();
  }

  if (!fs::exists(result.command_log)) {
    std::cerr << "No such file: " << result.command_log << "\n";
  }

  return result;
}

interceptor::log::Log read_log(const fs::path& log_file) {
  interceptor::log::Log result;
  std::ifstream input(log_file);
  if (!input) {
    std::cerr << "Could not open input file for reading.\n";
    exit(EX_NOINPUT);
  }
  result.ParseFromIstream(&input);
  return result;
}

void text_to_file(const interceptor::log::Log& log, const fs::path& output) {
  std::string content;
  google::protobuf::TextFormat::PrintToString(log, &content);
  std::ofstream os(output);
  if (!os) {
    std::cerr << "Could not open output file for writing.\n";
    exit(EX_CANTCREAT);
  }
  os << content;
  if (!os.flush()) {
    std::cerr << "Failed to write to output file.\n";
    exit(EX_CANTCREAT);
  }
}

int main(int argc, char* argv[]) {
  const auto options = parse_args(argc, argv);
  const auto log = read_log(options.command_log);

  switch (options.output_format) {
    case OutputFormat::TEXT:
      text_to_file(log, options.output);
      break;
  }
}
