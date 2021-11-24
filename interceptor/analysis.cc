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
#include <google/protobuf/util/json_util.h>
#include <sysexits.h>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <unordered_set>

#include "log.pb.h"

namespace fs = std::filesystem;

enum class OutputFormat { TEXT, COMPDB };

struct Options {
  fs::path command_log;
  OutputFormat output_format = OutputFormat::TEXT;
  fs::path output;
};

static Options parse_arguments(int argc, char* argv[]) {
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
              << " [-t|--output-type (text|compdb)]\n";
    exit(EX_USAGE);
  };
  while (true) {
    int ix;
    int c = getopt_long(argc, argv, "-l:t:o:", opts, &ix);
    if (c == -1) {
      break;
    }
    switch (c) {
      case 'l':
        result.command_log = fs::absolute(optarg);
        break;
      case 't':
        if (strcmp(optarg, "text") == 0) {
          result.output_format = OutputFormat::TEXT;
        }
        if (strcmp(optarg, "compdb") == 0) {
          result.output_format = OutputFormat::COMPDB;
        } else {
          usage();
        }
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

interceptor::Log read_log(const fs::path& log_file) {
  interceptor::Log result;
  std::ifstream input(log_file);
  if (!input) {
    std::cerr << "Could not open input file for reading.\n";
    exit(EX_NOINPUT);
  }
  result.ParseFromIstream(&input);
  return result;
}

void text_to_file(const interceptor::Log& log, const fs::path& output) {
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

void compdb_to_file(const interceptor::Log& log, const fs::path& output) {
  static const std::unordered_set<std::string_view> kCompileExtensions = {
      ".c", ".cc", ".cpp", ".cxx", ".S",
  };
  static const std::unordered_set<std::string_view> kCompilers = {
      "clang",
      "clang++",
      "gcc",
      "g++",
  };

  interceptor::CompilationDatabase compdb;

  for (const auto& command : log.commands()) {
    if (command.arguments().empty()) {
      continue;
    }

    // skip anything that is not a compiler invocation
    if (!kCompilers.count(fs::path(command.arguments(0)).filename().native())) {
      continue;
    }

    // determine if we have a uniquely identifyable output
    const std::string single_output = [&]() {
      std::vector<std::string> outputs;
      for (const auto& output : command.outputs()) {
        // skip .d files. They are conventionally used for make dependency files
        if (fs::path(output).extension() != ".d") {
          outputs.push_back(output);
        }
      }
      return (outputs.size() == 1) ? outputs[0] : "";
    }();

    // skip preprocessor invocations
    if (std::find(command.arguments().cbegin(), command.arguments().cend(), "-E") !=
        command.arguments().cend()) {
      continue;
    }

    // now iterate over all inputs, emitting an entry for each source file
    for (const auto& input : command.inputs()) {
      // skip anything that does not look like a source file (object files,
      // force included headers, etc.)
      if (!kCompileExtensions.count(fs::path(input).extension().native())) {
        continue;
      }

      // ok, now we have a new command
      auto& compile_command = *compdb.add_commands();

      compile_command.set_directory(fs::path(log.root_directory()) / command.current_directory());
      compile_command.set_file(input);
      if (!single_output.empty()) {
        compile_command.set_output(single_output);
      }
      *compile_command.mutable_arguments() = {command.arguments().cbegin(),
                                              command.arguments().cend()};
    }
  }

  std::ofstream out(output);

  if (!compdb.commands_size()) {
    out << "[]\n";
    return;
  }

  std::string out_str;
  auto options = google::protobuf::util::JsonPrintOptions{};
  options.add_whitespace = true;
  google::protobuf::util::MessageToJsonString(compdb, &out_str, options);

  // this would emit {"command":[yadayada]}, but we want only [yadayada]
  // the additional characters come from options.add_whitespace
  //
  // TODO: make this better, but as of now there is not much we can do as
  // util::MessageToJsonString() takes a message and that is always represented
  // as a dictionary, while the top level structure of compile_command.json is
  // an array. So, we have to chop of the leading and trailing characters to
  // find the contained array.
  const auto left_offset = out_str.find('[');
  const auto length = out_str.rfind(']') - left_offset + 1;
  out << std::string_view(out_str).substr(left_offset, length);
}

int main(int argc, char* argv[]) {
  const auto options = parse_arguments(argc, argv);
  const auto log = read_log(options.command_log);

  switch (options.output_format) {
    case OutputFormat::TEXT:
      text_to_file(log, options.output);
      break;
    case OutputFormat::COMPDB:
      compdb_to_file(log, options.output);
      break;
  }
}
