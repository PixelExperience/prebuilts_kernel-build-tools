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

#include "interceptor.h"

#include <dlfcn.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <android-base/strings.h>
#include <google/protobuf/util/delimited_message_util.h>

namespace fs = std::filesystem;

// UTILITY function declarations

// process applicable calls (i.e. programs that we might be able to handle)
static void process_command(const char* filename, char* const argv[], char* const envp[]);

// log command if logging is enabled
static void log(const interceptor::Command&);

// execute potentially modified command
static void execute(const interceptor::Command&, char* const envp[]);

// OVERLOADS for LD_PRELOAD USE

// Intercept execve calls, for that capture the original execve call
static auto const old_execve = reinterpret_cast<decltype(execve)*>(dlsym(RTLD_NEXT, "execve"));

extern "C" {
int execve(const char* filename, char* const argv[], char* const envp[]) {
  // pass on to process_command(), if unhandled, fall back to the original
  // execve
  process_command(filename, argv, envp);
  return old_execve(filename, argv, envp);
}
}  // extern "C"

// LIBRARY IMPLEMENTATION

namespace interceptor {

static Command instantiate_command(const char* program, char* const argv[], char* const envp[]) {
  Command result;
  result.set_program(program);
  result.set_current_directory(fs::current_path());

  for (auto current_argument = argv; *current_argument; ++current_argument) {
    result.add_arguments(*current_argument);
  }

  for (auto current_env_var = envp; *current_env_var; ++current_env_var) {
    const std::string s(*current_env_var);
    const auto pos = s.find('=');
    if (pos == std::string::npos) {
      continue;
    }

    (*result.mutable_environment_variables())[s.substr(0, pos)] = s.substr(pos + 1);
  }

  return result;
}

static void make_relative(Command* command) {
  // determine the ROOT_DIR
  std::string root_directory;
  if (auto it = command->environment_variables().find(kEnvRootDirectory);
      it != command->environment_variables().cend()) {
    root_directory = it->second;
    if (root_directory[root_directory.size() - 1] != '/') {
      root_directory += '/';
    }
  } else {
    return;
  }

  // determine the relative path to ROOT_DIR from the current working dir
  std::string relative_root = fs::relative(root_directory);
  if (relative_root[relative_root.size() - 1] != '/') {
    relative_root += '/';
  }
  if (relative_root == "./") {
    relative_root.clear();
  }

  // TODO: This is generally bad as this means we can't make anything relative.
  // This happens if the out dir is outside of the root.
  if (relative_root.find(root_directory) != std::string::npos) {
    return;
  }

  command->set_current_directory(fs::relative(command->current_directory(), root_directory));

  // replacement functor
  const auto replace_all = [&](auto& str) {
    auto pos = std::string::npos;
    while ((pos = str.find(root_directory)) != std::string::npos) {
      str.replace(pos, root_directory.length(), relative_root);
    }
  };

  // now go and replace everything
  replace_all(*command->mutable_program());
  std::for_each(command->mutable_arguments()->begin(), command->mutable_arguments()->end(), replace_all);
}

template <typename V>
static void dump_vector(std::ostream& os, const V& vec) {
  bool comma = false;
  for (const auto& e : vec) {
    if (comma) {
      os << ", ";
    }
    os << std::quoted(e);
    comma = true;
  }
}

std::ostream& operator<<(std::ostream& os, const interceptor::Command& command) {

  os << "[(";
  dump_vector(os, command.inputs());
  os << ") => (";
  dump_vector(os, command.outputs());
  os << ")] ";

  // TODO: chain output iterators instead and find a common expression
  const static auto escape = [](auto in) {
    in = android::base::StringReplace(in, "\t", "\\t", true);
    in = android::base::StringReplace(in, "\n", "\\n", true);
    return in;
  };

  std::ostringstream cmd;
  cmd << command.program();
  for (auto I = std::next(command.arguments().cbegin()), E = command.arguments().cend(); I != E; ++I) {
    cmd << ' ' << escape(*I);
  }

  os << cmd.str();
  return os;

}

static AnalysisResult analyze_command(const interceptor::Command& command);

static void analyze(Command* command) {
  auto [inputs, outputs] = analyze_command(*command);

  // TODO: this sanitizing should be done during make_relative
  for (auto& input : inputs) {
    if (input.rfind("./", 0) == 0) {
      input = input.substr(2);
    }
  }
  for (auto& output : outputs) {
    if (output.rfind("./", 0) == 0) {
      output = output.substr(2);
    }
  }
  for (const auto& input : inputs) {
    if (!fs::is_regular_file(input)) {
      std::cerr << "missing input: " << input << "\n" << *command << "\n";
      exit(1);
    }
  }

  *command->mutable_inputs() = {inputs.cbegin(), inputs.cend()};
  *command->mutable_outputs() = {outputs.cbegin(), outputs.cend()};
}

/// COMMAND ANALYSIS

using Analyzer = std::function<AnalysisResult(const std::string&, const ArgVec&, const EnvMap&)>;

static AnalysisResult analyze_compiler_linker(const std::string&, const ArgVec& arguments,
                                              const EnvMap&) {
  static constexpr std::array kSkipNextArguments{
      "-isystem", "-I", "-L", "-m", "-soname", "-z",
  };
  static constexpr std::string_view kOutputOption = "-Wp,-MMD,";

  AnalysisResult result;
  bool next_is_out = false;
  bool skip_next = false;
  // skip arguments[0] as this is the program itself
  for (auto it = arguments.cbegin() + 1; it != arguments.cend(); ++it) {
    const auto& argument = *it;
    if (argument == "-o") {
      next_is_out = true;
      continue;
    }
    if (next_is_out) {
      result.outputs.push_back(argument);
      next_is_out = false;
      continue;
    }
    if (argument.rfind(kOutputOption, 0) == 0) {
      result.outputs.push_back(argument.substr(kOutputOption.size()));
    }
    if (skip_next) {
      skip_next = false;
      continue;
    }
    if (std::find(kSkipNextArguments.cbegin(), kSkipNextArguments.cend(), argument) !=
        kSkipNextArguments.cend()) {
      skip_next = true;
    }
    // ignore test compilations
    if (argument == "/dev/null" || argument == "-") {
      return {};
    }
    if (argument[0] == '-') {  // ignore flags
      continue;
    }
    result.inputs.push_back(argument);
  }

  return result;
}

static AnalysisResult analyze_archiver(const std::string&, const ArgVec& arguments, const EnvMap&) {
  AnalysisResult result;

  if (arguments.size() < 3) {
    return result;
  }
  // skip arguments[0] as this is the program itself
  // skip arguments[1] are the archiver flags
  // arguments[2] is the output
  result.outputs.push_back(arguments[2]);
  // arguments[3:] are the inputs
  result.inputs.insert(result.inputs.cend(), arguments.cbegin() + 3, arguments.cend());
  return result;
}

static const std::initializer_list<std::pair<std::regex, Analyzer>> analyzers{
    {
        std::regex("^(.*/)?(clang|clang\\+\\+|gcc|g\\+\\+|ld(\\.lld)?|llvm-strip)$"),
        analyze_compiler_linker,
    },
    {
        std::regex("^(.*/)?(llvm-)?ar$"),
        analyze_archiver,
    },
};

static AnalysisResult analyze_command(const Command& command) {
  for (const auto& [regex, analyzer] : analyzers) {
    if (std::regex_match(command.arguments()[0], regex)) {
      return analyzer(command.program(), command.arguments(), command.environment_variables());
    }
  }
  return {};
}

}  // namespace interceptor

/// UTILITY FUNCTIONS

static void process_command(const char* filename, char* const argv[], char* const envp[]) {
  // First, try to find out whether we at all can handle this command. If not,
  // simply return and fall back to the original handler.

  if (!fs::is_regular_file(filename)) {
    return;
  }

  // Ok, we can handle that one, let's transform it.

  auto command = interceptor::instantiate_command(filename, argv, envp);

  // rewrite all command line arguments (including the program itself) to use
  // paths relative to ROOT_DIR. This is essential for reproducible builds and
  // furthermore necessary to produce cache hits in RBE.
  make_relative(&command);

  analyze(&command);

  log(command);

  // pass down the transformed command to execve
  execute(command, envp);
}

static void log(const interceptor::Command& command) {
  const auto& env = command.environment_variables();

  if (const auto env_it = env.find(kEnvCommandLog); env_it != env.cend()) {
    std::ofstream file;
    file.open(std::string(env_it->second),
              std::ofstream::out | std::ofstream::app | std::ofstream::binary);
    interceptor::Message message;
    *message.mutable_command() = command;
    message.mutable_command()->clear_environment_variables();
    if (file.is_open()) {
      google::protobuf::util::SerializeDelimitedToOstream(message, &file);
    }
  }
}

static void execute(const interceptor::Command& command, char* const envp[]) {
  std::vector<const char*> c_arguments;
  c_arguments.reserve(command.arguments().size() + 1);
  c_arguments[command.arguments().size()] = nullptr;
  for (const auto& arg : command.arguments()) {
    c_arguments.push_back(arg.data());
  }
  // TODO: at this point, we could free some memory that is held in Command.
  //       While the arguments vector is reused for arguments, we could free
  //       the EnvMap and the original arguments.

  // does not return
  old_execve(command.program().c_str(), const_cast<char**>(c_arguments.data()), envp);
}
