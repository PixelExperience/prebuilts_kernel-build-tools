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

namespace fs = std::filesystem;

// UTILITY function declarations

// process applicable calls (i.e. programs that we might be able to handle)
static void process_command(const char* filename, char* const argv[], char* const envp[]);

// log command if logging is enabled
static void log(const interceptor::Command&, const std::string& prefix);

// execute potentially modified command
static void exec(const interceptor::Command&);

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

Command::Command(const char* program, char* const argv[], char* const envp[])
    : program_(program), cwd_(fs::current_path()), argv_(argv), envp_(envp) {}

const ArgVec& Command::args() const {
  if (!args_.has_value()) {
    args_ = ArgVec();
    for (auto current_arg = argv_; *current_arg; ++current_arg) {
      args_->emplace_back(*current_arg);
    }
  }
  return *args_;
}

const EnvMap& Command::env() const {
  if (!env_.has_value()) {
    env_ = EnvMap();
    for (auto current_env = envp_; *current_env; ++current_env) {
      const std::string_view s(*current_env);
      const auto pos = s.find('=');
      if (pos == EnvMap::key_type::npos) {
        continue;
      }
      env_->emplace(s.substr(0, pos), s.substr(pos + 1));
    }
  }
  return *env_;
}

const std::string& Command::program() const {
  return program_;
}

// TODO: chain output iterators instead and find a common expression
static std::string escape(std::string in) {
  in = android::base::StringReplace(in, "\t", "\\t", true);
  in = android::base::StringReplace(in, "\n", "\\n", true);
  return in;
}

template <typename T>
static void dump_vector(std::ostream& os, const char* key, const std::vector<T>& vec) {
  os << std::quoted(key) << ": [";
  bool comma = false;
  for (const auto& e : vec) {
    if (comma) {
      os << ", ";
    }
    os << std::quoted(e);
    comma = true;
  }
  os << "]";
}

std::string Command::repr() const {
  std::ostringstream os;
  os << R"({"cmd": )";
  {
    std::ostringstream cmd;
    cmd << program();
    if (args().size() > 1) cmd << ' ';
    std::transform(args().cbegin() + 1, args().cend(), std::ostream_iterator<std::string>(cmd, " "),
                   escape);
    os << std::quoted(cmd.str());
  }

  os << ", ";
  dump_vector(os, "in", inputs());
  os << ", ";
  dump_vector(os, "out", outputs());

  os << R"(, "cwd": )" << std::quoted(cwd_);

  os << "}";
  return os.str();
}

void Command::make_relative() {
  // determine the ROOT_DIR
  std::string root_dir;
  if (auto it = env().find(ENV_root_dir); it != env().cend()) {
    root_dir = it->second;
    if (root_dir[root_dir.size() - 1] != '/') root_dir += '/';
  } else {
    return;
  }

  // determine the relative path to ROOT_DIR from the current working dir
  std::string rel_root = fs::relative(root_dir);
  if (rel_root[rel_root.size() - 1] != '/') rel_root += '/';
  if (rel_root == "./") rel_root = "";

  // TODO: This is generally bad as this means we can't make anything relative.
  // This happens if the out dir is outside of the root.
  if (rel_root.find(root_dir) != std::string::npos) {
    return;
  }

  cwd_ = fs::relative(cwd_, root_dir);

  // replacement functor
  const auto replace_all = [&](auto& str) {
    auto pos = std::string::npos;
    while ((pos = str.find(root_dir)) != std::string::npos) {
      str.replace(pos, root_dir.length(), rel_root);
    }
  };

  if (!args_.has_value()) args();

  // now go and replace everything
  replace_all(program_);
  std::for_each(args_->begin(), args_->end(), replace_all);
}

static AnalysisResult analyze_command(const interceptor::Command& command);

void Command::analyze() {
  auto [inputs, outputs] = analyze_command(*this);

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
      std::cerr << "missing input: " << input << "\n";
      std::cerr << Command::repr() << "\n";
      exit(1);
    }
  }

  inputs_ = std::move(inputs);
  outputs_ = std::move(outputs);
}

/// COMMAND ANALYSIS

using Analyzer = std::function<AnalysisResult(const std::string&, const ArgVec&, const EnvMap&)>;

static AnalysisResult analyze_compiler_linker(const std::string&, const ArgVec& args,
                                              const EnvMap&) {
  static constexpr std::array kSkipNextArgs{
      "-isystem", "-I", "-L", "-m", "-soname", "-z",
  };
  static constexpr std::string_view kOutputOption = "-Wp,-MMD,";

  AnalysisResult result;
  bool next_is_out = false;
  bool skip_next = false;
  // skip args[0] as this is the program itself
  for (auto it = args.cbegin() + 1; it != args.cend(); ++it) {
    const auto& arg = *it;
    if (arg == "-o") {
      next_is_out = true;
      continue;
    }
    if (next_is_out) {
      result.outputs.push_back(arg);
      next_is_out = false;
      continue;
    }
    if (arg.rfind(kOutputOption, 0) == 0) {
      result.outputs.push_back(arg.substr(kOutputOption.size()));
    }
    if (skip_next) {
      skip_next = false;
      continue;
    }
    if (std::find(kSkipNextArgs.cbegin(), kSkipNextArgs.cend(), arg) != kSkipNextArgs.cend()) {
      skip_next = true;
    }
    // ignore test compilations
    if (arg == "/dev/null" || arg == "-") {
      return {};
    }
    if (arg[0] == '-') {  // ignore flags
      continue;
    }
    result.inputs.push_back(arg);
  }

  return result;
}

static AnalysisResult analyze_archiver(const std::string&, const ArgVec& args, const EnvMap&) {
  AnalysisResult result;

  if (args.size() < 3) return result;
  // skip args[0] as this is the program itself
  // skip args[1] are the archiver flags
  // args[2] is the output
  result.outputs.push_back(args[2]);
  // args[3:] are the inputs
  result.inputs.insert(result.inputs.cend(), args.cbegin() + 3, args.cend());
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
    if (std::regex_match(command.args()[0], regex)) {
      return analyzer(command.program(), command.args(), command.env());
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

  interceptor::Command command(filename, argv, envp);

  // rewrite all command line arguments (including the program itself) to use
  // paths relative to ROOT_DIR. This is essential for reproducible builds and
  // furthermore necessary to produce cache hits in RBE.
  command.make_relative();

  command.analyze();

  log(command, "");

  // pass down the transformed command to execve
  exec(command);
}

static void log(const interceptor::Command& command, const std::string& prefix) {
  const auto& env = command.env();

  if (const auto env_it = env.find(ENV_command_log); env_it != env.cend()) {
    std::ofstream file;
    file.open(std::string(env_it->second), std::ofstream::out | std::ofstream::app);
    if (file.is_open()) {
      file << prefix << command.repr() << ",\n";
    }
  }
}

static void exec(const interceptor::Command& command) {
  std::vector<const char*> c_args;
  c_args.reserve(command.args().size() + 1);
  c_args[command.args().size()] = nullptr;
  for (const auto& arg : command.args()) {
    c_args.push_back(arg.data());
  }
  // TODO: at this point, we could free some memory that is held in Command.
  //       While the args vector is reused for args, we could free the EnvMap
  //       and the original args.
  old_execve(command.program().c_str(), const_cast<char**>(c_args.data()), command.envp());
}
