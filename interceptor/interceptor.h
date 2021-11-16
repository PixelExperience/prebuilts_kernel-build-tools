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

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Options passed via environment variables from the interceptor starter
constexpr static auto ENV_command_log = "INTERCEPTOR_command_log";
constexpr static auto ENV_root_dir = "INTERCEPTOR_root_dir";

namespace interceptor {

// Some type definitions to gain some type safety
using ArgVec = std::vector<std::string>;
using EnvMap = std::unordered_map<std::string, std::string>;

using Inputs = std::vector<std::string>;
using Outputs = Inputs;

// Command abstraction
//
// This is a utility container to keep program, args and env in an accessible
// fashion. Most data structures are created lazily.
class Command {
 public:
  Command(const char* program, char* const argv[], char* const envp[]);

  const std::string& program() const;
  const ArgVec& args() const;
  const EnvMap& env() const;

  char* const* envp() const { return envp_; };

  const Inputs& inputs() const { return inputs_; }
  const Outputs& outputs() const { return outputs_; }

  std::string repr() const;

  // make command line calls relative to ROOT_DIR
  void make_relative();

  // determine inputs/outputs
  void analyze();

 private:
  std::string program_;
  std::string cwd_;

  char* const* argv_;
  char* const* envp_;

  mutable std::optional<ArgVec> args_;
  mutable std::optional<EnvMap> env_;

  Inputs inputs_;
  Outputs outputs_;
};

// Command analysis

struct AnalysisResult {
  Inputs inputs;
  Outputs outputs;
};
}  // namespace interceptor
