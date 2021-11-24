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
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "log.pb.h"

// Options passed via environment variables from the interceptor starter
constexpr static auto kEnvCommandLog = "INTERCEPTOR_command_log";
constexpr static auto kEnvRootDirectory = "INTERCEPTOR_root_directory";

namespace interceptor {

// Some type definitions to gain some type safety
using ArgVec = std::remove_pointer_t<decltype(Command().mutable_arguments())>;
using EnvMap = std::remove_pointer_t<decltype(Command().mutable_environment_variables())>;

using Inputs = std::vector<std::string>;
using Outputs = Inputs;

std::ostream& operator<<(std::ostream& os, const interceptor::Command& command);

// Command analysis

struct AnalysisResult {
  Inputs inputs;
  Outputs outputs;
};
}  // namespace interceptor
