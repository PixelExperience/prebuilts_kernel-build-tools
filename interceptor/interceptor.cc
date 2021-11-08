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

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>

namespace fs = std::filesystem;

// OVERLOADS for LD_PRELOAD USE

// Intercept execve calls, for that capture the original execve call
static auto const old_execve = reinterpret_cast<decltype(execve)*>(dlsym(RTLD_NEXT, "execve"));

extern "C" {
int execve(const char* filename, char* const argv[], char* const envp[]) {
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
}  // namespace interceptor
