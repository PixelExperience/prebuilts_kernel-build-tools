#
# Copyright (C) 2021 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.21)

Project(interceptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)  # LTO

set(EXECUTABLE_OUTPUT_PATH bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY lib64)

find_package(Protobuf REQUIRED)

# just enough libbase from the android-base
add_library(android-base STATIC ../../../system/libbase/strings.cpp)
target_include_directories(android-base SYSTEM PUBLIC ../../../system/libbase/include/ )

# interceptor_log - the protobuf library
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS log.proto)
add_library(interceptor_log STATIC ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(interceptor_log ${Protobuf_LIBRARIES})

set(common_libraries interceptor_log android-base)

# libinterceptor.so
add_library(libinterceptor SHARED interceptor.cc)
target_link_libraries(libinterceptor ${common_libraries})
set_target_properties(libinterceptor PROPERTIES LIBRARY_OUTPUT_NAME interceptor)

# interceptor
add_executable(interceptor main.cc)
target_link_libraries(interceptor ${common_libraries})

# interceptor_analysis
add_executable(interceptor_analysis analysis.cc)
target_link_libraries(interceptor_analysis ${common_libraries})
