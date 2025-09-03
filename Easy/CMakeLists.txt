cmake_minimum_required(VERSION 3.14)
project(CrackMe VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

add_executable(CrackMe src/main.cpp)

if(MSVC)
    target_compile_options(CrackMe PRIVATE /W4 /std:c++20)
else()
    target_compile_options(CrackMe PRIVATE -Wall -Wextra -std=c++20)
endif()
