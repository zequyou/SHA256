cmake_minimum_required(VERSION 3.15)
project(SHA256)

set(CMAKE_CXX_STANDARD 11)

add_executable(SHA256 main.cpp golden.cpp SHA256_5.cpp)