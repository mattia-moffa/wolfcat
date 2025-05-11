cmake_minimum_required(VERSION 4.0)

project(wolfcat)

find_package(wolfssl REQUIRED)

add_executable(wolfcat src/main.c src/client.c src/server.c)
target_include_directories(wolfcat PRIVATE include)

target_link_libraries(wolfcat PRIVATE wolfssl::wolfssl)
