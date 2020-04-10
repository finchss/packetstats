cmake_minimum_required(VERSION 3.15)
project(packetstats)

set(CMAKE_CXX_STANDARD 14)

add_executable(packetstats
        packetstats.cpp
        readpcap.c)
