cmake_minimum_required(VERSION 3.8)
project(http_downloader)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES main.c http/uri.h buffer.h http/types.h helpers.h http/client.h http/writer.h http/reader.h)
add_executable(http_downloader ${SOURCE_FILES})