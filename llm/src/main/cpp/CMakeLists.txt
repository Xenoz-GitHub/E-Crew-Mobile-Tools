cmake_minimum_required(VERSION 3.22.1)

project("ecrew-llm" C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED true)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)

# Vendored llama.cpp build configuration (Component 12 design note): CPU only, no
# OpenMP, no dynamic backends, no tools - the static llama/ggml libraries are linked
# into the single shared object libecrew-llm.so.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_COMMON OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_APP OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_MTMD OFF CACHE BOOL "" FORCE)
set(LLAMA_OPENSSL OFF CACHE BOOL "" FORCE)
set(GGML_NATIVE OFF CACHE BOOL "" FORCE)
set(GGML_OPENMP OFF CACHE BOOL "" FORCE)
set(GGML_BACKEND_DL OFF CACHE BOOL "" FORCE)
set(GGML_CPU_KLEIDIAI OFF CACHE BOOL "" FORCE)
set(GGML_LLAMAFILE OFF CACHE BOOL "" FORCE)

add_subdirectory(
    ${CMAKE_CURRENT_LIST_DIR}/../../../third_party/llama.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/llama.cpp)

add_library(ecrew-llm SHARED jni.cpp)

target_include_directories(ecrew-llm PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../../third_party/llama.cpp/include
    ${CMAKE_CURRENT_LIST_DIR}/../../../third_party/llama.cpp/ggml/include)

target_link_libraries(ecrew-llm PRIVATE llama android log)

# AGP cannot strip this shared object itself; strip symbols at link time so the packaged
# libecrew-llm.so stays small (debug and release are identical in this respect).
target_link_options(ecrew-llm PRIVATE -Wl,--strip-all)
