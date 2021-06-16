cmake_minimum_required(VERSION 3.12)

set(CPPM_VERSION dev)
include(cmake/cppm_loader.cmake)
cppm_project()

project(second VERSION 0.0.1 LANGUAGES C CXX)
cppm_setting()
cppm_cxx_standard(17)
cppm_compiler_option(
   DEBUG
      CLANG "-Wno-deprecated-declarations"

   RELEASE
      CLANG "-Wno-deprecated-declarations"
)

include(cmake/OpenSSLEnv.cmake)
find_cppkg(OpenSSL git  MODULE OpenSSL::SSL OpenSSL::Crypto COMPONENTS SSL Crypto TYPE lib)
find_cppkg(fmt 7.1.3  MODULE fmt::fmt TYPE lib)
find_cppkg(nlohmann_json 3.9.1  MODULE nlohmann_json::nlohmann_json TYPE lib)
find_cppkg(range-v3 0.11.0  MODULE range-v3::range-v3 TYPE lib)
find_cppkg(serdepp 0.0.2  MODULE serdepp LOADPATH lib/serdepp TYPE lib)
find_cppkg(spdlog 1.8.2  MODULE spdlog::spdlog TYPE lib)


cppm_target_define(net BINARY
SOURCES
    src/ring_net.cpp
    src/hm_crypt/algorithm.cpp
    src/hm_crypt/hash.cpp
    src/hm_crypt/eig.cpp
    src/hm_crypt/bn.cpp
)


set(second_global_deps PUBLIC OpenSSL fmt nlohmann_json range-v3 serdepp spdlog)
cppm_target_dependencies(net
   ${second_global_deps})


cppm_target_install(net)

