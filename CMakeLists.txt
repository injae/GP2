cmake_minimum_required(VERSION 3.12)

set(CPPM_VERSION 0.0.13)
include(cmake/cppm_loader.cmake)
cppm_project()

project(second VERSION 0.0.1 LANGUAGES C CXX)
cppm_setting()
cppm_cxx_standard(17)
cppm_compiler_option(DEFAULT)

include(cmake/OpenSSLEnv.cmake)
find_cppkg(serdepp 0.1.1  MODULE serdepp::serdepp TYPE lib)
find_cppkg(RapidJSON 1.1.1  MODULE rapidjson TYPE lib)
find_cppkg(spdlog 1.8.2  MODULE spdlog::spdlog TYPE lib)
find_cppkg(nlohmann_json 3.9.1  MODULE nlohmann_json::nlohmann_json TYPE lib)
find_cppkg(range-v3 0.11.0  MODULE range-v3::range-v3 TYPE lib)
find_cppkg(OpenSSL git  MODULE OpenSSL::SSL OpenSSL::Crypto COMPONENTS SSL Crypto TYPE lib)


cppm_target_define(hm_crypt STATIC
SOURCES
    src/hm_crypt/algorithm.cpp
    src/hm_crypt/hash.cpp
    src/hm_crypt/eig.cpp
    src/hm_crypt/bn.cpp
)

cppm_target_define(net BINARY
SOURCES
    src/ring_net.cpp
)

cppm_target_define(net2 BINARY
SOURCES
    src/net2.cpp
)

cppm_examples_area()
if(SECOND_BUILD_EXAMPLES)

cppm_target_define(network_client BINARY
SOURCES
    examples/simnet_client.cpp
)

cppm_target_define(network_server BINARY
SOURCES
    examples/simnet_server.cpp
)

endif()


set(second_global_deps PRIVATE serdepp RapidJSON spdlog nlohmann_json range-v3 OpenSSL)
cppm_target_dependencies(hm_crypt
   ${second_global_deps})

cppm_target_dependencies(net
   ${second_global_deps}
   hm_crypt)

cppm_target_dependencies(net2
   ${second_global_deps}
   hm_crypt)

cppm_target_dependencies(network_client
   ${second_global_deps}
   hm_crypt)

cppm_target_dependencies(network_server
   ${second_global_deps}
   hm_crypt)


cppm_target_install(hm_crypt)
cppm_target_install(net)
cppm_target_install(net2)
cppm_target_install(network_client)
cppm_target_install(network_server)

