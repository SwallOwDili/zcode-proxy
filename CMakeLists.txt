cmake_minimum_required(VERSION 3.24)
project(zcode-proxy-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra -Wno-unused-parameter)
add_compile_definitions(CPPHTTPLIB_OPENSSL_SUPPORT CPPHTTPLIB_DISABLE_MACOSX_AUTOMATIC_ROOT_CERTIFICATES)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio-include
  ${OPENSSL_INCLUDE_DIRS}
)
add_compile_definitions(ASIO_STANDALONE ASIO_NO_DEPRECATED)

# ---------- 主程序 ----------
file(GLOB_RECURSE ZPROXY_SRC CONFIGURE_DEPENDS src/*.cpp)
add_executable(zproxy ${ZPROXY_SRC})
target_link_libraries(zproxy PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)

# ---------- 诊断工具 ----------
target_link_libraries(netcheck2 PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
target_link_libraries(netcheck PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)

# ---------- 测试 ----------
enable_testing()
file(GLOB ZPROXY_TESTS CONFIGURE_DEPENDS tests/*.cpp)
foreach(t ${ZPROXY_TESTS})
  get_filename_component(name ${t} NAME_WE)
  add_executable(${name} ${t})
  target_link_libraries(${name} PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
  add_test(NAME ${name} COMMAND ${name})
endforeach()
