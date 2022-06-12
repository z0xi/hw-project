cmake_minimum_required(VERSION 3.12)
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(HELibDemo VERSION 1.0)

# 开启调试信息
set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

project(ABY LANGUAGES CXX)
find_package(ABY QUIET)
find_package(ENCRYPTO_utils QUIET)
if(ABY_FOUND)
    message(STATUS "Found ABY")
elseif (NOT ABY_FOUND AND NOT TARGET ABY::aby)
    message("ABY was not found: add ABY subdirectory")
    add_subdirectory(./src/ABY)
endif()

find_package(OpenSSL REQUIRED)
set(DEP_LIBS
    OpenSSL::Crypto OpenSSL::SSL  # modern
)
find_package(nlohmann_json REQUIRED)

add_executable(client ./src/client.cpp ./src/ctcpclient.cpp ./src/client_circuit.cpp)
add_executable(user ./src/user.cpp ./src/ctcpclient.cpp ./src/openssl_utils/openssl_utils.cpp)

target_link_libraries(client -ltfhe-spqlios-fma ABY::aby ENCRYPTO_utils::encrypto_utils nlohmann_json::nlohmann_json)
target_link_libraries(user -ltfhe-spqlios-fma ${DEP_LIBS} nlohmann_json::nlohmann_json)
