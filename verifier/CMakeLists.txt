cmake_minimum_required(VERSION 3.12)
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(Demo VERSION 1.0)

# 开启调试信息
# set(CMAKE_BUILD_TYPE "Debug")
# set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
# set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
find_package(OpenSSL REQUIRED)
set(DEP_LIBS
    OpenSSL::Crypto OpenSSL::SSL  # modern
)
find_package(nlohmann_json REQUIRED)

add_executable(verifier ./src/main.cpp ./src/verifier.cpp ./src/openssl_utils/openssl_utils.cpp ./src/ctcpserver.cpp)

target_link_libraries(verifier -ltfhe-spqlios-fma ${DEP_LIBS} nlohmann_json::nlohmann_json -lpthread -lm)
