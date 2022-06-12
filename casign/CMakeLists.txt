cmake_minimum_required(VERSION 3.12)
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(Demo VERSION 1.0)



find_package(OpenSSL REQUIRED)
set(DEP_LIBS
    OpenSSL::Crypto OpenSSL::SSL  # modern
)
find_package(nlohmann_json REQUIRED)

add_executable(cred_create openssl_utils/openssl_utils.cpp casign.cpp)
target_link_libraries(cred_create ${DEP_LIBS} nlohmann_json::nlohmann_json)

