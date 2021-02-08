cmake_minimum_required (VERSION 3.18.4)
project (shade-so)

include (ExternalProject)
ExternalProject_Add (
    spdlog
    PREFIX          ${CMAKE_CURRENT_BINARY_DIR}/thirdparty
    GIT_REPOSITORY  https://github.com/gabime/spdlog.git
    GIT_TAG         a51b4856377a71f81b6d74b9af459305c4c644f8
    CMAKE_ARGS      -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/thirdparty/install/spdlog
)

add_subdirectory (src)
