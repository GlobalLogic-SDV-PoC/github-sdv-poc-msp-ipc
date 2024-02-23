if(NOT TARGET net::asio)
    find_path(
        ASIO_INCLUDE_DIR asio.hpp
        HINTS "${ASIO_ROOT}" ENV ASIO_ROOT "${ENV_ASIO_ROOT}"
        PATH_SUFFIXES asio/include)

    if(NOT ASIO_INCLUDE_DIR)
        message(
            "Could not find Asio. Set ASIO_ROOT as a CMake or environment variable to point to the Asio root install directory."
        )
    endif()

    if(ASIO_INCLUDE_DIR AND EXISTS "${ASIO_INCLUDE_DIR}/asio/version.hpp")
        message("Looking for ASIO version")
        # Matches a line of the form:
        #
        # #define ASIO_VERSION XXYYZZ // XX.YY.ZZ
        #
        # with arbitrary whitespace between the tokens
        file(
            STRINGS "${ASIO_INCLUDE_DIR}/asio/version.hpp"
            ASIO_VERSION_DEFINE_LINE
            REGEX
                "#define[ \t]+ASIO_VERSION[ \t]+[0-9]+[ \t]+//[ \t]+[0-9]+\.[0-9]+\.[0-9]+[ \t]*"
        )
        # Extracts the dotted version number after the comment as
        # ASIO_VERSION_STRING TODO: version matching
        string(REGEX
               REPLACE "#define ASIO_VERSION [0-9]+ // ([0-9]+\.[0-9]+\.[0-9]+)"
                       "\\1" ASIO_VERSION_STRING "${ASIO_VERSION_DEFINE_LINE}")
        message("Found Asio version ${ASIO_VERSION_STRING}")
    else()
        message("Looking for ASIO version failed. No version file found")
    endif()

    if(Asio_FIND_REQUIRED)
        find_package(Threads REQUIRED)
    else()
        find_package(Threads QUIET)
    endif()
    # error messages are not fatal to let this function handle errors
    find_package_handle_standard_args(
        Asio
        REQUIRED_VARS ASIO_INCLUDE_DIR Threads_FOUND
        VERSION_VAR ASIO_VERSION_STRING)

    if(Asio_FOUND)

        add_library(net::asio INTERFACE IMPORTED)
        target_include_directories(net::asio INTERFACE ${ASIO_INCLUDE_DIR})
        target_compile_definitions(net::asio INTERFACE ASIO_STANDALONE
                                                       ASIO_NO_DEPRECATED)
        target_link_libraries(net::asio INTERFACE Threads::Threads)
    endif()
    mark_as_advanced(ASIO_ROOT ASIO_INCLUDE_DIR ASIO_VERSION_STRING)
endif()
