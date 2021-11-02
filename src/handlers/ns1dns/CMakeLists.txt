message(STATUS "Handler Module: NS1 DNS")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(lmdb++ INTERFACE)
target_include_directories(lmdb++ SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/vendor/lmdbxx)
target_link_libraries(lmdb++ INTERFACE ${CONAN_LIBS_LMDB})

corrade_add_static_plugin(VisorHandlerNS1Dns
        ${CMAKE_CURRENT_BINARY_DIR}
        NS1DnsHandler.conf
        orgid_db.cpp
        orgid_db.h
        types.h
        )

add_library(Visor::Handler::NS1Dns ALIAS VisorHandlerNS1Dns)

target_include_directories(VisorHandlerNS1Dns
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNS1Dns
        PUBLIC
        lmdb++
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::NS1Dns PARENT_SCOPE)

add_executable(unit-tests-handler-ns1dns
        tests/main.cpp
        tests/test_orgid_lookup.cpp
        tests/test_orgid_db.cpp
        )

target_link_libraries(unit-tests-handler-ns1dns
        PRIVATE
        Visor::Handler::NS1Dns)

add_test(NAME unit-tests-handler-ns1dns
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-handler-ns1dns
        )
