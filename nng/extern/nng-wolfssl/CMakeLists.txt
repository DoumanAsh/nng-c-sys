#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is distributed under the terms of the GPLv3, a
# copy of which should be located as the file COPYING in the
# same directory as this file.  A copy of the license may also be
# found online at https://opensource.org/licenses/GPL-3.0
#
# Commercial users may obtain a commercial license without GPLv3
# restrictions.  Please contact info@staysail.tech for details.
#
# SPDX-License-Identifier: GPL-3.0-only
#

# This module is intended to be directly included in the NNG build
# process.  It is not standalone.

include(CheckLibraryExists)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

message(WARNING "
        ============================================================
        wolfSSL NNG Module is GPLv3.0 (See COPYING)
        ============================================================
        Linking against wolfSSL changes license terms (GPL v3.0)!
        Consult a lawyer and the license files for details.
        ============================================================")

add_library(nng-wolfssl OBJECT wolfssl.c)

# WolfSSL does not have a CMake configuration, so we depend on it to be
# installed separately. Because the configuration is rather onerous, and
# really should be edited by hand, we also don't try to automate any of it
# using ExternalProject_Add.  (End users need to hand-configure it.)
find_package(wolfSSL REQUIRED)
target_link_libraries(nng-wolfssl PUBLIC ${WOLFSSL_LIBRARIES})
target_include_directories(nng-wolfssl PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_include_directories(nng-wolfssl PRIVATE ${PROJECT_SOURCE_DIR}/include)

# wolfssl/options.h in theory has defines already for these checks, but they
# are poorly documented, and might not be reliable -- so we check ourselves.
check_library_exists(wolfssl wolfSSL_CTX_LoadCRLBuffer "" NNG_WOLFSSL_HAVE_CRL)
check_library_exists(wolfssl wolfSSL_get_verify_result "" NNG_WOLFSSL_HAVE_VERIFY)
check_library_exists(wolfssl wolfSSL_CTX_set_default_passwd_cb "" NNG_WOLFSSL_HAVE_PASSWORD)
check_library_exists(wolfssl wolfSSL_get_peer_certificate "" NNG_WOLFSSL_HAVE_PEER_CERT)

macro(nng_wolfssl_define DEF)
    if (${DEF})
        target_compile_definitions(nng-wolfssl PRIVATE ${DEF})
    endif ()
endmacro()

# We want this file to be added into the nng project.
# This particular CMakeLists.txt only works in the context of
# of a the larger NNG project.

if (NNG_WOLFSSL_HAVE_CRL)
    target_compile_definitions(nng-wolfssl PRIVATE NNG_WOLFSSL_HAVE_CRL)
else ()
    message(WARNING "wolfSSL configured without CRL support.")
endif ()
if (NNG_WOLFSSL_HAVE_PASSWORD)
    target_compile_definitions(nng-wolfssl PRIVATE NNG_WOLFSSL_HAVE_PASSWORD)
else ()
    message(WARNING "wolfSSL configured without password support.")
endif ()
if (NNG_WOLFSSL_HAVE_PEER_CERT)
    target_compile_definitions(nng-wolfssl PRIVATE NNG_WOLFSSL_HAVE_PEER_CERT)
else ()
    message(WARNING "wolfSSL configured without peer cert chain support.")
endif ()