# - Try to find the Cyrus sasl library (gsasl)
#
# Once done this will define
#
#  CYRUSSASL_FOUND - System has gnutls
#  CYRUSSASL_INCLUDE_DIR - The gnutls include directory
#  CYRUSSASL_LIBRARIES - The libraries needed to use gnutls
#  CYRUSSASL_DEFINITIONS - Compiler switches required for using gnutls

# Adapted from FindGnuTLS.cmake, which is:
#   Copyright 2009, Brad Hards, <bradh@kde.org>
#
# Changes are Copyright 2009, Michele Caini, <skypjack@gmail.com>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


IF (CYRUSSASL_INCLUDE_DIR AND CYRUSSASL_LIBRARIES)
   # in cache already
   SET(CyrusSASL_FIND_QUIETLY TRUE)
ENDIF (CYRUSSASL_INCLUDE_DIR AND CYRUSSASL_LIBRARIES)

IF (APPLE)
   SET(CYRUSSASL_DEFINITIONS ${PC_CYRUSSASL_CFLAGS_OTHER})
   SET(PC_CYRUSSASL_INCLUDEDIR /usr/include)
   SET(PC_CYRUSSASL_LIBDIR /usr/lib)

ELSEIF (NOT WIN32)
   # use pkg-config to get the directories and then use these values
   # in the FIND_PATH() and FIND_LIBRARY() calls
   find_package(PkgConfig)
   pkg_check_modules(PC_CYRUSSASL libsasl2)
   SET(CYRUSSASL_DEFINITIONS ${PC_CYRUSSASL_CFLAGS_OTHER})
ENDIF ()

FIND_PATH(CYRUSSASL_INCLUDE_DIR sasl.h
   HINTS
   ${PC_CYRUSSASL_INCLUDEDIR}
   ${PC_CYRUSSASL_INCLUDE_DIRS}
   PATH_SUFFIXES sasl
   )

FIND_LIBRARY(CYRUSSASL_LIBRARIES NAMES sasl2
    HINTS
    ${PC_CYRUSSASL_LIBDIR}
    ${PC_CYRUSSASL_LIBRARY_DIRS}
  )

INCLUDE(FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set CYRUSSASL_FOUND to TRUE if 
# all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CYRUSSASL DEFAULT_MSG CYRUSSASL_LIBRARIES CYRUSSASL_INCLUDE_DIR)

MARK_AS_ADVANCED(CYRUSSASL_INCLUDE_DIR CYRUSSASL_LIBRARIES)
