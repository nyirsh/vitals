# The release version comes from VERSION (major.minor, each 0 to 99)
# Sets VITALS_VERSION ("1.5"), VITALS_APP_VERSION, the Vita package's ##.## form ("01.05"), and
# VITALS_MODULE_VERSION_MAJOR and _MINOR, the same number in the modules' headers (1 and 5)
set(VITALS_VERSION_FILE "${CMAKE_CURRENT_LIST_DIR}/VERSION")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${VITALS_VERSION_FILE}")
file(READ "${VITALS_VERSION_FILE}" VITALS_VERSION)
string(STRIP "${VITALS_VERSION}" VITALS_VERSION)
if(NOT VITALS_VERSION MATCHES "^([0-9]|[1-9][0-9])\\.([0-9]|[1-9][0-9])$")
    message(FATAL_ERROR "VERSION holds \"${VITALS_VERSION}\"; expected major.minor such as 1.0, "
        "each from 0 to 99 without leading zeros")
endif()
set(VITALS_MODULE_VERSION_MAJOR ${CMAKE_MATCH_1})
set(VITALS_MODULE_VERSION_MINOR ${CMAKE_MATCH_2})
# The package version pads both parts to two digits
set(VITALS_APP_VERSION "0${CMAKE_MATCH_1}.0${CMAKE_MATCH_2}")
string(REGEX REPLACE "^0([0-9][0-9])" "\\1" VITALS_APP_VERSION "${VITALS_APP_VERSION}")
string(REGEX REPLACE "\\.0([0-9][0-9])$" ".\\1" VITALS_APP_VERSION "${VITALS_APP_VERSION}")
