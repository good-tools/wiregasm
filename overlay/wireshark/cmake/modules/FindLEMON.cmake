#
# - Find lemon executable
#

include(FindChocolatey)

find_program(LEMON_EXECUTABLE
  NAMES
    lemon
  PATHS
    ${CHOCOLATEY_BIN_PATH}
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LEMON DEFAULT_MSG LEMON_EXECUTABLE)

MARK_AS_ADVANCED(LEMON_EXECUTABLE)

# lemon a file

MACRO(ADD_LEMON_FILES _source _generated)
    set(_lemonpardir ${CMAKE_SOURCE_DIR}/tools/lemon)
    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_out ${CMAKE_CURRENT_BINARY_DIR}/${_basename})

      ADD_CUSTOM_COMMAND(
         OUTPUT
          ${_out}.c
          # These files are generated as side-effect
          ${_out}.h
          ${_out}.out
         COMMAND ${LEMON_EXECUTABLE}
           -T${_lemonpardir}/lempar.c
           -d.
           ${_in}
         DEPENDS
           ${_in}
           ${_lemonpardir}/lempar.c
      )

      LIST(APPEND ${_source} ${_in})
      LIST(APPEND ${_generated} ${_out}.c)
      if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
        set_source_files_properties(${_out}.c PROPERTIES COMPILE_OPTIONS "/w")
      elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set_source_files_properties(${_out}.c PROPERTIES COMPILE_OPTIONS "-Wno-unused-parameter")
      else()
        # Build with some warnings for lemon generated code
      endif()
    ENDFOREACH (_current_FILE)
ENDMACRO(ADD_LEMON_FILES)