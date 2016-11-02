include(CheckCCompilerFlag)

###########################
### Check for global CFLAGS compiler support
###########################

set(MY_TEST
"-W"
"-Waggregate-return"
"-Wall"
"-Warray-bounds"
"-Wbad-function-cast"
"-Wcast-align"
"-Wcast-qual"
"-Wchar-subscripts"
"-Wcomment"
"-Wconversion"
"-Wdeclaration-after-statement"
"-Wdisabled-optimization"
"-Wdouble-promotion"
"-Werror"
"-Wextra"
"-Wfloat-equal"
"-Wformat"
"-Wformat-nonliteral"
"-Wformat-security"
"-Wformat-y2k"
"-Wignored-qualifiers"
"-Wimplicit"
"-Wimplicit-function-declaration"
"-Wimplicit-int"
"-Winit-self"
"-Winline"
"-Winvalid-pch"
"-Wjump-misses-init"
"-Wlogical-op"
"-Wlong-long"
"-Wmain"
"-Wmissing-braces"
"-Wmissing-declarations"
"-Wmissing-field-initializers"
"-Wmissing-format-attribute"
"-Wmissing-include-dirs"
"-Wmissing-noreturn"
"-Wmissing-parameter-type"
"-Wmissing-prototypes"
"-Wmultichar"
"-Wnested-externs"
"-Wno-endif-labels"
"-Wno-multichar"
"-Wnonnull"
"-Wold-style-declaration"
"-Wold-style-definition"
"-Woverlength-strings"
"-Wpacked"
"-Wpacked-bitfield-compat"
"-Wpadded"
"-Wparentheses"
"-Wpointer-arith"
"-Wpointer-sign"
"-Wredundant-decls"
"-Wreturn-type"
"-Wsequence-point"
"-Wshadow"
"-Wsign-compare"
"-Wsign-conversion"
"-Wstack-protector"
"-Wstrict-aliasing=3"
"-Wstrict-overflow=5"
"-Wstrict-prototypes"
"-Wsuggest-attribute=const"
"-Wsuggest-attribute=noreturn"
"-Wsuggest-attribute=pure"
"-Wswitch"
"-Wswitch-default"
"-Wswitch-enum"
"-Wsync-nand"
"-Wtraditional-conversions"
"-Wtrampolines"
"-Wtrigraphs"
"-Wundef"
"-Wuninitialized"
"-Wunknown-pragmas"
"-Wunreachable-code"
"-Wunsafe-loop-optimizations"
"-Wunsuffixed-float-constants"
"-Wunused"
"-Wunused-function"
"-Wunused-label"
"-Wunused-local-typedefs"
"-Wunused-parameter"
"-Wunused-value"
"-Wunused-variable"
"-Wvariadic-macros"
"-Wvector-operation-performance"
"-Wvla"
"-Wvolatile-register-var"
"-Wwrite-strings"
"-ffreestanding"
"-fno-builtin"
"-fno-common"
"-fstack-protector-all"
"-fstack-protector"
"-fPIC"
"-mno-gpopt"
"-pedantic"
"-std=c99"
"-strict-aliasing"
)

foreach(i ${MY_TEST})
  check_c_compiler_flag(${i} HAS_${i})
  if (HAS_${i})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${i}")
  endif()
endforeach()

check_c_compiler_flag(-Weverything HAS_WEVERYTHING_CFLAG)
if (HAS_WEVERYTHING_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Weverything")
endif()

check_c_compiler_flag(-std=c99 HAS_STDC99_CFLAG)
if (HAS_STDC99_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
endif()

check_c_compiler_flag(-Wall HAS_WALL_CFLAG)
if (HAS_WALL_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

check_c_compiler_flag(-Wextra HAS_WEXTRA_CFLAG)
if (HAS_WEXTRA_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
endif()

check_c_compiler_flag(-Werror HAS_WERROR_CFLAG)
if (HAS_WERROR_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
endif()

check_c_compiler_flag(-pedantic HAS_PEDANTIC_CFLAG)
if (HAS_PEDANTIC_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
endif()

check_c_compiler_flag(-Wunused-macros HAS_UNUSED_MACROS_CFLAG)
if (HAS_UNUSED_MACROS_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-macros")
endif()

### Disabled compile flags because of code incompatibility (yet)

# Used for GCC "m" modifier
check_c_compiler_flag(-Wformat=0 HAS_FORMAT_0_CFLAG)
if (HAS_FORMAT_0_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=0")
endif()

# Used for Clang "m" modifier
check_c_compiler_flag(-Wno-format-non-iso HAS_FORMAT_NON_ISO_CFLAG)
if (HAS_FORMAT_NON_ISO_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format-non-iso")
endif()

# Used for skip strutures alignement requirement
check_c_compiler_flag(-Wno-padded HAS_PADDED_CFLAG)
if (HAS_PADDED_CFLAG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-padded")
endif()

### Define mandatory CFLAGS

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_XOPEN_SOURCE=800")

###########################
### Check for DEBUG mode CFLAGS compiler support
###########################
if (${CMAKE_BUILD_TYPE} MATCHES "DEBUG")

  check_c_compiler_flag(-fsanitize=address HAS_SAN_ADDR_CFLAG)
  if (HAS_SAN_ADDR_CFLAG)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
  endif()

  check_c_compiler_flag(-fsanitize=undefined HAS_SAN_UNDEF_CFLAG)
  if (HAS_SAN_UNDEF_CFLAG)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")
  endif()

  ### Define mandatory DEBUG CFLAGS

  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3")

endif()

###########################
### Check for RELEASE CFLAGS compiler support
###########################
if (${CMAKE_BUILD_TYPE} MATCHES "RELEASE")

  ### Define mandatory RELEASE CFLAGS

  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

endif()

###########################
### continue to subdirectories
###########################

add_subdirectory(pam)
add_subdirectory(daemon)
