cmake_minimum_required(VERSION 3.7)

project(CROSS C)
set(CMAKE_C_STANDARD 11)

set(CC gcc)
# set(CC clang)
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -pedantic -Wuninitialized -march=native -O3 -g3")
# set(SANITIZE "-fsanitize=address -g3")
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${SANITIZE}")
message("Compilation flags: ${CMAKE_C_FLAGS}")


#Define problem (RSDP or RSDPG), type (SIG_SIZE, BALANCED, SPEED), and category
set(PROBLEM_DEFINE "RSDP")
set(TYPE_DEFINE "BALANCED")
#If speed, set this
#set(OMIT_SEED_TREE "NO_TREES=1")
set(OMIT_SEED_TREE "")
#Else
#set(OMIT_SEED_TREE "")
set(CATEGORY_DEFINE "CATEGORY_1")

# Define required compile-time parameters
add_compile_definitions(${PROBLEM_DEFINE}=1 ${TYPE_DEFINE}=1 ${CATEGORY_DEFINE}=1 ${OMIT_SEED_TREE})

# By default, employ optimized implementation
set(REFERENCE 1) # Set to 1 for reference implementation

find_library(KECCAK_LIB keccak)
if(NOT KECCAK_LIB)
    set(STANDALONE_KECCAK 1)
endif()

# Selection of specialized compilation units differing between ref and opt implementations.
set(REFERENCE_CODE_DIR ../../Reference_Implementation)
set(OPTIMIZED_CODE_DIR ../../Optimized_Implementation)

if(REFERENCE EQUAL 1)
    message("Compiling portable reference code")
    set(BASE_DIR ${REFERENCE_CODE_DIR})
    set(SPEC_HEADERS
        ${BASE_DIR}/include/sha3.h
        ${BASE_DIR}/include/csprng_hash.h
        ${BASE_DIR}/include/restr_arith.h
        ${BASE_DIR}/include/fp_arith.h)
    set(SPEC_SOURCES
        ${BASE_DIR}/lib/merkle.c
        ${BASE_DIR}/lib/seedtree.c
        ${BASE_DIR}/lib/CROSS.c)
else()
    message("Compiling optimized AVX2 code")
    set(BASE_DIR ${OPTIMIZED_CODE_DIR})
    set(SPEC_HEADERS
        ${BASE_DIR}/include/align.h
        ${BASE_DIR}/include/fips202x4.h
        ${BASE_DIR}/include/KeccakP-1600-times4-SnP.h
        ${BASE_DIR}/include/SIMD256-config.h
        ${BASE_DIR}/include/sha3.h
        ${BASE_DIR}/include/csprng_hash.h
        ${BASE_DIR}/include/architecture_detect.h
        ${BASE_DIR}/include/restr_arith.h
        ${BASE_DIR}/include/fp_arith.h)
    set(SPEC_SOURCES
        ${BASE_DIR}/lib/fips202x4.c
        ${BASE_DIR}/lib/KeccakP-1600-times4-SIMD256.c
        ${BASE_DIR}/lib/merkle.c
        ${BASE_DIR}/lib/seedtree.c
        ${BASE_DIR}/lib/CROSS.c)
endif()

set(COMMON_DIR ${REFERENCE_CODE_DIR})
set(HEADERS
    ${SPEC_HEADERS}
    ${COMMON_DIR}/include/api.h
    ${COMMON_DIR}/include/CROSS.h
    ${COMMON_DIR}/include/pack_unpack.h
    ${COMMON_DIR}/include/fips202.h
    ${COMMON_DIR}/include/keccakf1600.h
    ${COMMON_DIR}/include/parameters.h
    ${COMMON_DIR}/include/seedtree.h
    ${COMMON_DIR}/include/merkle_tree.h)

if(STANDALONE_KECCAK)
    message("Employing standalone SHA-3")
    set(KECCAK_EXTERNAL_LIB "")
    set(KECCAK_EXTERNAL_ENABLE "")
    list(APPEND FALLBACK_SOURCES ${COMMON_DIR}/lib/keccakf1600.c)
    list(APPEND FALLBACK_SOURCES ${COMMON_DIR}/lib/fips202.c)
else()
    message("Employing libkeccak")
    set(KECCAK_EXTERNAL_LIB keccak)
    set(KECCAK_EXTERNAL_ENABLE "-DSHA_3_LIBKECCAK")
endif()

set(SOURCES
    ${SPEC_SOURCES}
    ${FALLBACK_SOURCES}
    ${COMMON_DIR}/lib/csprng_hash.c
    ${COMMON_DIR}/lib/pack_unpack.c
    ${COMMON_DIR}/lib/keccakf1600.c
    ${COMMON_DIR}/lib/fips202.c
    ${COMMON_DIR}/lib/sign.c)

# Create a static library
add_library(cross_static STATIC ${SOURCES})

# Create a shared library
add_library(cross_shared SHARED ${SOURCES})

# Specify include directories
target_include_directories(cross_static PUBLIC ${COMMON_DIR}/include)
target_include_directories(cross_shared PUBLIC ${COMMON_DIR}/include)

# Set compile definitions for the libraries
target_compile_definitions(cross_static PUBLIC ${PROBLEM_DEFINE}=1 ${TYPE_DEFINE}=1 ${CATEGORY_DEFINE}=1 ${OMIT_SEED_TREE})
target_compile_definitions(cross_shared PUBLIC ${PROBLEM_DEFINE}=1 ${TYPE_DEFINE}=1 ${CATEGORY_DEFINE}=1 ${OMIT_SEED_TREE})

# Link external libraries if required
if(KECCAK_EXTERNAL_LIB)
    target_link_libraries(cross_static ${KECCAK_EXTERNAL_LIB})
    target_link_libraries(cross_shared ${KECCAK_EXTERNAL_LIB})
endif()

# Optionally install the library
install(TARGETS cross_static cross_shared
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

install(FILES ${HEADERS} DESTINATION include)

# If you have a main file, create an executable
add_executable(main main.c)
target_link_libraries(main cross_static)
target_include_directories(main PUBLIC ${COMMON_DIR}/include)

# Set compile definitions for the main executable
target_compile_definitions(main PUBLIC ${PROBLEM_DEFINE}=1 ${TYPE_DEFINE}=1 ${CATEGORY_DEFINE}=1 ${OMIT_SEED_TREE})

