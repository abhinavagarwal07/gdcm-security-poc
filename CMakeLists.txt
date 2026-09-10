cmake_minimum_required(VERSION 3.20)
project(gdcm_security_repros LANGUAGES CXX)

if(NOT DEFINED GDCM_DIR)
  message(FATAL_ERROR "Set GDCM_DIR to the matching GDCM build tree")
endif()

find_package(GDCM CONFIG REQUIRED PATHS "${GDCM_DIR}" NO_DEFAULT_PATH)
include("${GDCM_USE_FILE}")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Sanitizer harnesses: observation only.
set(REPRO_TARGETS
  finding01 finding02 finding03 finding03_propagation finding03_sentinel
  finding04 finding05 finding06)

foreach(target IN LISTS REPRO_TARGETS)
  add_executable(${target} "harnesses/${target}.cpp")
  target_link_libraries(${target} PRIVATE gdcmMSFF)
  target_compile_options(${target} PRIVATE -fno-omit-frame-pointer -g)
endforeach()

if(REPRO_SANITIZER STREQUAL "asan")
  set(REPRO_SAN_FLAG address)
elseif(REPRO_SANITIZER STREQUAL "ubsan")
  set(REPRO_SAN_FLAG undefined)
elseif(REPRO_SANITIZER STREQUAL "none")
  set(REPRO_SAN_FLAG "")
else()
  message(FATAL_ERROR "REPRO_SANITIZER must be asan, ubsan, or none")
endif()

if(REPRO_SAN_FLAG)
  foreach(target IN LISTS REPRO_TARGETS)
    target_compile_options(${target} PRIVATE -fsanitize=${REPRO_SAN_FLAG})
    target_link_options(${target} PRIVATE -fsanitize=${REPRO_SAN_FLAG})
  endforeach()
endif()

# Exploitation-primitive harnesses only build in the unsanitized profile: they
# replace the global array allocator, which a sanitizer runtime already owns,
# and they need stable function addresses across two runs (-no-pie).
if(REPRO_SANITIZER STREQUAL "none" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(finding01_exploit "harnesses/finding01_exploit.cpp")
  target_link_libraries(finding01_exploit PRIVATE gdcmMSFF)
  target_compile_options(finding01_exploit PRIVATE -fno-omit-frame-pointer -g -fno-pie)
  target_link_options(finding01_exploit PRIVATE -no-pie)

  # Exploitability research harnesses. Unlike finding01_exploit these use
  # default PIE and the system allocator, with instrumentation documented in
  # their source files.
  foreach(research finding01_groom finding03_leak)
    add_executable(${research} "harnesses/${research}.cpp")
    target_link_libraries(${research} PRIVATE gdcmMSFF ${CMAKE_DL_LIBS})
    target_compile_options(${research} PRIVATE -fno-omit-frame-pointer -g)
  endforeach()
endif()
