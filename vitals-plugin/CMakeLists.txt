cmake_minimum_required(VERSION 3.16)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")

project(HENkaku)
set(VITALS_HTTP_PROVIDER_PATH "vs0:/data/external/vitals/native/vitals_http.suprx"
    CACHE STRING "Where the kernel plugin loads the HTTP provider from")
if(NOT VITALS_HTTP_PROVIDER_PATH MATCHES "^(vs0|ux0|ur0):/[A-Za-z0-9_./-]+$")
    message(FATAL_ERROR "HTTP provider requires an absolute vs0, ux0 or ur0 path")
endif()

set(CMAKE_C_FLAGS "-Wl,-q -Wall -Wextra -Werror -O3 -std=gnu11 -mgeneral-regs-only")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/../tls13-vita/include
)

# The module header carries the release version from ../VERSION
include(${CMAKE_CURRENT_SOURCE_DIR}/../version.cmake)
configure_file(vitals.yml.in vitals.yml @ONLY)

add_executable(vitals.elf
	main.c
	native_contract.c
	native_module_api.c
	hook_guard.c
	post_start.c
	reauth.c
	tls13_loader.c
	../tls13-vita/src/path.c
)
target_compile_definitions(vitals.elf PRIVATE
	VITALS_HTTP_PROVIDER_PATH="${VITALS_HTTP_PROVIDER_PATH}"
)
target_link_libraries(vitals.elf
	SceSysclibForDriver_stub
	SceSysmemForDriver_stub
	SceIofilemgrForDriver_stub
	SceThreadmgrForDriver_stub
	SceCpuForDriver_stub
	taihenModuleUtils_stub
	taihenForKernel_stub
	SceDebugForDriver_stub
	SceModulemgrForDriver_stub
	SceModulemgrForKernel_stub
	SceSysrootForDriver_stub
	SceSysrootForKernel_stub
	SceKernelUtilsForDriver_stub
)

set_target_properties(vitals.elf
	PROPERTIES LINK_FLAGS "-nostdlib"
	COMPILE_FLAGS "-D__VITA_KERNEL__"
)

add_custom_target(vitals.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_CURRENT_BINARY_DIR}/vitals.yml vitals.elf vitals.velf
	COMMAND vita-make-fself -c vitals.velf vitals.skprx
)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_target(vitals_kernel_register_check
	COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_kernel_registers.py
		$<TARGET_FILE:vitals.elf>
	DEPENDS vitals.elf
	VERBATIM
)
add_dependencies(vitals.skprx vitals_kernel_register_check)
