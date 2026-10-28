cmake_minimum_required(VERSION 3.16)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")

project(HENkaku)

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
	redirects.c
	dns_watch.c
	dns_message.c
	diag.c
	tls13_loader.c
	../tls13-vita/src/path.c
	../tls13-vita/src/host_map.c
	../tls13-vita/src/redirect_list.c
)
set(VITALS_DEBUG 0 CACHE STRING "Debug output: 0, 1 or 2 (1 and up log every DNS query)")
target_compile_definitions(vitals.elf PRIVATE
	VITALS_DEBUG=${VITALS_DEBUG}
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
# The user stub for the plugin's system calls, which vitals-http links (../vitals-http)
add_custom_target(vitals_stubs ALL
	COMMAND vita-elf-export kernel vitals.elf ${CMAKE_CURRENT_BINARY_DIR}/vitals.yml vitals_exports.yml
	COMMAND vita-libs-gen vitals_exports.yml stubs
	COMMAND make -C stubs
	DEPENDS vitals.elf
)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_target(vitals_kernel_register_check
	COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_kernel_registers.py
		$<TARGET_FILE:vitals.elf>
	DEPENDS vitals.elf
	VERBATIM
)
add_dependencies(vitals.skprx vitals_kernel_register_check)
