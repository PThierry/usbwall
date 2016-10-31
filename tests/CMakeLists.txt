###########################
### Start Unitary tests internal system
###########################

enable_testing()
find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
#set(LIBS ${LIBS} ${CHECK_LIBRARIES} isti_clib)

include_directories(. ../src)

add_executable(check_devusb check_devusb.c)
#target_link_libraries(check_devusb ${LIBS})
add_test(check_devusb ${EXECUTABLE_OUTPUT_PATH}/check_devusb)
