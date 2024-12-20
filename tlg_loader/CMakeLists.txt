cmake_minimum_required(VERSION 3.27)
project(tlg_loader)

set(CMAKE_CXX_STANDARD 23)

# 设置输入和输出路径
set(INPUT_FILE_DRIVER "${CMAKE_SOURCE_DIR}/../dummy/output/x64/Release/dummy.sys")
set(OUTPUT_FILE_DRIVER "${CMAKE_SOURCE_DIR}/driver_res.h")

set(INPUT_FILE_KDU "${CMAKE_SOURCE_DIR}/resource/kdu.exe")
set(OUTPUT_FILE_KDU "${CMAKE_SOURCE_DIR}/kdu_res.h")

set(INPUT_FILE_DRV64_DLL "${CMAKE_SOURCE_DIR}/resource/drv64.dll")
set(OUTPUT_FILE_DRV64_DLL "${CMAKE_SOURCE_DIR}/drv64_res.h")

# 生成资源文件
add_custom_command(
        OUTPUT ${OUTPUT_FILE_DRIVER}
        COMMAND python ${CMAKE_SOURCE_DIR}/scripts/res_generate.py ${INPUT_FILE_DRIVER} ${OUTPUT_FILE_DRIVER} tlgDriverData
        DEPENDS ${INPUT_FILE_DRIVER}
        COMMENT \"Generating driver_res.h from dummy.sys\"
)
add_custom_command(
        OUTPUT ${OUTPUT_FILE_KDU}
        COMMAND python ${CMAKE_SOURCE_DIR}/scripts/res_generate.py ${INPUT_FILE_KDU} ${OUTPUT_FILE_KDU} kduData
        DEPENDS ${INPUT_FILE_KDU}
        COMMENT \"Generating kdu\"
)
add_custom_command(
        OUTPUT ${OUTPUT_FILE_DRV64_DLL}
        COMMAND python ${CMAKE_SOURCE_DIR}/scripts/res_generate.py ${INPUT_FILE_DRV64_DLL} ${OUTPUT_FILE_DRV64_DLL} drv64Data
        DEPENDS ${INPUT_FILE_DRV64_DLL}
        COMMENT \"Generating drv64\"
)

add_custom_target(generate_res_header ALL DEPENDS ${OUTPUT_FILE_DRIVER} ${OUTPUT_FILE_KDU} ${OUTPUT_FILE_DRV64_DLL})

# multi-processor compilation
if(MSVC)
    include(ProcessorCount)
    ProcessorCount(PROCESSOR_COUNT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP${PROCESSOR_COUNT}")
    set(CMAKE_VS_MSBUILD_COMMAND "${CMAKE_VS_MSBUILD_COMMAND} /p:CL_MPCount=${PROCESSOR_COUNT} /m")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /PDB:${CMAKE_BINARY_DIR}/Release/tlg_loader.pdb")
set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)


set(CPM_SOURCE_CACHE "${CMAKE_SOURCE_DIR}/.cache/cpm")
include(cmake/CPM.cmake)

CPMAddPackage("gh:chinosk6/libKDU@1.4.3")  # libKDU

set(RESOURCE_FILES ${CMAKE_SOURCE_DIR}/app.rc
        utils.hpp)
add_executable(tlg_loader main.cpp
        driver_res.h
        drv64_res.h
        kdu_res.h
        ${RESOURCE_FILES}
        tlgPipe.hpp
        device_control.hpp
)
set_target_properties(tlg_loader PROPERTIES OUTPUT_NAME "tlg_starter")

if (WIN32)
    target_link_libraries(tlg_loader PRIVATE user32)
endif()

set_property(TARGET tlg_loader APPEND_STRING PROPERTY LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator'\"")

add_dependencies(tlg_loader generate_res_header)

CPMAddPackage(
        NAME lazy_importer
        GITHUB_REPOSITORY JustasMasiulis/lazy_importer
        GIT_TAG master
        DOWNLOAD_ONLY True
)

target_link_libraries(tlg_loader PUBLIC ntdll libKDU)  # libKDU
