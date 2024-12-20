import os
import sys


def file_to_cpp_array(input_file: str, output_file: str, arg_name: str):
    CPP_TEMPLATE = """/*
Generation Code
*/

#pragma once

#include <array>

std::array<unsigned char, {size}> {arg_name} {{{data}}};
"""
    # 检查文件是否存在
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' does not exist.")
        return

    try:
        # 读取文件字节内容
        with open(input_file, "rb") as f:
            byte_data = f.read()

        # 将字节数据转换为十六进制字符串
        hex_data = ", ".join(f"0x{byte:02x}" for byte in byte_data)
        size = len(byte_data)

        # 填充模板
        cpp_output = CPP_TEMPLATE.format(size=size, arg_name=arg_name, data=hex_data)

        # 导出到指定文件
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(cpp_output)
        print(f"C++ array header file generated: {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python res_generate.py <input_file> <output_file>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    arg_name = sys.argv[3]
    file_to_cpp_array(input_path, output_path, arg_name)
