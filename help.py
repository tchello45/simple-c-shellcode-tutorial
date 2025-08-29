import argparse

def create_shellcode_array(bin_file, output_var_name="shellcode"):
    try:
        with open(bin_file, 'rb') as f:
            shellcode_bytes = f.read()

        hex_strings = [f"0x{byte:02x}" for byte in shellcode_bytes]
        
        lines = []
        for i in range(0, len(hex_strings), 16):
            lines.append(", ".join(hex_strings[i:i+16]))

        shellcode_str = ",\n    ".join(lines)

        result = f"unsigned char {output_var_name}[] = {{\n    {shellcode_str}\n}};"
        
        print(result)

    except FileNotFoundError:
        print(f"Error: File '{bin_file}' not found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a C array from shellcode binary.")
    parser.add_argument("bin_file", help="Path to the shellcode binary file.")
    parser.add_argument("-o", "--output_var_name", default="shellcode", help="Name of the output C array variable.")
    args = parser.parse_args()

    create_shellcode_array(args.bin_file, args.output_var_name)