# A simple Proof of Concept on how to execute "shellcode" in C programs

This repository shows you a simple proof of concept on how to use shellcode in a C program.
Our shellcode will consist of a simplified payload which just ends the program via a syscall.

## Requirements

- A Linux environment
- GCC (GNU Compiler Collection)
- NASM (Netwide Assembler)
- objdump
- Basic knowledge of C programming and assembly language

## Workflow

1. Write the shellcode in assembly language.
2. Assemble the shellcode using NASM.
3. Link the shellcode object file to create an executable.
4. Use objdump to analyze the executable and extract the shellcode.
5. Integrate the shellcode into a C program.
6. Compile and run the C program to execute the shellcode.

## What is shellcode?

Shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is typically written in assembly language and is designed to be injected into a running process to perform a specific task, such as spawning a shell or executing a command.

## Creating our shellcode

1. We need to write the shellcode in assembly language. For this example, we will use NASM (Netwide Assembler) for the x86-64 ISA (Instruction Set Architecture).

```assembly
global _start

section .text
_start:
    ; Your shellcode goes here
    mov rax, 60     ; syscall: exit
    mov rdi, 0      ; status: 0
    syscall
```

Explanation:

This shellcode is a simple program that exits cleanly by invoking the `exit` syscall. Here's a breakdown of the instructions:

1. `mov rax, 60`: This instruction moves the value `60` into the `rax` register. In the context of Linux x86-64 assembly, `60` is the syscall number for `exit`.

2. `mov rdi, 0`: This instruction moves the value `0` into the `rdi` register. The `rdi` register is used to pass the first argument to syscalls, and for `exit`, this argument is the exit status code (like the `return 0` statement in C).

3. `syscall`: This instruction triggers the syscall specified by the value in the `rax` register (in this case, `exit`), causing the program to execute the syscall and therefore exit.

Now that we have our payload, we need to assemble and link it to create an executable.

```bash
nasm -f elf64 -o shellcode.o shellcode.asm
ld -o shellcode shellcode.o
```

Explanation:

The `nasm` command assembles the `shellcode.asm` file into an object file (`shellcode.o`) in the ELF64 format. The `ld` command then links the object file to create an executable named `shellcode`.

Now we can use `objdump` to analyze the executable and extract the shellcode.

```bash
objdump -d shellcode
```

The output should look like this:

```bash
0000000000400080 <_start>:
  400080:       b8 3c 00 00 00          mov    $0x3c,%eax
  400085:       bf 00 00 00 00          mov    $0x0,%edi
  40008a:       0f 05                   syscall
```

Using this output, we can extract the shellcode bytes.

```c
unsigned char shellcode[] = {
    0xb8, 0x3c, 0x00, 0x00, 0x00,
    0xbf, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x05};
```

## Integrating the shellcode into a C program

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {
    0xb8, 0x3c, 0x00, 0x00, 0x00,
    0xbf, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x05};

int main()
{
    printf("Shellcode length: %zu bytes\n", sizeof(shellcode));

    void (*func_ptr)();
    func_ptr = (void (*)())shellcode;

    size_t pagesize = 4096;
    void *aligned_addr = (void *)((long)shellcode & ~(pagesize - 1));
    int result = mprotect(aligned_addr, sizeof(shellcode) + (shellcode - (unsigned char *)aligned_addr), PROT_READ | PROT_WRITE | PROT_EXEC);

    if (result == -1)
    {
        perror("mprotect failed");
        return 1;
    }

    printf("Executing shellcode...\n");

    func_ptr();

    printf("If you see this, the shellcode did not work :(\n");

    return 0;
}
```

Explanation:

The `void (*func_ptr)();` line declares a function pointer named `func_ptr` that points to a function taking no arguments and returning no value. The line `func_ptr = (void (*)())shellcode;` assigns the address of the shellcode to this function pointer, effectively allowing us to call the shellcode as if it were a regular function.

The `size_t pagesize = 4096;` line defines the size of a memory page (4KB on most systems).

The line `void *aligned_addr = (void *)((long)shellcode & ~(pagesize - 1));` may seem complex, so we can break it down:

1. `(long)shellcode` converts the shellcode pointer to a long integer, allowing us to perform bitwise operations on it.
2. `pagesize - 1` calculates the size of the page minus one (i.e., 4095).
3. `~(pagesize - 1)` takes the bitwise NOT of the previous result, creating a mask that has all bits set to 1 except for the lower 12 bits (which are set to 0).
4. Finally, `((long)shellcode & ~(pagesize - 1))` aligns the shellcode address down to the nearest page boundary by clearing the lower 12 bits.

The `mprotect` call is used to change the memory protection of the page containing the shellcode, allowing it to be executed. If `mprotect` fails, an error message is printed and the program exits.

Finally, the shellcode is executed by calling `func_ptr()`. If the shellcode executes successfully, the program will not return to the point after the call, and the message indicating failure will not be printed.

## Compile and Run

To compile the C program with the embedded shellcode, use the following command:

```bash
gcc -o shellcode_exec shellcode_exec.c
```

This will create an executable named `shellcode_exec`. You can run it with:

```bash
./shellcode_exec
```

Make sure to replace `shellcode_exec.c` with the actual filename of your C source file containing the shellcode.

## Conclusion

In this tutorial, we have covered the process of creating, embedding, and executing shellcode within a C program. This involves using assembly language to create the shellcode, and then using C to manage memory and execute the shellcode safely. Making the memory executable is a crucial step in this process, as it allows the shellcode to run without being blocked by modern operating system security features. In a real-world scenario, this would not be possible and would require additional and more advanced techniques to bypass security measures.
