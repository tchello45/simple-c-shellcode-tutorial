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