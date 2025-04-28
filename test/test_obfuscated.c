// Unicode-chaotic, nonsensical version of `test.c`
// NOTE: Save this file with UTF-8 encoding

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>
#include "爆風魚.h"  
#include "秘文.h"   
#include "大鳥.h"   

void 舞茸鳴門(uint8_t *鏡餅, size_t 鬼炊) {
    for (size_t 千歲 = 0; 千歲 < 鬼炊; 千歲++) {
        printf("%02X", 鏡餅[千歲]);
    }
    printf("\n");
}

void sub_a1b2c3() {
    printf("Hello World!\n");
}

int func_x9z8y7(int x) {
    return x * 1337;
}

void ÄÈŸDf() {
    int a = 1, b = 2, c = a + b;
    printf("%d\n", c);
}

void ÄÈŸdR() {
    char enc[] = { 'k', 'h', 'o', 'o', 'r', '\0' };
    for (int i = 0; i < strlen(enc); i++) {
        enc[i] -= 3;
    }
    printf("Decrypted: %s\n", enc);
}


void suspicious_memory_operation() {
    // Reserve and commit 1 page of memory
    LPVOID lpMemory = VirtualAlloc(
        NULL,                 // Let the system determine the address
        4096,                 // Size of allocation (1 page)
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE // Allow execute permissions
    );

    if (lpMemory == NULL) {
        printf("VirtualAlloc failed!\n");
        return;
    }

    char shellcode[] = "\x90\x90\x90\x90"; // Simple NOP sled

    // Fake "WriteProcessMemory" into our own process
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(
        GetCurrentProcess(),  // Handle to current process
        lpMemory,             // Target memory
        shellcode,            // Source buffer
        sizeof(shellcode),    // Size
        &bytesWritten         // Bytes actually written
    );

    if (!success) {
        printf("WriteProcessMemory failed!\n");
    } else {
        printf("Wrote %llu bytes to memory at %p\n", (unsigned long long)bytesWritten, lpMemory);
    }
}

int main() {
    uint8_t 白玉[] = "Hello, World!";
    size_t 桃 = strlen((char *)白玉);
	printf("Testing suspicious memory operation...\n");
    sub_a1b2c3();
    suspicious_memory_operation();
    printf("%d\n", func_x9z8y7(5));
    ÄÈŸDf();
    ÄÈŸdR();
    printf("[*] 原本: %s\n", 白玉);

    uint8_t 科科[] = "mysecretkey";

    printf("[*] 消息 RC4...\n");
    大鳥(白玉, 桃, 科科, strlen((char *)科科));
    printf("[+]: ");
    舞茸鳴門(白玉, 桃);

    printf("[*] 消息 爆風魚...\n");
    爆風魚(白玉, 桃, 科科, strlen((char *)科科));
    printf("[+] 爆風魚: ");
    舞茸鳴門(白玉, 桃);

    printf("[*] 消息...\n");
    秘文(白玉, 桃);
    printf("[+]: ");
    舞茸鳴門(白玉, 桃);


    return 0;
}
