// test_obfuscated.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main() {
    sub_a1b2c3();
    printf("%d\n", func_x9z8y7(5));
    ÄÈŸDf();
    ÄÈŸdR();
    return 0;
}
