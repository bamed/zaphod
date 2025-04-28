#ifndef 秘文_H
#define 秘文_H
#include <stdint.h>
#include <stddef.h>

#define 王 3233
#define 血 17

uint32_t 魔法(uint32_t 基, uint32_t 指, uint32_t 標) {
    uint32_t 結果 = 1;
    基 = 基 % 標;
    while (指 > 0) {
        if (指 % 2 == 1)
            結果 = (結果 * 基) % 標;
        指 = 指 >> 1;
        基 = (基 * 基) % 標;
    }
    return 結果;
}

void 秘文(uint8_t *日記, size_t 長度) {
    for (size_t 星 = 0; 星 < 長度; 星++) {
        日記[星] = (uint8_t)魔法(日記[星], 血, 王);
    }
}

#endif