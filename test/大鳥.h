#ifndef 大鳥_H
#define 大鳥_H
#include <stdint.h>
#include <stddef.h>

void 大鳥(uint8_t *長組, size_t 長度, const uint8_t *鍵, size_t 鍵長) {
    uint8_t 狂[256];
    uint8_t 一 = 0, 二 = 0, 三, 五;

    for (三 = 0; 三 < 256; 三++) 狂[三] = 三;

    for (三 = 0, 二 = 0; 三 < 256; 三++) {
        二 = (二 + 狂[三] + 鍵[三 % 鍵長]) & 0xFF;
        五 = 狂[三];
        狂[三] = 狂[二];
        狂[二] = 五;
    }

    for (三 = 0, 一 = 0, 二 = 0; 三 < 長度; 三++) {
        一 = (一 + 1) & 0xFF;
        二 = (二 + 狂[一]) & 0xFF;
        五 = 狂[一];
        狂[一] = 狂[二];
        狂[二] = 五;
        長組[三] ^= 狂[(狂[一] + 狂[二]) & 0xFF];
    }
}

#endif