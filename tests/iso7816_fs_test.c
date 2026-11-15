#include "iso7816_fs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t image[ISO7816_FS_MAX_IMAGE], output[262];
static iso7816_fs_t fs;
static uint16_t used, response_length;
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void node(uint8_t parent, uint8_t type, uint16_t fid, uint8_t sfi,
        uint8_t access, const uint8_t *aid, uint8_t aid_len,
        const uint8_t *data, uint16_t data_len, uint16_t record_len) {
    uint8_t *p = image + used;
    p[0] = parent; p[1] = type; put16(p + 2, fid); p[4] = sfi; p[5] = access;
    p[6] = aid_len; put16(p + 7, 0); put16(p + 9, data_len); put16(p + 11, record_len);
    used += 13;
    if (aid_len) { memcpy(image + used, aid, aid_len); used += aid_len; }
    if (data_len) { memcpy(image + used, data, data_len); used += data_len; }
}
static void fixture(void) {
    memset(image, 0, sizeof(image)); memcpy(image, "CFS1", 4); image[4] = 1; image[5] = 5; used = 8;
    node(255, 0, 0x3F00, 0, 0, NULL, 0, NULL, 0, 0);
    const uint8_t aid[] = {0xF0,1,2,3,4,5,6};
    node(0, 0, 0x1001, 0, 0, aid, sizeof(aid), NULL, 0, 0);
    const uint8_t binary[] = {0,4,'A','B','C','D'};
    node(1, 1, 0x1002, 2, 3, NULL, 0, binary, sizeof(binary), 0);
    const uint8_t records[] = {1,2,3,4,5,6,7,8};
    node(1, 2, 0x1003, 4, 3, NULL, 0, records, sizeof(records), 4);
    node(1, 1, 0x1004, 5, 0, NULL, 0, binary, sizeof(binary), 0);
    put16(image + 6, used); assert(iso7816_fs_open(&fs, image, used));
}
static uint16_t exchange(const uint8_t *command, uint16_t length) {
    memset(output, 0xA5, sizeof(output));
    response_length = iso7816_fs_exchange(&fs, command, length, output + 1, 260);
    assert(response_length >= 2 && response_length <= 260);
    assert(output[0] == 0xA5 && output[261] == 0xA5);
    return (uint16_t)((output[response_length - 1] << 8) | output[response_length]);
}
#define APDU(...) exchange((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
static void select_app(void) { assert(APDU(0,0xA4,4,0x0C,7,0xF0,1,2,3,4,5,6) == 0x9000); }

int main(void) {
    fixture();
    for (uint16_t n = 0; n < used; n++) assert(!iso7816_fs_validate(image, n));
    uint8_t broken[ISO7816_FS_MAX_IMAGE]; memcpy(broken, image, used);
    broken[8] = 0; assert(!iso7816_fs_validate(broken, used));
    memcpy(broken, image, used); broken[21] = 1; assert(!iso7816_fs_validate(broken, used));
    assert(APDU(0,0xB0,0,0,1) == 0x6986);
    assert(APDU(0,0xA4,4,0,5,0xF0,9,9,9,9) == 0x6A82);
    select_app();
    assert(APDU(0,0xA4,0,4,2,0x10,2) == 0x9000 && output[1] == 0x62);
    assert(APDU(0,0xB0,0,2,4) == 0x9000 && !memcmp(output + 1, "ABCD", 4));
    assert(APDU(0,0xD6,0,3,2,0xAA,0xBB) == 0x9000 && fs.dirty);
    assert(APDU(0,0xB0,0,2,4) == 0x9000);
    const uint8_t changed[] = {'A',0xAA,0xBB,'D'}; assert(!memcmp(output + 1, changed, 4));
    assert(APDU(0,0xB0,0,0,0) == 0x6282 && response_length == 8);
    memcpy(broken, image, used);
    assert(APDU(0,0xD6,0,5,2,9,9) == 0x6B00 && !memcmp(image, broken, used));
    assert(APDU(0,0xD6,0,0,3,9,9) == 0x6700 && !memcmp(image, broken, used));
    iso7816_fs_reset(&fs);
    assert(APDU(0,0xB0,0,0,1) == 0x6986);
    assert(APDU(0,0xA4,8,0x0C,6,0x3F,0,0x10,1,0x10,2) == 0x9000);
    assert(APDU(0,0xB0,0,2,4) == 0x9000 && !memcmp(output + 1, changed, 4));
    assert(iso7816_fs_open(&fs, image, used)); /* simulated slot save/reload */
    select_app();
    assert(APDU(0,0xB2,2,0x24,0) == 0x9000 && !memcmp(output + 1, "\5\6\7\10", 4));
    assert(APDU(0,0xB2,2,0x24,2) == 0x6C04);
    assert(APDU(0,0xDC,1,0x24,4,0xAA,0xBB,0xCC,0xDD) == 0x9000);
    assert(APDU(0,0xB2,1,0x24,4) == 0x9000 && output[1] == 0xAA);
    assert(APDU(0,0xB2,3,0x24,4) == 0x6A83);
    assert(APDU(0,0xB2,1,0x20,4) == 0x6A86);
    assert(APDU(0,0xA4,0,0x0C,2,0x10,4) == 0x9000);
    assert(APDU(0,0xB0,0,0,1) == 0x6982);
    assert(APDU(0,0xD6,0,0,1,0) == 0x6982);
    assert(APDU(0x80,0x84,0,0,8) == 0x6E00);
    assert(APDU(0,0x84,0,0,8) == 0x6D00);
    assert((APDU(0,0xA4,0,0,2,0x3F,0,2) & 0xFF00) == 0x6100);
    assert(APDU(0,0xC0,0,0,0) == 0x9000);
    assert(APDU(0,0xC0,0,0,0) == 0x6985);
    /* All byte values and short/maximum APDU sizes exercise parser bounds. */
    uint32_t seed = 0xC001CAFE;
    uint8_t command[260];
    for (uint16_t n = 0; n <= 260; n++) {
        for (unsigned repeat = 0; repeat < 32; repeat++) {
            for (uint16_t j = 0; j < n; j++) {
                seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; command[j] = (uint8_t)seed;
            }
            (void)exchange(command, n);
            assert(iso7816_fs_validate(image, used));
        }
    }
    /* Mutated images must never produce out-of-bounds node offsets. */
    fixture();
    for (unsigned repeat = 0; repeat < 4096; repeat++) {
        memcpy(broken, image, used);
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        broken[seed % used] ^= (uint8_t)(1u << (seed % 8));
        iso7816_fs_t candidate;
        if (iso7816_fs_open(&candidate, broken, used)) {
            for (uint16_t n = 4; n <= 260; n += 8) {
                uint16_t got = iso7816_fs_exchange(&candidate, command, n, output, sizeof(output));
                assert(got >= 2 && got <= sizeof(output));
            }
        }
    }
    fixture(); select_app();
    assert(APDU(0,0xA4,0,0x0C,2,0x10,2) == 0x9000);
    uint8_t tiny[3] = {0xA5,0xA5,0xA5};
    const uint8_t read[] = {0,0xB0,0,0,4};
    assert(iso7816_fs_exchange(&fs,read,sizeof(read),tiny,1) == 0);
    assert(tiny[0] == 0xA5);
    assert(iso7816_fs_exchange(&fs,read,sizeof(read),tiny,2) == 2);
    assert(tiny[0] == 0x67 && tiny[1] == 0 && tiny[2] == 0xA5);
    puts("ISO7816 filesystem: hierarchy, selection, binary/record writes, access, reload, GET RESPONSE and bounds passed");
    return 0;
}