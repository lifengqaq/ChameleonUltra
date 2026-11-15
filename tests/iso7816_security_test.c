#include "iso7816_fs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t image[128], response[262];
static iso7816_fs_t fs;
static const uint8_t challenge[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
static bool random_ok(uint8_t *out, uint8_t length) {
    assert(length == 8); memcpy(out, challenge, 8); return true;
}
static bool random_fail(uint8_t *out, uint8_t length) { (void)out; (void)length; return false; }
static void fixture(void) {
    memset(image, 0, sizeof(image)); memcpy(image, "CFS1", 4);
    image[4] = 2; image[5] = 2; image[7] = 82;
    image[8] = 255; image[10] = 0x3F;
    image[21] = 0; image[22] = 1; image[23] = 0x10; image[24] = 1;
    image[26] = ISO7816_FS_READ | ISO7816_FS_WRITE | ISO7816_FS_READ_PIN | ISO7816_FS_WRITE_KEY;
    image[31] = 4; memcpy(image + 34, "ABCD", 4);
    uint8_t *sec = image + 38; memcpy(sec, "SEC1", 4);
    sec[6] = sec[7] = sec[8] = sec[9] = 3;
    sec[10] = 6; sec[11] = 8; memset(sec + 12, 0xFF, 28); memcpy(sec + 12, "000000", 6);
    const uint8_t key[8] = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
    memcpy(sec + 24, key, 8);
    assert(iso7816_fs_open(&fs, image, 82));
}
static uint16_t apdu(const uint8_t *command, uint16_t length) {
    memset(response, 0xA5, sizeof(response));
    uint16_t n = iso7816_fs_exchange(&fs, command, length, response + 1, 260);
    assert(n >= 2 && n <= 260 && response[0] == 0xA5 && response[261] == 0xA5);
    return (uint16_t)((response[n-1] << 8) | response[n]);
}
#define APDU(...) apdu((const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
static void select_file(void) { assert(APDU(0,0xA4,0,0x0C,2,0x10,1) == 0x9000); }
static uint16_t bad_pin(void) { return APDU(0,0x20,0,0,6,'1','1','1','1','1','1'); }
static uint16_t good_pin(void) { return APDU(0,0x20,0,0,6,'0','0','0','0','0','0'); }
int main(void) {
    fixture();
    for (uint16_t n = 0; n < 82; n++) assert(!iso7816_fs_validate(image, n));
    select_file(); assert(APDU(0,0xB0,0,0,4) == 0x6982);
    assert(APDU(0,0x20,0,0) == 0x6700 && image[46] == 3);
    assert(APDU(0,0x20,0,1,6,'0','0','0','0','0','0') == 0x6A88 && image[46] == 3);
    assert(bad_pin() == 0x63C2 && image[46] == 2 && fs.dirty);
    assert(bad_pin() == 0x63C1 && image[46] == 1);
    assert(iso7816_fs_open(&fs, image, 82)); /* live counter is in saved slot image */
    assert(image[46] == 1 && !fs.pin_authenticated);
    select_file(); assert(good_pin() == 0x9000 && image[46] == 3);
    assert(APDU(0,0xB0,0,0,4) == 0x9000 && !memcmp(response + 1, "ABCD", 4));
    assert(bad_pin() == 0x63C2 && APDU(0,0xB0,0,0,4) == 0x6982);
    assert(good_pin() == 0x9000); iso7816_fs_reset(&fs); select_file();
    assert(APDU(0,0xB0,0,0,4) == 0x6982);
    fixture(); assert(bad_pin() == 0x63C2 && bad_pin() == 0x63C1 && bad_pin() == 0x63C0);
    assert(good_pin() == 0x6983); iso7816_fs_reset(&fs); assert(good_pin() == 0x6983);
    assert(iso7816_fs_open(&fs, image, 82) && good_pin() == 0x6983);

    fixture(); select_file();
    assert(APDU(0,0xD6,0,0,1,0xAA) == 0x6982);
    assert(APDU(0,0x84,0,0,8) == 0x6985); /* no deterministic RNG fallback */
    fs.random = random_ok;
    assert(APDU(0,0x84,0,0,8) == 0x9000 && !memcmp(response + 1, challenge, 8));
    /* DES known-answer vector: 133457799BBCDFF1 / 0123456789ABCDEF. */
    assert(APDU(0,0x82,0,0,8,0x85,0xE8,0x13,0x54,0x0F,0x0A,0xB4,0x05) == 0x9000);
    assert(APDU(0,0xD6,0,0,1,0xAA) == 0x9000 && image[34] == 0xAA);
    assert(APDU(0,0x82,0,0,8,0x85,0xE8,0x13,0x54,0x0F,0x0A,0xB4,0x05) == 0x6985);
    assert(APDU(0,0x84,0,0,8) == 0x9000);
    assert(APDU(0,0x82,0,0,8,0,0,0,0,0,0,0,0) == 0x63C2);
    assert(APDU(0,0x82,0,0,8,0,0,0,0,0,0,0,0) == 0x6985 && image[47] == 2);
    fs.random = random_fail; assert(APDU(0,0x84,0,0,8) == 0x6985 && image[47] == 2);
    fs.random = random_ok; assert(APDU(0,0x84,0,0,8) == 0x9000);
    assert(APDU(0,0x82,0,0,8,0,0,0,0,0,0,0,0) == 0x63C1);
    assert(APDU(0,0x84,0,0,8) == 0x9000);
    assert(APDU(0,0x82,0,0,8,0,0,0,0,0,0,0,0) == 0x63C0);
    assert(APDU(0,0x84,0,0,8) == 0x6983);

    fixture(); image[78] = 2; assert(iso7816_fs_open(&fs, image, 82));
    assert(APDU(0,0x20,0,0,8,0x26,0,0,0,0xFF,0xFF,0xFF,0xFF) == 0x9000);
    fixture(); image[78] = 1; assert(iso7816_fs_open(&fs, image, 82));
    assert(APDU(0,0x20,0,0,8,0,0,0,0xFF,0xFF,0xFF,0xFF,0xFF) == 0x9000);
    fixture(); image[26] = ISO7816_FS_READ_PIN;
    assert(!iso7816_fs_validate(image, 82)); /* missing base read grant */
    puts("ISO7816 security: PIN encodings, DES challenge, remaining attempts, blocked state, reset and replay passed");
    return 0;
}