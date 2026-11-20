#include "iso7816_fs.h"
#include "sm4.h"
#include "ulc_3des.h"
#include <stddef.h>
#include <string.h>

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint16_t sw(uint8_t *out, uint16_t status) {
    out[0] = (uint8_t)(status >> 8); out[1] = (uint8_t)status; return 2;
}
static uint16_t result(uint8_t *out, uint16_t size, uint16_t status) {
    sw(out + size, status); return (uint16_t)(size + 2);
}
void iso7816_fs_reset(iso7816_fs_t *fs) {
    fs->selected_df = 0; fs->selected_ef = ISO7816_FS_NONE;
    fs->current_record = 0; fs->pending_length = fs->pending_offset = 0;
    fs->pin_authenticated = fs->key_authenticated = fs->challenge_valid = false;
    memset(fs->challenge, 0, sizeof(fs->challenge));
}

bool iso7816_fs_open(iso7816_fs_t *fs, uint8_t *image, uint16_t length) {
    memset(fs, 0, sizeof(*fs));
    if (!image || length < 8 || length > ISO7816_FS_MAX_IMAGE ||
            memcmp(image, "CFS1", 4) || image[4] < 1 || image[4] > ISO7816_FS_VERSION_SM4 || !image[5] ||
            image[5] > ISO7816_FS_MAX_NODES || be16(image + 6) != length) return false;
    const bool protected = image[4] >= 2;
    const bool sm4 = image[4] == ISO7816_FS_VERSION_SM4;
    uint32_t offset = 8;
    for (uint8_t i = 0; i < image[5]; i++) {
        if (offset + 13 > length) return false;
        const uint8_t *p = image + offset;
        iso7816_fs_node_t *n = &fs->nodes[i];
        n->parent = p[0]; n->type = p[1]; n->fid = be16(p + 2);
        n->sfi = p[4]; n->access = p[5]; n->aid_length = p[6];
        n->fci_length = be16(p + 7); n->data_length = be16(p + 9);
        n->record_length = be16(p + 11);
        offset += 13;
        if (n->type > ISO7816_FS_RECORDS || !n->fid || n->fid == 0x3FFF ||
                n->sfi > 30 || n->access > (protected ? 63 : 3) || n->aid_length > 16 ||
                (n->aid_length && n->aid_length < 5) || n->fci_length > ISO7816_FS_MAX_FCI ||
                offset + n->aid_length + n->fci_length + n->data_length > length) return false;
        if (i == 0) {
            if (n->parent != ISO7816_FS_NONE || n->fid != 0x3F00 ||
                    n->type != ISO7816_FS_DF || n->aid_length) return false;
        } else if (n->parent >= i || fs->nodes[n->parent].type != ISO7816_FS_DF ||
                n->fid == 0x3F00) return false;
        if (n->type == ISO7816_FS_DF) {
            if (n->data_length || n->record_length || n->sfi || n->access) return false;
        } else {
            if (n->aid_length) return false;
            if (n->type == ISO7816_FS_BINARY && n->record_length) return false;
            if (n->type == ISO7816_FS_RECORDS && (!n->record_length ||
                    n->record_length > 253 || n->data_length % n->record_length ||
                    n->data_length / n->record_length > 254)) return false;
        }
        n->aid_offset = (uint16_t)offset; offset += n->aid_length;
        n->fci_offset = (uint16_t)offset; offset += n->fci_length;
        n->data_offset = (uint16_t)offset; offset += n->data_length;
        for (uint8_t j = 0; j < i; j++) {
            const iso7816_fs_node_t *other = &fs->nodes[j];
            if (other->parent == n->parent && (other->fid == n->fid ||
                    (n->sfi && other->sfi == n->sfi))) return false;
            if (n->aid_length && n->aid_length == other->aid_length &&
                    !memcmp(image + n->aid_offset, image + other->aid_offset, n->aid_length)) return false;
        }
    }
    if (protected) {
        if (offset + ISO7816_FS_SECURITY_SIZE != length || memcmp(image + offset, "SEC1", 4)) return false;
        const uint8_t *sec = image + offset;
        if (sec[10] > 12 || (sec[10] && sec[10] < 4) ||
                (sec[11] != 0 && sec[11] != 8 && sec[11] != 16) ||
                (sec[10] && sec[11]) || /* exactly one auth type per file system */
                sec[6] > 15 || sec[7] > 15 || sec[8] > sec[6] || sec[9] > sec[7] ||
                (sec[10] ? !sec[6] : (sec[6] || sec[8])) ||
                (sec[11] ? !sec[7] : (sec[7] || sec[9])) ||
                (!sec[10] && !sec[11]) || sec[40] > 2 || sec[43] ||
                (sm4 ? (sec[11] != SM4_BLOCK_SIZE ||
                    (sec[42] != ISO7816_FS_SM4_PADDED8 && sec[42] != ISO7816_FS_SM4_RAW16))
                    : sec[42] != 0)) return false;
        for (uint8_t j = 0; j < sec[10]; j++) if (sec[12+j] < '0' || sec[12+j] > '9') return false;
        for (uint8_t j = 0; j < image[5]; j++) {
            const uint8_t a = fs->nodes[j].access;
            if (((a & 20) && !(a & ISO7816_FS_READ)) || ((a & 40) && !(a & ISO7816_FS_WRITE)) ||
                    ((a & 4) && (a & 16)) || ((a & 8) && (a & 32)) ||
                    ((a & 12) && !sec[10]) || ((a & 48) && !sec[11])) return false;
        }
        fs->security_offset = (uint16_t)offset;
        offset += ISO7816_FS_SECURITY_SIZE;
    }
    if (offset != length) return false;
    fs->image = image; fs->length = length; fs->count = image[5];
    iso7816_fs_reset(fs);
    return true;
}

bool iso7816_fs_validate(const uint8_t *image, uint16_t length) {
    iso7816_fs_t parsed;
    return iso7816_fs_open(&parsed, (uint8_t *)(uintptr_t)image, length);
}

typedef struct {
    uint8_t cla, ins, p1, p2;
    const uint8_t *data;
    uint16_t lc, le;
    bool has_le;
} apdu_t;
static bool parse(const uint8_t *in, uint16_t size, apdu_t *a) {
    if (!in || size < 4 || size > 260) return false;
    memset(a, 0, sizeof(*a));
    a->cla = in[0]; a->ins = in[1]; a->p1 = in[2]; a->p2 = in[3];
    if (size == 4) return true;
    if (size == 5) {
        a->has_le = true; a->le = in[4] ? in[4] : 256; return true;
    }
    if (!in[4] || (size != (uint16_t)(5 + in[4]) && size != (uint16_t)(6 + in[4]))) return false;
    a->lc = in[4]; a->data = in + 5;
    if (size == (uint16_t)(6 + a->lc)) {
        a->has_le = true; a->le = in[size - 1] ? in[size - 1] : 256;
    }
    return true;
}

static uint8_t child(iso7816_fs_t *fs, uint8_t parent, uint16_t fid) {
    for (uint8_t i = 1; i < fs->count; i++)
        if (fs->nodes[i].parent == parent && fs->nodes[i].fid == fid) return i;
    return ISO7816_FS_NONE;
}
static uint8_t by_sfi(iso7816_fs_t *fs, uint8_t sfi) {
    if (!sfi) return fs->selected_ef;
    for (uint8_t i = 1; i < fs->count; i++)
        if (fs->nodes[i].parent == fs->selected_df && fs->nodes[i].type != ISO7816_FS_DF &&
                fs->nodes[i].sfi == sfi) return i;
    return ISO7816_FS_NONE;
}
static uint16_t control_info(iso7816_fs_t *fs, uint8_t index, bool fcp, uint8_t *out) {
    const iso7816_fs_node_t *n = &fs->nodes[index];
    if (!fcp && n->fci_length) {
        memcpy(out, fs->image + n->fci_offset, n->fci_length); return n->fci_length;
    }
    uint8_t f[32]; uint16_t k = 0;
    f[k++] = 0x82;
    if (n->type == ISO7816_FS_RECORDS) {
        f[k++] = 5; f[k++] = 2; f[k++] = 0;
        f[k++] = (uint8_t)(n->record_length >> 8); f[k++] = (uint8_t)n->record_length;
        f[k++] = (uint8_t)(n->data_length / n->record_length);
    } else { f[k++] = 1; f[k++] = n->type == ISO7816_FS_DF ? 0x38 : 1; }
    f[k++] = 0x83; f[k++] = 2; f[k++] = (uint8_t)(n->fid >> 8); f[k++] = (uint8_t)n->fid;
    if (n->type != ISO7816_FS_DF) {
        f[k++] = 0x80; f[k++] = 2; f[k++] = (uint8_t)(n->data_length >> 8); f[k++] = (uint8_t)n->data_length;
    }
    if (fs->security_offset && n->type != ISO7816_FS_DF) {
        f[k++] = 0x86; f[k++] = 2;
        f[k++] = !(n->access & 1) ? 0xFF : n->access & 4 ? 1 : n->access & 16 ? 2 : 0;
        f[k++] = !(n->access & 2) ? 0xFF : n->access & 8 ? 1 : n->access & 32 ? 2 : 0;
    }
    uint16_t pos = 0;
    if (!fcp) {
        out[pos++] = 0x6F; out[pos++] = (uint8_t)(k + 2 + (n->aid_length ? n->aid_length + 2 : 0));
        if (n->aid_length) {
            out[pos++] = 0x84; out[pos++] = n->aid_length;
            memcpy(out + pos, fs->image + n->aid_offset, n->aid_length); pos += n->aid_length;
        }
    }
    out[pos++] = 0x62; out[pos++] = (uint8_t)k;
    memcpy(out + pos, f, k); return (uint16_t)(pos + k);
}

static uint16_t select_file(iso7816_fs_t *fs, const apdu_t *a, uint8_t *out, uint16_t cap) {
    uint8_t target = ISO7816_FS_NONE;
    if (a->p2 != 0 && a->p2 != 4 && a->p2 != 0x0C) return sw(out, 0x6A86);
    if (a->p1 <= 2) {
        if (a->lc != 2) return sw(out, 0x6A86);
        uint16_t fid = be16(a->data);
        target = fid == 0x3F00 && a->p1 == 0 ? 0 : child(fs, fs->selected_df, fid);
        if (target != ISO7816_FS_NONE &&
                ((a->p1 == 1 && fs->nodes[target].type != ISO7816_FS_DF) ||
                 (a->p1 == 2 && fs->nodes[target].type == ISO7816_FS_DF))) target = ISO7816_FS_NONE;
    } else if (a->p1 == 3) {
        if (a->lc) return sw(out, 0x6A86);
        target = fs->selected_df ? fs->nodes[fs->selected_df].parent : 0;
    } else if (a->p1 == 4) {
        if (a->lc < 5 || a->lc > 16) return sw(out, 0x6A86);
        for (uint8_t i = 1; i < fs->count; i++) {
            const iso7816_fs_node_t *n = &fs->nodes[i];
            if (n->aid_length == a->lc && !memcmp(fs->image + n->aid_offset, a->data, a->lc)) { target = i; break; }
        }
    } else if (a->p1 == 8 || a->p1 == 9) {
        if (!a->lc || (a->lc & 1)) return sw(out, 0x6A86);
        target = a->p1 == 8 ? 0 : fs->selected_df;
        for (uint16_t pos = 0; pos < a->lc; pos += 2) {
            uint16_t fid = be16(a->data + pos);
            if (pos == 0 && a->p1 == 8 && fid == 0x3F00) continue;
            if (fs->nodes[target].type != ISO7816_FS_DF) { target = ISO7816_FS_NONE; break; }
            target = child(fs, target, fid);
            if (target == ISO7816_FS_NONE) break;
        }
    } else return sw(out, 0x6A86);
    if (target == ISO7816_FS_NONE) return sw(out, 0x6A82);
    if (a->p2 != 0x0C) {
        fs->pending_length = control_info(fs, target, a->p2 == 4, fs->pending);
        uint16_t count = fs->pending_length;
        if (a->has_le && count > a->le) count = a->le;
        if (count + 2 > cap) { fs->pending_length = 0; return sw(out, 0x6700); }
        memcpy(out, fs->pending, count); fs->pending_offset = count;
    }
    if (fs->nodes[target].type == ISO7816_FS_DF) {
        if (fs->selected_df != target) {
            fs->pin_authenticated = fs->key_authenticated = false;
        }
        fs->selected_df = target; fs->selected_ef = ISO7816_FS_NONE;
    } else {
        fs->selected_df = fs->nodes[target].parent; fs->selected_ef = target;
    }
    fs->current_record = 0;
    if (a->p2 == 0x0C) return sw(out, 0x9000);
    uint16_t sent = fs->pending_offset;
    uint16_t remaining = (uint16_t)(fs->pending_length - sent);
    if (!remaining) fs->pending_length = fs->pending_offset = 0;
    return result(out, sent, remaining ? (uint16_t)(0x6100 | remaining) : 0x9000);
}


/* SEC1 byte 42 selects the SM4 challenge layout in CFS v3 (reserved in v2).
 * EXTERNAL AUTHENTICATE consumes one challenge and compares one block. */
static uint16_t authentication(iso7816_fs_t *fs, const apdu_t *a, uint8_t *out, uint16_t cap) {
    if (!fs->security_offset) return sw(out, 0x6D00);
    uint8_t *sec = fs->image + fs->security_offset;
    const bool sm4 = sec[42] != 0;
    const uint8_t challenge_length = sec[42] == ISO7816_FS_SM4_RAW16 ? SM4_BLOCK_SIZE : 8;
    if (a->ins == 0x84) {
        fs->challenge_valid = false;
        if (!sec[11]) return sw(out, 0x6D00);
        if (a->p1 || a->p2 || a->lc || !a->has_le || a->le != challenge_length) return sw(out, 0x6A86);
        if (!sec[9]) return sw(out, 0x6983);
        if (cap < challenge_length + 2u) return sw(out, 0x6700);
        memset(fs->challenge, 0, sizeof(fs->challenge));
        if (!fs->random || !fs->random(fs->challenge, challenge_length)) return sw(out, 0x6985);
        if (sm4 && challenge_length == 8) fs->challenge[8] = 0x80;
        memcpy(out, fs->challenge, challenge_length); fs->challenge_valid = true;
        return result(out, challenge_length, 0x9000);
    }
    const bool pin = a->ins == 0x20;
    const uint8_t length = sec[pin ? 10 : 11];
    if (!length) return sw(out, 0x6D00);
    if (a->p1 != (pin ? 0 : sec[41]) || a->p2 != sec[pin ? 4 : 5]) return sw(out, 0x6A88);
    if (!a->lc || a->has_le) return sw(out, 0x6700); /* never a counter query */
    uint8_t *remaining = sec + (pin ? 8 : 9);
    if (!*remaining) return sw(out, 0x6983);
    uint8_t expected[16]; memset(expected, 0xFF, sizeof(expected));
    uint8_t expected_length;
    if (pin) {
        fs->pin_authenticated = false;
        if (sec[40] == 0) { expected_length = length; memcpy(expected, sec + 12, length); }
        else {
            expected_length = 8;
            uint8_t nibble = sec[40] == 2 ? 2 : 0;
            if (sec[40] == 2) expected[0] = (uint8_t)(0x20 | length);
            for (uint8_t i = 0; i < length; i++, nibble++) {
                uint8_t digit = (uint8_t)(sec[12+i] - '0');
                if (!(nibble & 1)) expected[nibble/2] = (uint8_t)((digit << 4) | 0x0F);
                else expected[nibble/2] = (uint8_t)((expected[nibble/2] & 0xF0) | digit);
            }
        }
    } else {
        fs->key_authenticated = false;
        if (!fs->challenge_valid) return sw(out, 0x6985);
        fs->challenge_valid = false;
        expected_length = sm4 ? SM4_BLOCK_SIZE : 8;
        if (a->lc != expected_length) {
            memset(fs->challenge, 0, sizeof(fs->challenge));
            return sw(out, 0x6700);
        }
        if (sm4) {
            sm4_encrypt_block(expected, fs->challenge, sec + 24);
        } else {
            uint8_t key[16], iv[8] = {0};
            memcpy(key, sec + 24, length);
            if (length == 8) memcpy(key + 8, key, 8);
            ulc_tdes_enc_cbc(expected, fs->challenge, 8, key, iv);
            memset(key, 0, sizeof(key));
        }
        memset(fs->challenge, 0, sizeof(fs->challenge));
    }
    if (a->lc != expected_length) { memset(expected, 0, sizeof(expected)); return sw(out, 0x6700); }
    uint8_t difference = 0;
    for (uint8_t i = 0; i < expected_length; i++) difference |= (uint8_t)(expected[i] ^ a->data[i]);
    memset(expected, 0, sizeof(expected));
    if (difference) {
        --*remaining; fs->dirty = true;
        return sw(out, (uint16_t)(0x63C0 | *remaining));
    }
    if (*remaining != sec[pin ? 6 : 7]) fs->dirty = true;
    *remaining = sec[pin ? 6 : 7];
    if (pin) fs->pin_authenticated = true; else fs->key_authenticated = true;
    return sw(out, 0x9000);
}

uint16_t iso7816_fs_exchange(iso7816_fs_t *fs, const uint8_t *command,
        uint16_t length, uint8_t *out, uint16_t cap) {
    if (!out || cap < 2) return 0;
    if (!fs || !fs->image || !fs->count) return sw(out, 0x6985);
    apdu_t a;
    if (!parse(command, length, &a)) return sw(out, 0x6700);
    if (a.cla != 0) return sw(out, 0x6E00);
    if (a.ins != 0x82 && a.ins != 0x84) fs->challenge_valid = false;
    if (a.ins == 0x20 || a.ins == 0x82 || a.ins == 0x84) {
        fs->pending_length = fs->pending_offset = 0;
        return authentication(fs, &a, out, cap);
    }
    if (a.ins == 0xC0) {
        if (a.p1 || a.p2 || a.lc || !a.has_le) return sw(out, 0x6A86);
        if (fs->pending_offset >= fs->pending_length) return sw(out, 0x6985);
        uint16_t count = (uint16_t)(fs->pending_length - fs->pending_offset);
        if (count > a.le) count = a.le;
        if (count + 2 > cap) return sw(out, 0x6700);
        memcpy(out, fs->pending + fs->pending_offset, count); fs->pending_offset += count;
        uint16_t remaining = (uint16_t)(fs->pending_length - fs->pending_offset);
        if (!remaining) fs->pending_length = fs->pending_offset = 0;
        return result(out, count, remaining ? (uint16_t)(0x6100 | remaining) : 0x9000);
    }
    fs->pending_length = fs->pending_offset = 0;
    if (a.ins == 0xA4) return select_file(fs, &a, out, cap);
    bool binary = a.ins == 0xB0 || a.ins == 0xD6;
    bool records = a.ins == 0xB2 || a.ins == 0xDC;
    bool write = a.ins == 0xD6 || a.ins == 0xDC;
    if (!binary && !records) return sw(out, 0x6D00);
    if (write ? (!a.lc || a.has_le) : (a.lc || !a.has_le)) return sw(out, 0x6700);
    uint8_t index = fs->selected_ef;
    uint16_t offset = 0;
    if (binary) {
        if (a.p1 & 0x80) {
            if (a.p1 & 0x60) return sw(out, 0x6A86);
            if (!(a.p1 & 0x1F)) return sw(out, 0x6A86);
            index = by_sfi(fs, a.p1 & 0x1F); offset = a.p2;
        } else offset = (uint16_t)((a.p1 << 8) | a.p2);
    } else {
        if ((a.p2 & 7) != 4 || (a.p2 >> 3) == 31) return sw(out, 0x6A86);
        index = by_sfi(fs, a.p2 >> 3);
    }
    if (index == ISO7816_FS_NONE) return sw(out, 0x6986);
    const iso7816_fs_node_t *n = &fs->nodes[index];
    if (n->type != (binary ? ISO7816_FS_BINARY : ISO7816_FS_RECORDS)) return sw(out, 0x6981);
    if (!(n->access & (write ? ISO7816_FS_WRITE : ISO7816_FS_READ))) return sw(out, 0x6982);
    if ((n->access & (write ? ISO7816_FS_WRITE_PIN : ISO7816_FS_READ_PIN)) && !fs->pin_authenticated)
        return sw(out, 0x6982);
    if ((n->access & (write ? ISO7816_FS_WRITE_KEY : ISO7816_FS_READ_KEY)) && !fs->key_authenticated)
        return sw(out, 0x6982);
    uint16_t count = write ? a.lc : a.le;
    uint16_t status = 0x9000;
    if (records) {
        uint8_t record = a.p1 ? a.p1 : (index == fs->selected_ef ? fs->current_record : 0);
        if (!record || record > n->data_length / n->record_length) return sw(out, 0x6A83);
        if (write && a.lc != n->record_length) return sw(out, 0x6700);
        if (!write && a.le != 256 && a.le != n->record_length)
            return sw(out, (uint16_t)(0x6C00 | n->record_length));
        count = n->record_length;
        offset = (uint16_t)((record - 1) * n->record_length);
        if (!write && count + 2 > cap) return sw(out, 0x6700);
        fs->current_record = record;
    } else {
        if (offset > n->data_length || (write && (uint32_t)offset + count > n->data_length)) return sw(out, 0x6B00);
        if (!write && count > n->data_length - offset) {
            count = (uint16_t)(n->data_length - offset); status = 0x6282;
        }
    }
    if (!write && count + 2 > cap) return sw(out, 0x6700);
    if (binary && index != fs->selected_ef) fs->current_record = 0;
    fs->selected_ef = index;
    if (write) {
        memcpy(fs->image + n->data_offset + offset, a.data, count); fs->dirty = true;
        return sw(out, 0x9000);
    }
    memcpy(out, fs->image + n->data_offset + offset, count);
    return result(out, count, status);
}
