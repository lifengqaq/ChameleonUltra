#include "iso7816_fs.h"
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
}

bool iso7816_fs_open(iso7816_fs_t *fs, uint8_t *image, uint16_t length) {
    memset(fs, 0, sizeof(*fs));
    if (!image || length < 8 || length > ISO7816_FS_MAX_IMAGE ||
            memcmp(image, "CFS1", 4) || image[4] != 1 || !image[5] ||
            image[5] > ISO7816_FS_MAX_NODES || be16(image + 6) != length) return false;
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
                n->sfi > 30 || n->access > 3 || n->aid_length > 16 ||
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

uint16_t iso7816_fs_exchange(iso7816_fs_t *fs, const uint8_t *command,
        uint16_t length, uint8_t *out, uint16_t cap) {
    if (!out || cap < 2) return 0;
    if (!fs || !fs->image || !fs->count) return sw(out, 0x6985);
    apdu_t a;
    if (!parse(command, length, &a)) return sw(out, 0x6700);
    if (a.cla != 0) return sw(out, 0x6E00);
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