/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "iso14443_4.h"
#include <string.h>

static const uint16_t frame_sizes[9] = {16, 24, 32, 40, 48, 64, 96, 128, 256};

uint16_t iso_dep_crc_a(const uint8_t *data, uint16_t size) {
    uint16_t crc = 0x6363;
    while (size--) {
        uint8_t b = *data++ ^ (uint8_t)crc;
        b ^= (uint8_t)(b << 4);
        crc = (crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ (b >> 4);
    }
    return crc;
}

void iso_dep_picc_reset(iso_dep_picc_t *s) {
    memset(s, 0, sizeof(*s));
    s->frame_size = 16; /* Safe until RATS supplies FSDI. */
}

bool iso_dep_picc_rats(iso_dep_picc_t *s, uint8_t parameter) {
    uint8_t fsdi = parameter >> 4;
    if (fsdi > 8 || (parameter & 15) == 15) return false;
    iso_dep_picc_reset(s);
    s->frame_size = frame_sizes[fsdi];
    s->m_cid = parameter & 15;
    return true;
}

static uint8_t picc_header(iso_dep_picc_t *s, uint8_t *buf, uint8_t pcb) {
    buf[0] = pcb | (s->m_cid_supported ? 8 : 0);
    if (s->m_cid_supported) buf[1] = s->m_cid;
    return s->m_cid_supported ? 2 : 1;
}

static void picc_ack(iso_dep_picc_t *s, iso_dep_send_fn send, void *context) {
    uint8_t frame[2];
    uint8_t n = picc_header(s, frame, 0xA2 | s->m_block_num);
    send(context, frame, n);
}

static void picc_next(iso_dep_picc_t *s, iso_dep_send_fn send, void *context) {
    uint8_t off = picc_header(s, s->last_frame, 0x02 | s->m_block_num);
    uint16_t capacity = s->frame_size - off - 2; /* CRC is appended by NFCT. */
    uint16_t n = s->m_resp_len - s->response_offset;
    if (n > capacity) n = capacity;
    s->sending_chain = s->response_offset + n < s->m_resp_len;
    if (s->sending_chain) s->last_frame[0] |= 0x10;
    memcpy(s->last_frame + off, s->m_resp_buf + s->response_offset, n);
    s->response_offset += n;
    s->last_frame_len = off + n;
    s->m_block_num ^= 1;
    s->waiting_wtx = false;
    s->awaiting_response = false;
    send(context, s->last_frame, s->last_frame_len);
}

void iso_dep_picc_respond(iso_dep_picc_t *s, iso_dep_send_fn send, void *context) {
    if (s->m_response_ready) {
        s->m_response_ready = false;
        s->response_offset = 0;
        picc_next(s, send, context);
        return;
    }
    if (++s->wtx_count > 8) {
        s->m_resp_buf[0] = 0x64;
        s->m_resp_buf[1] = 0x00;
        s->m_resp_len = 2;
        s->m_apdu_pending = false;
        s->response_offset = 0;
        picc_next(s, send, context);
        return;
    }
    uint8_t frame[3];
    uint8_t n = picc_header(s, frame, 0xF2);
    frame[n++] = 59;
    s->waiting_wtx = true;
    send(context, frame, n);
}

iso_dep_picc_result_t iso_dep_picc_receive(iso_dep_picc_t *s, const uint8_t *frame,
        uint16_t size, iso_dep_send_fn send, void *context) {
    if (!size || s->frame_size < 16) return ISO_DEP_IGNORED;
    uint8_t pcb = frame[0];
    bool cid = (pcb & 8) != 0;
    uint16_t off = cid ? 2 : 1;
    if (size < off || (cid && ((frame[1] & 0xF0) || frame[1] != s->m_cid)) ||
            (!cid && s->m_cid_supported)) return ISO_DEP_IGNORED;
    if (cid) s->m_cid_supported = true;
    if ((pcb & 0xF7) == 0xC2 && size == off) {
        send(context, frame, size);
        iso_dep_picc_reset(s);
        return ISO_DEP_DESELECTED;
    }
    if ((pcb & 0xF7) == 0xF2) {
        /* An S(WTX) response completes our request: transmit exactly ONE frame. */
        if (s->waiting_wtx && size == off + 1 && frame[off] == 59)
            iso_dep_picc_respond(s, send, context);
        return ISO_DEP_IGNORED;
    }
    if ((pcb & 0xE6) == 0xA2 && size == off) {
        if ((pcb & 0x10) || (pcb & 1) != s->m_block_num) {
            if (s->last_frame_len) send(context, s->last_frame, s->last_frame_len);
        } else if (s->sending_chain) {
            picc_next(s, send, context);
        }
        return ISO_DEP_IGNORED;
    }
    /* NAD is not advertised and is deliberately rejected. Reserved bits too. */
    if ((pcb & 0xE6) != 0x02 || size <= off) return ISO_DEP_IGNORED;
    if ((pcb & 1) != s->m_block_num) {
        if (s->receiving_chain) picc_ack(s, send, context);
        else if (s->last_frame_len) send(context, s->last_frame, s->last_frame_len);
        return ISO_DEP_IGNORED;
    }
    if (s->awaiting_response) {
        iso_dep_picc_respond(s, send, context);
        return ISO_DEP_IGNORED;
    }
    if (s->sending_chain) return ISO_DEP_IGNORED;
    if (!s->receiving_chain) s->m_apdu_len = 0;
    uint16_t n = size - off;
    if (n > sizeof(s->m_apdu_buf) - s->m_apdu_len) {
        iso_dep_picc_reset(s);
        return ISO_DEP_IGNORED;
    }
    memcpy(s->m_apdu_buf + s->m_apdu_len, frame + off, n);
    s->m_apdu_len += n;
    s->receiving_chain = (pcb & 0x10) != 0;
    if (s->receiving_chain) {
        s->m_block_num ^= 1;
        picc_ack(s, send, context);
        return ISO_DEP_IGNORED;
    }
    s->m_apdu_pending = true;
    s->m_response_ready = false;
    s->m_resp_len = 0;
    s->awaiting_response = true;
    s->wtx_count = 0;
    return ISO_DEP_APDU;
}

bool iso_dep_reader_init(iso_dep_reader_t *s, const uint8_t *ats, uint16_t size) {
    if (size < 2 || ats[0] != size || (ats[1] & 0x80) || (ats[1] & 15) > 8)
        return false;
    uint16_t off = 2;
    if (ats[1] & 0x10) off++;
    uint8_t fwi = 4;
    if (ats[1] & 0x20) {
        if (off >= size) return false;
        fwi = ats[off++] >> 4;
        if (fwi > 14) return false;
    }
    if (ats[1] & 0x40) off++;
    if (off > size) return false;
    s->block_num = 0;
    s->frame_size = frame_sizes[ats[1] & 15];
    /* RC522 transmits/receives through a 64-byte FIFO, RATS advertises FSD=48. */
    if (s->frame_size > 64) s->frame_size = 64;
    s->fwt_ms = (uint16_t)(((uint32_t)303 << fwi) / 1000 + 6);
    return true;
}

static uint16_t append_crc(uint8_t *buf, uint16_t size) {
    uint16_t crc = iso_dep_crc_a(buf, size);
    buf[size] = (uint8_t)crc;
    buf[size + 1] = crc >> 8;
    return size + 2;
}

iso_dep_result_t iso_dep_reader_exchange(iso_dep_reader_t *s, const uint8_t *apdu,
        uint16_t size, uint8_t *response, uint16_t *response_size,
        iso_dep_transceive_fn exchange, void *context) {
    uint16_t capacity = *response_size;
    *response_size = 0;
    if (!size || size > ISO_DEP_MAX_APDU || s->frame_size < 16 || s->frame_size > 64)
        return ISO_DEP_PROTOCOL_ERROR;
    uint8_t tx[64], rx[64], saved[64];
    uint16_t tx_size = 0, saved_size = 0, offset = 0, sent = 0, used = 0;
    uint16_t timeout = s->fwt_ms;
    uint8_t retries = 0, wtx = 0;
    bool transmitting = true, build = true, received = false;
    for (unsigned steps = 0; steps < 128; steps++) {
        if (build) {
            sent = size - offset;
            if (sent > s->frame_size - 3) sent = s->frame_size - 3;
            tx[0] = 0x02 | s->block_num | (offset + sent < size ? 0x10 : 0);
            memcpy(tx + 1, apdu + offset, sent);
            tx_size = append_crc(tx, sent + 1);
            memcpy(saved, tx, tx_size);
            saved_size = tx_size;
            build = false;
        }
        uint16_t rx_size = sizeof(rx);
        if (!exchange(context, tx, tx_size, rx, &rx_size, timeout)) return ISO_DEP_IO_ERROR;
        timeout = s->fwt_ms;
        if (rx_size < 3 || rx_size > 48) return ISO_DEP_PROTOCOL_ERROR;
        uint16_t crc = iso_dep_crc_a(rx, rx_size - 2);
        if (rx[rx_size-2] != (uint8_t)crc || rx[rx_size-1] != (uint8_t)(crc >> 8))
            return ISO_DEP_PROTOCOL_ERROR;
        uint8_t pcb = rx[0];
        uint16_t header = (pcb & 8) ? 2 : 1;
        uint16_t payload = rx_size - 2;
        if (payload < header || ((pcb & 8) && rx[1] != 0)) return ISO_DEP_PROTOCOL_ERROR;
        if ((pcb & 0xF7) == 0xF2) {
            if (payload != header + 1 || rx[header] == 0 || rx[header] > 59 || ++wtx > 8)
                return ISO_DEP_PROTOCOL_ERROR;
            uint32_t wait = (uint32_t)s->fwt_ms * rx[header];
            if (wait > 5000) return ISO_DEP_LIMIT;
            timeout = (uint16_t)wait;
            memcpy(tx, rx, rx_size);
            tx_size = rx_size;
            continue;
        }
        if ((pcb & 0xE6) == 0xA2) {
            if (!transmitting || payload != header) return ISO_DEP_PROTOCOL_ERROR;
            if ((pcb & 0x10) || (pcb & 1) == s->block_num) {
                if (++retries > 2) return ISO_DEP_LIMIT;
                memcpy(tx, saved, saved_size);
                tx_size = saved_size;
                continue;
            }
            if (offset + sent >= size) return ISO_DEP_PROTOCOL_ERROR;
            offset += sent;
            s->block_num ^= 1;
            retries = 0;
            build = true;
            continue;
        }
        if ((pcb & 0xE6) != 0x02 || (transmitting && offset + sent != size))
            return ISO_DEP_PROTOCOL_ERROR;
        if ((pcb & 1) != s->block_num) {
            if (!received || ++retries > 2) return ISO_DEP_PROTOCOL_ERROR;
        } else {
            uint16_t n = payload - header;
            if (n > capacity - used) return ISO_DEP_OVERFLOW;
            memcpy(response + used, rx + header, n);
            used += n;
            s->block_num ^= 1;
            retries = 0;
            received = true;
            transmitting = false;
            if (!(pcb & 0x10)) {
                *response_size = used;
                return ISO_DEP_OK;
            }
        }
        /* R(ACK) carries the number of the NEXT I-block, not the previous one. */
        tx[0] = 0xA2 | s->block_num | (pcb & 8);
        if (pcb & 8) tx[1] = 0;
        tx_size = append_crc(tx, header);
    }
    return ISO_DEP_LIMIT;
}
