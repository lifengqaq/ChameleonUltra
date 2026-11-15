/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ISO14443_4_H
#define ISO14443_4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ISO_DEP_MAX_APDU 260
#define ISO_DEP_MAX_FRAME 256

typedef void (*iso_dep_send_fn)(void *context, const uint8_t *frame, uint16_t size);
/* Reader callback exchanges complete frames INCLUDING CRC_A. */
typedef bool (*iso_dep_transceive_fn)(void *context, const uint8_t *tx, uint16_t tx_size,
                                    uint8_t *rx, uint16_t *rx_size, uint16_t timeout_ms);

typedef struct {
    uint8_t m_block_num;
    bool m_cid_supported;
    uint8_t m_cid;
    uint8_t m_apdu_buf[ISO_DEP_MAX_APDU];
    uint16_t m_apdu_len;
    volatile bool m_apdu_pending;
    uint8_t m_resp_buf[ISO_DEP_MAX_APDU];
    uint16_t m_resp_len;
    volatile bool m_response_ready;
    uint16_t frame_size;
    uint16_t response_offset;
    uint8_t last_frame[ISO_DEP_MAX_FRAME];
    uint16_t last_frame_len;
    bool receiving_chain;
    bool sending_chain;
    bool awaiting_response;
    bool waiting_wtx;
    uint8_t wtx_count;
} iso_dep_picc_t;

typedef enum {
    ISO_DEP_IGNORED, ISO_DEP_APDU, ISO_DEP_DESELECTED
} iso_dep_picc_result_t;

void iso_dep_picc_reset(iso_dep_picc_t *s);
bool iso_dep_picc_rats(iso_dep_picc_t *s, uint8_t parameter);
/* PICC input/output excludes CRC_A; RF driver checks/appends it. */
iso_dep_picc_result_t iso_dep_picc_receive(iso_dep_picc_t *s, const uint8_t *frame,
                                        uint16_t size, iso_dep_send_fn send, void *context);
void iso_dep_picc_respond(iso_dep_picc_t *s, iso_dep_send_fn send, void *context);

typedef struct {
    uint8_t block_num;
    uint16_t frame_size;
    uint16_t fwt_ms;
} iso_dep_reader_t;

typedef enum {
    ISO_DEP_OK, ISO_DEP_IO_ERROR, ISO_DEP_PROTOCOL_ERROR, ISO_DEP_OVERFLOW, ISO_DEP_LIMIT
} iso_dep_result_t;

bool iso_dep_reader_init(iso_dep_reader_t *s, const uint8_t *ats, uint16_t size);
iso_dep_result_t iso_dep_reader_exchange(iso_dep_reader_t *s, const uint8_t *apdu,
    uint16_t size, uint8_t *response, uint16_t *response_size,
    iso_dep_transceive_fn exchange, void *context);
uint16_t iso_dep_crc_a(const uint8_t *data, uint16_t size);

#endif
