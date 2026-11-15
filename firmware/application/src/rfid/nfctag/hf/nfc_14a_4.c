/**
 * @file nfc_14a_4.c
 * @brief ISO14443-4 T=CL emulation for ChameleonUltra
 *
 * Implements a full ISO14443-4 tag emulator with a static APDU response
 * table.  The table is populated by the host before field activation, so
 * the firmware can respond to an EMV reader autonomously without any USB
 * communication while the RF field is active.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include "app_util_platform.h"
#include "nfc_14a_4.h"
#include "nfc_14a.h"
#include "tag_emulation.h"
#include "tag_persistence.h"
#include "fds_util.h"
#include "nrf_log.h"

/* ------------------------------------------------------------------ */
/*  Module state                                                        */
/* ------------------------------------------------------------------ */
static nfc_tag_14a_4_information_t *m_tag_information = NULL;

/* Shadow coll-res references into m_tag_information */
static nfc_tag_14a_coll_res_reference_t m_shadow_coll_res;

/* T=CL session state */
static nfc_tag_14a_4_tcl_state_t m_tcl_session_state;

/* TX scratch buffer */
static uint8_t m_tx_buf[NFC_14A_4_MAX_APDU + 4];

/* Debug counters — readable via hf 14a debug */
static uint8_t  m_dbg_iblocks_rx  = 0;  /* I-blocks received */
static uint8_t  m_dbg_iblocks_tx  = 0;  /* I-blocks sent */
static uint8_t  m_dbg_last_rx_pcb = 0;  /* PCB of last received I-block */
static uint8_t  m_dbg_last_match  = 0;  /* last find_static_response result */

/* Static APDU response table (RAM copy, populated from m_tag_information) */
static nfc_tag_14a_4_static_response_t m_static_resp[NFC_14A_4_MAX_STATIC_RESPONSES];
static uint8_t m_static_resp_count = 0;

/* Large response overflow (RAM only, > NFC_14A_4_MAX_STATIC_RESP_LEN bytes).
 * NOT persisted to flash. Must reload via emv load after power cycle. */
typedef struct {
    uint8_t  cmd[NFC_14A_4_MAX_STATIC_CMD_LEN];
    uint8_t  cmd_len;
    uint8_t  resp[NFC_14A_4_MAX_LARGE_RESP_LEN];
    uint16_t resp_len;
} nfc_tag_14a_4_large_response_t;
static nfc_tag_14a_4_large_response_t m_large_resp[NFC_14A_4_MAX_LARGE_RESPONSES];
static uint8_t m_large_resp_count = 0;

/* ------------------------------------------------------------------ */
/*  Static response table                                               */
/* ------------------------------------------------------------------ */

static void persist_static_table(void) {
    if (m_tag_information) {
        m_tag_information->static_resp_count = m_static_resp_count;
        memcpy(m_tag_information->static_resp, m_static_resp,
               m_static_resp_count * sizeof(m_static_resp[0]));
    }
}

static bool add_static_response_unlocked(const uint8_t *cmd, uint8_t cmd_len,
                                    const uint8_t *resp, uint16_t resp_len) {
    if (!cmd_len || cmd_len > NFC_14A_4_MAX_STATIC_CMD_LEN || resp_len < 2 ||
            resp_len > NFC_14A_4_MAX_LARGE_RESP_LEN) return false;
    int normal = -1, large = -1;
    for (uint8_t i = 0; i < m_static_resp_count; i++)
        if (m_static_resp[i].cmd_len == cmd_len && !memcmp(m_static_resp[i].cmd, cmd, cmd_len)) normal = i;
    for (uint8_t i = 0; i < m_large_resp_count; i++)
        if (m_large_resp[i].cmd_len == cmd_len && !memcmp(m_large_resp[i].cmd, cmd, cmd_len)) large = i;
    if (resp_len <= NFC_14A_4_MAX_STATIC_RESP_LEN) {
        if (normal < 0 && m_static_resp_count == NFC_14A_4_MAX_STATIC_RESPONSES) return false;
        if (normal < 0) normal = m_static_resp_count++;
        nfc_tag_14a_4_static_response_t *e = &m_static_resp[normal];
        e->cmd_len = cmd_len; e->resp_len = resp_len;
        memcpy(e->cmd, cmd, cmd_len); memcpy(e->resp, resp, resp_len);
        if (large >= 0) {
            memmove(&m_large_resp[large], &m_large_resp[large + 1],
                    (--m_large_resp_count - large) * sizeof(m_large_resp[0]));
        }
    } else {
        if (large < 0 && m_large_resp_count == NFC_14A_4_MAX_LARGE_RESPONSES) return false;
        if (large < 0) large = m_large_resp_count++;
        nfc_tag_14a_4_large_response_t *e = &m_large_resp[large];
        e->cmd_len = cmd_len; e->resp_len = resp_len;
        memcpy(e->cmd, cmd, cmd_len); memcpy(e->resp, resp, resp_len);
        if (normal >= 0) {
            memmove(&m_static_resp[normal], &m_static_resp[normal + 1],
                    (--m_static_resp_count - normal) * sizeof(m_static_resp[0]));
        }
    }
    persist_static_table();
    return true;
}

bool nfc_tag_14a_4_add_static_response(const uint8_t *cmd, uint8_t cmd_len,
        const uint8_t *resp, uint16_t resp_len) {
    bool result;
    CRITICAL_REGION_ENTER();
    result = add_static_response_unlocked(cmd, cmd_len, resp, resp_len);
    CRITICAL_REGION_EXIT();
    return result;
}

uint8_t nfc_tag_14a_4_static_response_count(void) {
    return m_static_resp_count + m_large_resp_count;
}

bool nfc_tag_14a_4_get_static_response(uint8_t index, const uint8_t **cmd,
        uint8_t *cmd_len, const uint8_t **response, uint16_t *response_len) {
    if (index < m_static_resp_count) {
        nfc_tag_14a_4_static_response_t *e = &m_static_resp[index];
        *cmd = e->cmd; *cmd_len = e->cmd_len;
        *response = e->resp; *response_len = e->resp_len;
        return true;
    }
    index -= m_static_resp_count;
    if (index >= m_large_resp_count) return false;
    nfc_tag_14a_4_large_response_t *e = &m_large_resp[index];
    *cmd = e->cmd; *cmd_len = e->cmd_len;
    *response = e->resp; *response_len = e->resp_len;
    return true;
}

void nfc_tag_14a_4_clear_static_responses(void) {
    CRITICAL_REGION_ENTER();
    m_static_resp_count = 0;
    m_large_resp_count  = 0;
    if (m_tag_information) {
        m_tag_information->static_resp_count = 0;
    }
    CRITICAL_REGION_EXIT();
}

static bool find_static_response(const uint8_t *apdu, uint16_t apdu_len,
                                  const uint8_t **resp_out, uint16_t *resp_len_out) {
    uint8_t best = 0;
    for (uint8_t i = 0; i < nfc_tag_14a_4_static_response_count(); i++) {
        const uint8_t *cmd, *response;
        uint8_t cmd_len;
        uint16_t response_len;
        if (!nfc_tag_14a_4_get_static_response(i, &cmd, &cmd_len, &response, &response_len)) continue;
        if (cmd_len > best && cmd_len <= apdu_len && !memcmp(apdu, cmd, cmd_len)) {
            best = cmd_len; *resp_out = response; *resp_len_out = response_len;
        }
    }
    return best != 0;
}

static void tcl_send(void *context, const uint8_t *frame, uint16_t size) {
    (void)context;
    /* NFCT consumes the bytes synchronously when configuring EasyDMA. */
    memcpy(m_tx_buf, frame, size);
    nfc_tag_14a_tx_bytes(m_tx_buf, size, true);
}

void nfc_tag_14a_4_base_respond(nfc_tag_14a_4_tcl_state_t *s) {
    iso_dep_picc_respond(s, tcl_send, NULL);
}

bool nfc_tag_14a_4_base_handler(nfc_tag_14a_4_tcl_state_t *s, uint8_t *data, uint16_t size) {
    iso_dep_picc_result_t result = iso_dep_picc_receive(s, data, size, tcl_send, NULL);
    if (result == ISO_DEP_DESELECTED) nfc_tag_14a_set_state(NFC_TAG_STATE_14A_HALTED);
    return result == ISO_DEP_APDU;
}

static void nfc_tag_14a_4_rats(uint8_t parameter) {
    iso_dep_picc_rats(&m_tcl_session_state, parameter);
}

static void nfc_tag_14a_4_state_handler(uint8_t *data, uint16_t szBits) {
    if ((szBits & 7) || szBits < 24) return;
    uint16_t szBytes = szBits / 8;
    if (!nfc_tag_14a_checks_crc(data, szBytes)) return;
    szBytes -= 2; /* RF callback counts bits and includes CRC_A. */
    if (!nfc_tag_14a_4_base_handler(&m_tcl_session_state, data, szBytes)) return;
    
    /* APDU complete — check static table first, then WTX */
    const uint8_t *static_resp = NULL;
    uint16_t  static_len  = 0;
    bool _found = find_static_response(m_tcl_session_state.m_apdu_buf, m_tcl_session_state.m_apdu_len,
                                        &static_resp, &static_len);
    m_dbg_last_match = _found ? 1 : 0;
    NRF_LOG_INFO("14A4 find_static: found=%d static_len=%d resp_count=%d",
                    _found, static_len, m_static_resp_count);
    m_dbg_iblocks_rx++;
    m_dbg_last_rx_pcb = data[0];
    if (_found) {
        m_tcl_session_state.m_apdu_pending = false;
        m_dbg_iblocks_tx++;
        memcpy(m_tcl_session_state.m_resp_buf, static_resp, static_len);
        m_tcl_session_state.m_resp_len = static_len;
        m_tcl_session_state.m_response_ready = true;
    } else if (nfc_tag_14a_4_static_response_count()) {
        /* Offline table mode: report an unknown INS instead of endless WTX. */
        m_tcl_session_state.m_apdu_pending = false;
        m_tcl_session_state.m_resp_buf[0] = 0x6D;
        m_tcl_session_state.m_resp_buf[1] = 0x00;
        m_tcl_session_state.m_resp_len = 2;
        m_tcl_session_state.m_response_ready = true;
    }

    nfc_tag_14a_4_base_respond(&m_tcl_session_state);
}

/* ------------------------------------------------------------------ */
/*  APDU relay API (for host-driven responses)                         */
/* ------------------------------------------------------------------ */

bool nfc_tag_14a_4_get_pending_apdu(uint8_t *buf, uint16_t *length) {
    bool pending;
    CRITICAL_REGION_ENTER();
    pending = m_tcl_session_state.m_apdu_pending;
    if (pending) {
        *length = m_tcl_session_state.m_apdu_len;
        memcpy(buf, m_tcl_session_state.m_apdu_buf, *length);
        m_tcl_session_state.m_apdu_pending = false;
    }
    CRITICAL_REGION_EXIT();
    return pending;
}

bool nfc_tag_14a_4_set_response(const uint8_t *data, uint16_t length) {
    bool accepted;
    CRITICAL_REGION_ENTER();
    accepted = length >= 2 && length <= NFC_14A_4_MAX_APDU &&
        m_tcl_session_state.awaiting_response && !m_tcl_session_state.m_response_ready;
    if (accepted) {
        memcpy(m_tcl_session_state.m_resp_buf, data, length);
        m_tcl_session_state.m_resp_len = length;
        m_tcl_session_state.m_response_ready = true;
    }
    CRITICAL_REGION_EXIT();
    return accepted;
}

/* ------------------------------------------------------------------ */
/*  Reset handler                                                       */
/* ------------------------------------------------------------------ */

void nfc_tag_14a_4_reset_state(nfc_tag_14a_4_tcl_state_t *m_tcl_session_state) {
    iso_dep_picc_reset(m_tcl_session_state);
}

void nfc_tag_14a_4_reset_handler(void) {
    nfc_tag_14a_4_reset_state(&m_tcl_session_state);
}

void nfc_tag_14a_4_get_debug_counters(uint8_t *rx, uint8_t *tx,
                                      uint8_t *last_pcb, uint8_t *last_match) {
    *rx = m_dbg_iblocks_rx;
    *tx = m_dbg_iblocks_tx;
    *last_pcb = m_dbg_last_rx_pcb;
    *last_match = m_dbg_last_match;
}

/* ------------------------------------------------------------------ */
/*  Anti-collision resource                                             */
/* ------------------------------------------------------------------ */

nfc_tag_14a_coll_res_reference_t *nfc_tag_14a_4_get_coll_res(void) {
    if (m_tag_information == NULL) return NULL;
    m_shadow_coll_res.sak  = m_tag_information->res_coll.sak;
    m_shadow_coll_res.atqa = m_tag_information->res_coll.atqa;
    m_shadow_coll_res.uid  = m_tag_information->res_coll.uid;
    m_shadow_coll_res.size = &m_tag_information->res_coll.size;
    m_shadow_coll_res.ats  = &m_tag_information->res_coll.ats;
    return &m_shadow_coll_res;
}

/* ------------------------------------------------------------------ */
/*  Data load / save / factory callbacks                               */
/* ------------------------------------------------------------------ */

int nfc_tag_14a_4_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    int info_size = sizeof(nfc_tag_14a_4_information_t);
    if (buffer->length < info_size) {
        NRF_LOG_ERROR("14A-4 loadcb: buffer too small (%d < %d)",
                      buffer->length, info_size);
        return info_size;
    }
    m_tag_information = (nfc_tag_14a_4_information_t *)buffer->buffer;

    m_large_resp_count = 0; /* Never leak volatile responses across slots. */
    nfc_tag_14a_4_reset_handler();
    /* Populate RAM static table from persisted slot data */
    m_static_resp_count = m_tag_information->static_resp_count;
    if (m_static_resp_count > NFC_14A_4_MAX_STATIC_RESPONSES)
        m_static_resp_count = NFC_14A_4_MAX_STATIC_RESPONSES;
    memcpy(m_static_resp, m_tag_information->static_resp,
           m_static_resp_count * sizeof(nfc_tag_14a_4_static_response_t));

    for (uint8_t i = 0; i < m_static_resp_count; i++) {
        if (!m_static_resp[i].cmd_len || m_static_resp[i].cmd_len > NFC_14A_4_MAX_STATIC_CMD_LEN ||
                m_static_resp[i].resp_len < 2 || m_static_resp[i].resp_len > NFC_14A_4_MAX_STATIC_RESP_LEN) {
            m_static_resp_count = 0;
            break;
        }
    }
    nfc_tag_14a_handler_t handler = {
        .cb_rats      = nfc_tag_14a_4_rats,
        .get_coll_res = nfc_tag_14a_4_get_coll_res,
        .cb_state     = nfc_tag_14a_4_state_handler,
        .cb_reset     = nfc_tag_14a_4_reset_handler,
    };
    nfc_tag_14a_set_handler(&handler);
    NRF_LOG_INFO("14A-4 loadcb OK: SAK=%02x uid_sz=%d static_resp=%d",
                 m_tag_information->res_coll.sak[0],
                 m_tag_information->res_coll.size,
                 m_static_resp_count);
    return info_size;
}

int nfc_tag_14a_4_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    return sizeof(nfc_tag_14a_4_information_t);
}

bool nfc_tag_14a_4_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    if (tag_type != TAG_TYPE_HF14A_4) return false;

    /* Build factory defaults on stack and write directly to FDS
     * (same pattern as nfc_tag_mf1_data_factory). */
    nfc_tag_14a_4_information_t info;
    memset(&info, 0, sizeof(info));

    /* Placeholder 7-byte NXP-style UID */
    info.res_coll.size    = NFC_TAG_14A_UID_DOUBLE_SIZE;
    info.res_coll.atqa[0] = 0x04;
    info.res_coll.atqa[1] = 0x00;
    info.res_coll.sak[0]  = 0x20;   /* ISO14443-4 */
    info.res_coll.uid[0]  = 0x04;
    info.res_coll.uid[1]  = 0x01;
    info.res_coll.uid[2]  = 0x02;
    info.res_coll.uid[3]  = 0x03;
    info.res_coll.uid[4]  = 0x04;
    info.res_coll.uid[5]  = 0x05;
    info.res_coll.uid[6]  = 0x06;

    static const uint8_t default_ats[] = {
        0x10, 0x78, 0x80, 0x70, 0x02, 0x00,
        0x31, 0xC1, 0x64, 0x09, 0x97, 0x61,
        0x26, 0x00, 0x90, 0x00
    };
    info.res_coll.ats.length = sizeof(default_ats);
    memcpy(info.res_coll.ats.data, default_ats, sizeof(default_ats));
    info.static_resp_count = 0;

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(info), &info);
    NRF_LOG_INFO("14A-4 factory slot %d: %s", slot, ret ? "OK" : "FAIL");
    return ret;
}
