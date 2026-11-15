#include "fds_util.h"
#include "bsp_time.h"
#include "bsp_delay.h"
#include "usb_main.h"
#include "rfid_main.h"
#include "ble_main.h"
#include "syssleep.h"
#include "hex_utils.h"
#include "data_cmd.h"
#include "app_cmd.h"
#include "app_status.h"
#include "battery_health.h"
#include "tag_persistence.h"
#include "nrf_pwr_mgmt.h"
#include "settings.h"
#include "delayed_reset.h"
#include "netdata.h"
#if defined(PROJECT_CHAMELEON_ULTRA)
#include "bsp_wdt.h"
#include "lf_reader_generic.h"
#include "lf_em4x05_data.h"
#include "rc522.h"
#include "mf1_crapto1.h"
#include "parity.h"
#endif
#include "nfc_14a.h"
/* Forward declarations for functions added to nfc_14a.c/h in this PR.
 * These are declared here to avoid build failure if nfc_14a.h is not yet
 * updated on the build system. */
extern void nfc_tag_14a_set_tx_sniff_cb(void (*cb)(const uint8_t *, uint16_t));
extern void nfc_tag_14a_clear_tx_sniff_cb(void);
extern void nfc_tag_14a_set_sniff_passive(bool passive);
#include "nfc_14a_4.h"

#if defined(PROJECT_CHAMELEON_ULTRA)
static bool m_cpu_active = false;
#endif

#define NRF_LOG_MODULE_NAME app_cmd
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();


static void change_slot_auto(uint8_t slot_new) {
    uint8_t slot_now = tag_emulation_get_slot();
    device_mode_t mode = get_device_mode();
    tag_emulation_change_slot(slot_new, mode != DEVICE_MODE_READER);
    apply_slot_change(slot_now, slot_new);
}

static data_frame_tx_t *cmd_processor_get_app_version(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint8_t version_major;
        uint8_t version_minor;
    } PACKED payload;
    payload.version_major = APP_FW_VER_MAJOR;
    payload.version_minor = APP_FW_VER_MINOR;
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}


static data_frame_tx_t *cmd_processor_get_git_version(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    return data_frame_make(cmd, STATUS_SUCCESS, strlen(GIT_VERSION), (uint8_t *)GIT_VERSION);
}


static data_frame_tx_t *cmd_processor_get_device_model(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t resp_data = hw_get_device_type();
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(resp_data), &resp_data);
}


static data_frame_tx_t *cmd_processor_change_device_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 1) || (data[0] > 1)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    if (data[0] == 1) {
#if defined(PROJECT_CHAMELEON_ULTRA)
        m_cpu_active = false;
        reader_mode_enter();
        return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
#else
        return data_frame_make(cmd, STATUS_NOT_IMPLEMENTED, 0, NULL);
#endif
    } else {
#if defined(PROJECT_CHAMELEON_ULTRA)
        m_cpu_active = false;
        tag_mode_enter();
#endif
        return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
    }
}

static data_frame_tx_t *cmd_processor_get_device_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t resp_data = (get_device_mode() == DEVICE_MODE_READER);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(resp_data), &resp_data);
}

static data_frame_tx_t *cmd_processor_enter_bootloader(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // restart to boot
#define BOOTLOADER_DFU_GPREGRET_MASK            (0xB0)
#define BOOTLOADER_DFU_START_BIT_MASK           (0x01)
#define BOOTLOADER_DFU_START    (BOOTLOADER_DFU_GPREGRET_MASK |         BOOTLOADER_DFU_START_BIT_MASK)
    APP_ERROR_CHECK(sd_power_gpregret_clr(0, 0xffffffff));
    APP_ERROR_CHECK(sd_power_gpregret_set(0, BOOTLOADER_DFU_START));
    nrf_pwr_mgmt_shutdown(NRF_PWR_MGMT_SHUTDOWN_GOTO_DFU);
    // Never into here...
    while (1) __NOP();
    // For the compiler to be happy...
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_device_chip_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint32_t chip_HSW;
        uint32_t chip_LSW;
    } PACKED payload;
    payload.chip_LSW = U32HTONL(NRF_FICR->DEVICEID[0]);
    payload.chip_HSW = U32HTONL(NRF_FICR->DEVICEID[1]);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_get_device_address(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // The FICR value is a just a random number, with no knowledge
    // of the Bluetooth Specification requirements for random addresses.
    // So we need to set a Bluetooth LE random address as a static address.
    // See: https://github.com/zephyrproject-rtos/zephyr/blob/7b6b1328a0cb96fe313a5e2bfc57047471df236e/subsys/bluetooth/controller/hci/nordic/hci_vendor.c#L29

    struct {
        uint16_t device_address_HSW;
        uint32_t device_address_LSW;
    } PACKED payload;
    payload.device_address_LSW = U32HTONL(NRF_FICR->DEVICEADDR[0]);
    payload.device_address_HSW = U16HTONS(NRF_FICR->DEVICEADDR[1] | 0xC000);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_save_settings(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    status = settings_save_config();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_reset_settings(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    settings_init_config();
    status = settings_save_config();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_device_settings(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t settings[7 + BLE_PAIRING_KEY_LEN] = {};
    settings[0] = SETTINGS_CURRENT_VERSION; // current version
    settings[1] = settings_get_animation_config(); // animation mode
    settings[2] = settings_get_button_press_config('A'); // short A button press mode
    settings[3] = settings_get_button_press_config('B'); // short B button press mode
    settings[4] = settings_get_long_button_press_config('A'); // long A button press mode
    settings[5] = settings_get_long_button_press_config('B'); // long B button press mode
    settings[6] = settings_get_ble_pairing_enable(); // is device require pairing
    memcpy(settings + 7, settings_get_ble_connect_key(), BLE_PAIRING_KEY_LEN);
    return data_frame_make(cmd, STATUS_SUCCESS, 7 + BLE_PAIRING_KEY_LEN, settings);
}

static data_frame_tx_t *cmd_processor_set_animation_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 1) || (data[0] >= SettingsAnimationModeMAX)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    settings_set_animation_config(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_animation_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t animation_mode = settings_get_animation_config();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &animation_mode);
}

static data_frame_tx_t *cmd_processor_get_battery_info(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint16_t voltage;
        uint8_t percent;
    } PACKED payload;
    payload.voltage = U16HTONS(batt_lvl_in_milli_volts);
    payload.percent = percentage_batt_lvl;
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_get_battery_info_ex(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint16_t voltage;
        uint8_t percent;
        uint8_t condition;
    } PACKED payload;
    // The condition field is a compact hint derived from estimated remaining capacity.
    payload.voltage = U16HTONS(batt_lvl_in_milli_volts);
    payload.percent = percentage_batt_lvl;
    payload.condition = battery_health_to_code(
        battery_health_from_measurement(batt_lvl_in_milli_volts, percentage_batt_lvl));
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_get_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 1) || (!is_settings_button_type_valid(data[0]))) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t button_press_config = settings_get_button_press_config(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(button_press_config), &button_press_config);
}

static data_frame_tx_t *cmd_processor_set_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 2) || (!is_settings_button_type_valid(data[0]))) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    settings_set_button_press_config(data[0], data[1]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_long_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 1) || (!is_settings_button_type_valid(data[0]))) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t button_press_config = settings_get_long_button_press_config(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(button_press_config), &button_press_config);
}

static data_frame_tx_t *cmd_processor_set_long_button_press_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 2) || (!is_settings_button_type_valid(data[0]))) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    settings_set_long_button_press_config(data[0], data[1]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_sleep_timeout(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t seconds = settings_get_sleep_timeout() / 1000U;
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &seconds);
}

static data_frame_tx_t *cmd_processor_set_sleep_timeout(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] < SETTINGS_SLEEP_TIMEOUT_MIN_S || data[0] > SETTINGS_SLEEP_TIMEOUT_MAX_S) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    settings_set_sleep_timeout(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_ble_pairing_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t is_enable = settings_get_ble_pairing_enable();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &is_enable);
}

static data_frame_tx_t *cmd_processor_set_ble_pairing_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 && data[0] > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    settings_set_ble_pairing_enable(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_long_press_threshold(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // Ignore unused parameters
    (void)status;
    (void)length;
    (void)data;

    uint16_t duration = settings_get_long_press_threshold();
    uint8_t resp_data[2];
    // Pack as big-endian (network byte order)
    resp_data[0] = (uint8_t)(duration >> 8);
    resp_data[1] = (uint8_t)(duration & 0xFF);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(resp_data), resp_data);
}

static data_frame_tx_t *cmd_processor_set_long_press_threshold(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 2) { // Check for 2 bytes
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    // Unpack uint16_t from data (assuming big-endian/network byte order)
    uint16_t duration = ((uint16_t)data[0] << 8) | data[1];
    settings_set_long_press_threshold(duration);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

#if defined(PROJECT_CHAMELEON_ULTRA)

static data_frame_tx_t *cmd_processor_hf14a_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    // uidlen[1]|uid[uidlen]|atqa[2]|sak[1]|atslen[1]|ats[atslen]
    // dynamic length, so no struct
    uint8_t payload[1 + sizeof(taginfo.uid) + sizeof(taginfo.atqa) + sizeof(taginfo.sak) + 1 + 254];
    uint16_t offset = 0;
    payload[offset++] = taginfo.uid_len;
    memcpy(&payload[offset], taginfo.uid, taginfo.uid_len);
    offset += taginfo.uid_len;
    memcpy(&payload[offset], taginfo.atqa, sizeof(taginfo.atqa));
    offset += sizeof(taginfo.atqa);
    payload[offset++] = taginfo.sak;
    payload[offset++] = taginfo.ats_len;
    memcpy(&payload[offset], taginfo.ats, taginfo.ats_len);
    offset += taginfo.ats_len;
    return data_frame_make(cmd, STATUS_HF_TAG_OK, offset, payload);
}

static data_frame_tx_t *cmd_processor_mf1_detect_support(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    status = check_std_mifare_nt_support();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_detect_prng(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t type;
    status = check_prng_type((mf1_prng_type_t *)&type);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_HF_TAG_OK, sizeof(type), &type);
}

// We have a reusable payload structure.
typedef struct {
    uint8_t type_known;
    uint8_t block_known;
    uint8_t key_known[6];
    uint8_t type_target;
    uint8_t block_target;
} PACKED nested_common_payload_t;

static data_frame_tx_t *cmd_processor_mf1_static_nested_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    mf1_static_nested_core_t sncs;
    if (length != sizeof(nested_common_payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    nested_common_payload_t *payload = (nested_common_payload_t *)data;
    status = static_nested_recover_key(bytes_to_num(payload->key_known, 6), payload->block_known, payload->type_known, payload->block_target, payload->type_target, &sncs);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    // mf1_static_nested_core_t is PACKED and comprises only bytes so we can use it directly
    return data_frame_make(cmd, STATUS_HF_TAG_OK, sizeof(sncs), (uint8_t *)(&sncs));
}

static data_frame_tx_t *cmd_processor_mf1_darkside_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 4) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    struct {
        uint8_t darkside_status;
        // DarksideCore_t is PACKED and comprises only bytes so we can use it directly
        DarksideCore_t dc;
    } PACKED payload;
    status = darkside_recover_key(data[1], data[0], data[2], data[3], &payload.dc, (mf1_darkside_status_t *)&payload.darkside_status);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    if (payload.darkside_status != DARKSIDE_OK) {
        return data_frame_make(cmd, STATUS_HF_TAG_OK, sizeof(payload.darkside_status), &payload.darkside_status);
    }
    return data_frame_make(cmd, STATUS_HF_TAG_OK, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_mf1_detect_nt_dist(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t type_known;
        uint8_t block_known;
        uint8_t key_known[6];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    struct {
        uint8_t uid[4];
        uint32_t distance;
    } PACKED payload_resp;

    payload_t *payload = (payload_t *)data;
    uint32_t distance;
    status = nested_distance_detect(payload->block_known, payload->type_known, payload->key_known, payload_resp.uid, &distance);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    payload_resp.distance = U32HTONL(distance);
    return data_frame_make(cmd, STATUS_HF_TAG_OK, sizeof(payload_resp), (uint8_t *)&payload_resp);
}

static data_frame_tx_t *cmd_processor_mf1_nested_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    mf1_nested_core_t ncs[SETS_NR];
    if (length != sizeof(nested_common_payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    nested_common_payload_t *payload = (nested_common_payload_t *)data;
    status = nested_recover_key(bytes_to_num(payload->key_known, 6), payload->block_known, payload->type_known, payload->block_target, payload->type_target, ncs);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    // mf1_nested_core_t is PACKED and comprises only bytes so we can use it directly
    return data_frame_make(cmd, STATUS_HF_TAG_OK, sizeof(ncs), (uint8_t *)(&ncs));
}

static data_frame_tx_t *cmd_processor_mf1_enc_nested_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t key[6];
        uint8_t sector_count;
        uint8_t starting_sector;
    } PACKED payload_t;

    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;

    uint64_t ui64Key = bytes_to_num(payload->key, 6);
    uint8_t sector_data[40][sizeof(mf1_static_nonce_sector_t)];
    uint8_t sectors_acquired = 0;
    uint32_t cuid = 0;

    status = mf1_static_encrypted_nonces_acquire(ui64Key, payload->sector_count, payload->starting_sector, sector_data, &sectors_acquired, &cuid);

    uint8_t response_data[sizeof(uint32_t) + sectors_acquired * sizeof(mf1_static_nonce_sector_t)];
    num_to_bytes(cuid, 4, response_data);
    memcpy(response_data + sizeof(uint32_t), sector_data, sectors_acquired * sizeof(mf1_static_nonce_sector_t));

    return data_frame_make(cmd, status, sectors_acquired * sizeof(mf1_static_nonce_sector_t) + sizeof(uint32_t), response_data);
}

static data_frame_tx_t *cmd_processor_mf1_auth_one_key_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t type;
        uint8_t block;
        uint8_t key[6];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    status = auth_key_use_522_hw(payload->block, payload->type, payload->key);
    pcd_14a_reader_mf1_unauth();
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_check_keys_of_sectors(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length < 16 || (length - 10) % 6 != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    // init
    mf1_toolbox_check_keys_of_sectors_in_t in = {
        .mask = *(mf1_toolbox_check_keys_of_sectors_mask_t *) &data[0],
        .keys_len = (length - 10) / 6,
        .keys = (mf1_key_t *) &data[10]
    };
    mf1_toolbox_check_keys_of_sectors_out_t out;
    status = mf1_toolbox_check_keys_of_sectors(&in, &out);

    return data_frame_make(cmd, status, sizeof(out), (uint8_t *)&out);
}

static data_frame_tx_t *cmd_processor_mf1_check_keys_on_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length < 9 || data[2] * 6 + 3 != length) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    mf1_toolbox_check_keys_on_block_in_t in = {
        .block = data[0],
        .key_type = data[1],
        .keys_len = data[2],
        .keys = (mf1_key_t *) &data[3]
    };

    mf1_toolbox_check_keys_on_block_out_t out;
    status = mf1_toolbox_check_keys_on_block(&in, &out);

    return data_frame_make(cmd, status, sizeof(out), (uint8_t *)&out);
}

static data_frame_tx_t *cmd_processor_mf1_hardnested_nonces_acquire(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t slow;
        uint8_t type_known;
        uint8_t block_known;
        uint8_t key_known[6];
        uint8_t type_target;
        uint8_t block_target;
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    payload_t *payload = (payload_t *)data;

    // It is enough to collect 110 nonces at a time. The total transmitted data payload is 495 + 1 bytes
    // Then, the total length can be controlled within 4096, so that when encountering a BLE host that supports large packets, one communication can be completed.
    // There is no need to send or receive packets in separate packets, which improves communication speed.
    uint8_t nonces[500] = { 0x00 };
    if (length < 11) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    status = mf1_hardnested_nonces_acquire(
                 payload->slow,
                 payload->block_known,
                 payload->type_known,
                 bytes_to_num(payload->key_known, 6),
                 payload->block_target,
                 payload->type_target,
                 nonces + 1,
                 sizeof(nonces) - 1,         // The upper limit of the buffer size. Here we take out the first byte to mark the number of collections.
                 &nonces[0]                  // The number of random numbers collected above
             );
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, status, nonces[0] * 4.5, (uint8_t *)(nonces + 1));
}

static data_frame_tx_t *cmd_processor_mf1_read_one_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t type;
        uint8_t block;
        uint8_t key[6];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    uint8_t block[16] = { 0x00 };
    status = auth_key_use_522_hw(payload->block, payload->type, payload->key);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf1_read(payload->block, block);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, status, sizeof(block), block);
}

static data_frame_tx_t *cmd_processor_mf1_write_one_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t type;
        uint8_t block;
        uint8_t key[6];
        uint8_t block_data[16];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    status = auth_key_use_522_hw(payload->block, payload->type, payload->key);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf1_write(payload->block, payload->block_data);
    return data_frame_make(cmd, status, 0, NULL);
}

#define MF0_ULC_READ_MAX_PAGES 48

static data_frame_tx_t *cmd_processor_mf0_ulc_auth(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t key[16];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf0_ulc_auth(payload->key);
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ulc_read(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t key[16];
        uint8_t page;
        uint8_t count;
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    if (payload->count == 0 || payload->count > MF0_ULC_READ_MAX_PAGES) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf0_ulc_auth(payload->key);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    uint8_t out[MF0_ULC_READ_MAX_PAGES * 4];
    uint16_t out_len = 0;
    for (uint8_t i = 0; i < payload->count;) {
        uint8_t block[16];
        status = pcd_14a_reader_mf1_read(payload->page + i, block);
        if (status != STATUS_HF_TAG_OK) {
            break;
        }
        uint8_t take = ((payload->count - i) < 4) ? (payload->count - i) : 4;
        memcpy(&out[out_len], block, (size_t)take * 4);
        out_len += (uint16_t)take * 4;
        i += take;
    }
    if (out_len == 0) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_HF_TAG_OK, out_len, out);
}

static data_frame_tx_t *cmd_processor_mf0_ulc_write(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t key[16];
        uint8_t page;
        uint8_t page_data[4];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf0_ulc_auth(payload->key);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf0_ult_write_page(payload->page, payload->page_data);
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ulc_set_key(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t old_key[16];
        uint8_t new_key[16];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    status = pcd_14a_reader_mf0_ulc_auth(payload->old_key);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    uint8_t card[16];
    for (int i = 0; i < 8; i++) card[i] = payload->new_key[7 - i];
    for (int i = 0; i < 8; i++) card[8 + i] = payload->new_key[15 - i];

    for (uint8_t i = 0; i < 4; i++) {
        status = pcd_14a_reader_mf0_ult_write_page(0x2C + i, &card[i * 4]);
        if (status != STATUS_HF_TAG_OK) {
            return data_frame_make(cmd, status, 0, NULL);
        }
    }
    return data_frame_make(cmd, STATUS_HF_TAG_OK, 0, NULL);
}

#if defined(PROJECT_CHAMELEON_ULTRA)

static data_frame_tx_t *cmd_processor_hf14a_set_field_on(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (cmd != DATA_CMD_HF14A_4_READER_APDU && cmd != DATA_CMD_HF14A_4_SESSION)
        m_cpu_active = false;
    device_mode_t mode = get_device_mode();
    if (mode != DEVICE_MODE_READER) {
        return data_frame_make(cmd, STATUS_DEVICE_MODE_ERROR, 0, NULL);
    }

    // Reset and turn on the antenna
    pcd_14a_reader_reset();
    pcd_14a_reader_antenna_on();

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_hf14a_set_field_off(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    device_mode_t mode = get_device_mode();
    if (mode != DEVICE_MODE_READER) {
        return data_frame_make(cmd, STATUS_DEVICE_MODE_ERROR, 0, NULL);
    }

    // Turn off the antenna
    pcd_14a_reader_antenna_off();

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

#endif

static data_frame_tx_t *cmd_processor_hf14a_raw(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // Response Buffer
    uint8_t resp[DEF_FIFO_LENGTH] = { 0x00 };
    uint16_t resp_length = 0;

    typedef struct {
        struct { // LSB -> MSB
            uint8_t reserved : 2;

            uint8_t check_response_crc : 1;
            uint8_t keep_rf_field : 1;
            uint8_t auto_select : 1;
            uint8_t append_crc : 1;
            uint8_t wait_response : 1;
            uint8_t activate_rf_field : 1;
        } options;

        // U16NTOHS
        uint16_t resp_timeout;
        uint16_t data_bitlength;

        uint8_t data_buffer[0]; // We can have a lot of data or no data. struct just to compute offsets with min options.
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    NRF_LOG_INFO("activate_rf_field  = %d", payload->options.activate_rf_field);
    NRF_LOG_INFO("wait_response      = %d", payload->options.wait_response);
    NRF_LOG_INFO("append_crc         = %d", payload->options.append_crc);
    NRF_LOG_INFO("auto_select        = %d", payload->options.auto_select);
    NRF_LOG_INFO("keep_rf_field      = %d", payload->options.keep_rf_field);
    NRF_LOG_INFO("check_response_crc = %d", payload->options.check_response_crc);
    NRF_LOG_INFO("reserved           = %d", payload->options.reserved);

    status = pcd_14a_reader_raw_cmd(
                 payload->options.activate_rf_field,
                 payload->options.wait_response,
                 payload->options.append_crc,
                 payload->options.auto_select,
                 payload->options.keep_rf_field,
                 payload->options.check_response_crc,

                 U16NTOHS(payload->resp_timeout),

                 U16NTOHS(payload->data_bitlength),
                 payload->data_buffer,

                 resp,
                 &resp_length,
                 U8ARR_BIT_LEN(resp)
             );

    return data_frame_make(cmd, status, resp_length, resp);
}

static data_frame_tx_t *cmd_processor_hf14a_get_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    hf14a_config_t *hc = get_hf14a_config();
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(hf14a_config_t), (uint8_t *)hc);
}

static data_frame_tx_t *cmd_processor_hf14a_set_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != sizeof(hf14a_config_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    hf14a_config_t hc;
    memcpy(&hc, data, sizeof(hf14a_config_t));
    set_hf14a_config(&hc);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_manipulate_value_block(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t src_type;
        uint8_t src_block;
        uint8_t src_key[6];
        uint8_t operator;
        uint32_t operand;
        uint8_t dst_type;
        uint8_t dst_block;
        uint8_t dst_key[6];
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;

    // scan tag
    picc_14a_tag_t taginfo;
    if (pcd_14a_reader_scan_auto(&taginfo) != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, STATUS_HF_TAG_NO, 0, NULL);
    }

    // auth src
    status = pcd_14a_reader_mf1_auth(&taginfo, payload->src_type, payload->src_block, payload->src_key);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    // value block operation
    status = pcd_14a_reader_mf1_manipulate_value_block(payload->operator, payload->src_block, (int32_t) U32NTOHL(payload->operand));
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    // auth dst if needed
    if (payload->src_block != payload->dst_block || payload->src_type != payload->dst_type) {
        status = pcd_14a_reader_mf1_auth(&taginfo, payload->dst_type, payload->dst_block, payload->dst_key);
        if (status != STATUS_HF_TAG_OK) {
            return data_frame_make(cmd, status, 0, NULL);
        }
    }

    // transfer value block
    status = pcd_14a_reader_mf1_transfer_value_block(payload->dst_block);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_em410x_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_buffer[2 + LF_EM410X_ELECTRA_TAG_ID_SIZE] = {0x00};
    status = scan_em410x(card_buffer);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    tag_specific_type_t tag_type = (card_buffer[0] << 8) | card_buffer[1];
    uint16_t id_size = (tag_type == TAG_TYPE_EM410X_ELECTRA) ? LF_EM410X_ELECTRA_TAG_ID_SIZE : LF_EM410X_TAG_ID_SIZE;

    return data_frame_make(cmd, STATUS_LF_TAG_OK, 2 + id_size, card_buffer);
}

static data_frame_tx_t *cmd_processor_em410x_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t id[5];
        uint8_t new_key[4];
        uint8_t old_keys[4]; // we can have more than one... struct just to compute offsets with min 1 key
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t) || (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    status = write_em410x_to_t55xx(payload->id, payload->new_key, payload->old_keys, (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys));
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_em410x_electra_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t id[13];
        uint8_t new_key[4];
        uint8_t old_keys[4]; // we can have more than one... struct just to compute offsets with min 1 key
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t) || (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    status = write_em410x_electra_to_t55xx(payload->id, payload->new_key, payload->old_keys, (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys));
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_hidprox_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t id[13];
        uint8_t old_key[4];
        uint8_t new_keys[4]; // we can have more than one... struct just to compute offsets with min 1 key
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t) || (length - offsetof(payload_t, new_keys)) % sizeof(payload->new_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    uint8_t format = payload->id[0];
    uint32_t fc = bytes_to_num(payload->id + 1, 4);
    uint64_t cn = payload->id[5];
    cn = (cn << 32) | (bytes_to_num(payload->id + 6, 4));
    uint32_t il = payload->id[10];
    uint32_t oem = bytes_to_num(payload->id + 11, 2);
    status = write_hidprox_to_t55xx(format, fc, cn, il, oem, payload->old_key, payload->new_keys, (length - offsetof(payload_t, new_keys)) / sizeof(payload->new_keys));
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_hidprox_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_data[16] = {0x00};
    status = scan_hidprox(card_data, data[0]);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(card_data), card_data);
}

static data_frame_tx_t *cmd_processor_ioprox_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_data[16] = {0};
    uint8_t hint = (data != NULL) ? data[0] : 0;
    status = scan_ioprox(card_data, hint);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }

    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(card_data), card_data);
}

static data_frame_tx_t *cmd_processor_ioprox_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t card_data[16];  // ioprox_codec_t->data layout: version, facility code, card number, raw8
        uint8_t new_key[4];
        uint8_t old_keys[4];  // we can have more than one... struct just to compute offsets with min 1 key
    } PACKED payload_t;

    payload_t *payload = (payload_t *)data;

    // Validate packet length
    if (length < sizeof(payload_t) ||
            (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    uint8_t old_cnt = (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys);

    // Pass card_data (including raw8 at index 4-11) directly to the T55xx writer.
    status = write_ioprox_to_t55xx(
                 payload->card_data,
                 payload->new_key,
                 payload->old_keys,
                 old_cnt
             );

    return data_frame_make(cmd, status, 0, NULL);
}



/**
 * @brief Decode raw8 data to structured ioProx format
 * @param raw8 Input 8 bytes
 * @param output 16 bytes ioprox_codec_t->data layout: version, facility code, card number, raw8
 * @return STATUS_SUCCESS on success
 */
static data_frame_tx_t *cmd_processor_ioprox_decode_raw(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 8) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);

    uint8_t output[16];
    uint8_t result = decode_ioprox_raw(data, output);

    if (result != STATUS_SUCCESS) {
        return data_frame_make(cmd, STATUS_CMD_ERR, 0, NULL);
    }

    return data_frame_make(cmd, STATUS_SUCCESS, 16, output);
}

/**
 * @brief Encode ioProx parameters to structured ioProx format
 * @param ver Version byte
 * @param fc Facility code byte
 * @param cn Card number (16-bit)
 * @param out 16 bytes ioprox_codec_t->data layout: version, facility code, card number, raw8
 * @return STATUS_SUCCESS on success
 */
static data_frame_tx_t *cmd_processor_ioprox_compose_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 4) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);

    uint8_t output[16];
    memset(output, 0, sizeof(output));
    uint8_t result = encode_ioprox_params(data[0], data[1], (data[2] << 8) | data[3], output);

    if (result != STATUS_SUCCESS) {
        return data_frame_make(cmd, STATUS_CMD_ERR, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, 16, output);
}

static data_frame_tx_t *cmd_processor_viking_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_buffer[4] = {0x00};
    status = scan_viking(card_buffer);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(card_buffer), card_buffer);
}

static data_frame_tx_t *cmd_processor_pac_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_id[8] = {0x00};
    status = scan_pac(card_id);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(card_id), card_id);
}

static data_frame_tx_t *cmd_processor_viking_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t id[4];
        uint8_t new_key[4];
        uint8_t old_keys[4]; // we can have more than one... struct just to compute offsets with min 1 key
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t) || (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    status = write_viking_to_t55xx(payload->id, payload->new_key, payload->old_keys, (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys));
    return data_frame_make(cmd, status, 0, NULL);
}


static data_frame_tx_t *cmd_processor_pac_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t id[LF_PAC_TAG_ID_SIZE];
        uint8_t new_key[4];
        uint8_t old_keys[4];
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t) || (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    status = write_pac_to_t55xx(payload->id, payload->new_key, payload->old_keys, (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys));
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_jablotron_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_buffer[5] = {0x00};
    status = scan_jablotron(card_buffer);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(card_buffer), card_buffer);
}

static data_frame_tx_t *cmd_processor_pyramid_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t card_data[16] = {0};  // raw 128-bit Pyramid frame
    status = scan_pyramid(card_data);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(card_data), card_data);
}

static data_frame_tx_t *cmd_processor_jablotron_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t id[5];
        uint8_t new_key[4];
        uint8_t old_keys[4];
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if (length < sizeof(payload_t) || (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    status = write_jablotron_to_t55xx(payload->id, payload->new_key, payload->old_keys, (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys));
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_lf_t55xx_write(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t block;    /* block number */
        uint8_t word[4];  /* 32-bit data word, big-endian */
        uint8_t use_pwd;  /* 1 = password write, 0 = open write */
        uint8_t pwd[4];   /* 32-bit password, big-endian (ignored when use_pwd == 0) */
        uint8_t page1;    /* 1 = target page 1, 0 = page 0 */
    } PACKED payload_t;

    if (length < sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *p = (payload_t *)data;

    bool    page1     = (bool)p->page1;
    uint8_t max_block = page1 ? 3u : 7u;

    if (p->block > max_block) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    uint32_t word    = bytes_to_num(p->word, 4);
    uint32_t passwd  = bytes_to_num(p->pwd,  4);
    bool     use_pwd = (bool)p->use_pwd;

    status = lf_t55xx_write_block(p->block, word, passwd, use_pwd, page1);
    return data_frame_make(cmd, status, 0, NULL);
}

#define GENERIC_READ_LEN 800
#define GENERIC_READ_TIMEOUT_MS 500
static data_frame_tx_t *cmd_processor_generic_read(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t *outdata = malloc(GENERIC_READ_LEN);

    if (outdata == NULL) {
        return data_frame_make(cmd, STATUS_MEM_ERR, 0, NULL);
    }

    size_t outlen = 0;
    if (!raw_read_to_buffer(outdata, GENERIC_READ_LEN, GENERIC_READ_TIMEOUT_MS, &outlen)) {
        free(outdata);
        return data_frame_make(cmd, STATUS_CMD_ERR, 0, NULL);
    };
    data_frame_tx_t *frame = data_frame_make(cmd, STATUS_LF_TAG_OK, outlen, outdata);

    free(outdata);

    if (frame == NULL) {
        return data_frame_make(cmd, STATUS_CREATE_RESPONSE_ERR, 0, NULL);
    }

    return frame;
}

#endif


static data_frame_tx_t *cmd_processor_set_active_slot(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] >= TAG_MAX_SLOT_NUM) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    change_slot_auto(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_tag_type(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t num_slot;
        uint16_t tag_type;
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    tag_specific_type_t tag_type = U16NTOHS(payload->tag_type);
    if (payload->num_slot >= TAG_MAX_SLOT_NUM || !is_tag_specific_type_valid(tag_type)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_emulation_change_type(payload->num_slot, tag_type);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_delete_slot_sense_type(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t num_slot;
        uint8_t sense_type;
    } PACKED payload_t;
    payload_t *payload = (payload_t *)data;
    if ((length != sizeof(payload_t)) ||
            (payload->num_slot >= TAG_MAX_SLOT_NUM) ||
            (payload->sense_type != TAG_SENSE_HF && payload->sense_type != TAG_SENSE_LF)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    tag_emulation_delete_data(payload->num_slot, payload->sense_type);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_data_default(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t num_slot;
        uint16_t tag_type;
    } PACKED payload_t;
    if (length != sizeof(payload_t)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    payload_t *payload = (payload_t *)data;
    tag_specific_type_t tag_type = U16NTOHS(payload->tag_type);
    if (payload->num_slot >= TAG_MAX_SLOT_NUM || !is_tag_specific_type_valid(tag_type)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    status = tag_emulation_factory_data(payload->num_slot, tag_type) ? STATUS_SUCCESS : STATUS_NOT_IMPLEMENTED;
    return data_frame_make(cmd, status, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t slot_index;
        uint8_t sense_type;
        uint8_t enabled;
    } PACKED payload_t;

    payload_t *payload = (payload_t *)data;
    if (length != sizeof(payload_t) ||
            payload->slot_index >= TAG_MAX_SLOT_NUM ||
            (payload->sense_type != TAG_SENSE_HF && payload->sense_type != TAG_SENSE_LF) ||
            payload->enabled > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    uint8_t slot_now = payload->slot_index;
    tag_emulation_slot_set_enable(slot_now, payload->sense_type, payload->enabled);
    if ((!payload->enabled) &&
            (!is_slot_enabled(slot_now, payload->sense_type == TAG_SENSE_HF ? TAG_SENSE_LF : TAG_SENSE_HF))) {
        // HF and LF disabled, need to change slot
        uint8_t slot_prev = tag_emulation_slot_find_next(slot_now);
        NRF_LOG_INFO("slot_now = %d, slot_prev = %d", slot_now, slot_prev);
        if (slot_prev == slot_now) {
            set_slot_light_color(RGB_MAGENTA);
        } else {
            change_slot_auto(slot_prev);
        }
    }
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_slot_data_config_save(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_emulation_save();
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_active_slot(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t slot = tag_emulation_get_slot();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &slot);
}

static data_frame_tx_t *cmd_processor_get_slot_info(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint16_t hf_tag_type;
        uint16_t lf_tag_type;
    } PACKED payload[8];

    tag_slot_specific_type_t tag_types;
    for (uint8_t slot = 0; slot < 8; slot++) {
        tag_emulation_get_specific_types_by_slot(slot, &tag_types);
        payload[slot].hf_tag_type = U16HTONS(tag_types.tag_hf);
        payload[slot].lf_tag_type = U16HTONS(tag_types.tag_lf);
    }

    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_wipe_fds(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    bool success = fds_wipe();
    status = success ? STATUS_SUCCESS : STATUS_FLASH_WRITE_FAIL;
    delayed_reset(50);
    return data_frame_make(cmd, status, 0, NULL);
}

static bool get_active_em410x_type(tag_specific_type_t *tag_type_out, uint16_t *id_size_out) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf == TAG_TYPE_EM410X || tag_types.tag_lf == TAG_TYPE_EM410X_ELECTRA) {
        *tag_type_out = tag_types.tag_lf;
        *id_size_out = (tag_types.tag_lf == TAG_TYPE_EM410X_ELECTRA) ? LF_EM410X_ELECTRA_TAG_ID_SIZE : LF_EM410X_TAG_ID_SIZE;
        return true;
    }
    return false;
}

static data_frame_tx_t *cmd_processor_em410x_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_specific_type_t tag_type;
    uint16_t id_size;
    if (!get_active_em410x_type(&tag_type, &id_size) || length != id_size) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(tag_type);
    memcpy(buffer->buffer, data, id_size);
    tag_emulation_load_by_buffer(tag_type, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_em410x_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_specific_type_t tag_type;
    uint16_t id_size;
    if (!get_active_em410x_type(&tag_type, &id_size)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);  // no data in slot, don't send garbage
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(tag_type);
    uint8_t resp[2 + LF_EM410X_ELECTRA_TAG_ID_SIZE] = {0x00};
    resp[0] = tag_type >> 8;
    resp[1] = tag_type;
    memcpy(resp + 2, buffer->buffer, id_size);
    return data_frame_make(cmd, STATUS_SUCCESS, 2 + id_size, resp);
}

static data_frame_tx_t *cmd_processor_hidprox_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != LF_HIDPROX_TAG_ID_SIZE) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_HID_PROX);
    memcpy(buffer->buffer, data, LF_HIDPROX_TAG_ID_SIZE);
    tag_emulation_load_by_buffer(TAG_TYPE_HID_PROX, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_hidprox_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf != TAG_TYPE_HID_PROX) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);  // no data in slot, don't send garbage
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_HID_PROX);
    return data_frame_make(cmd, STATUS_SUCCESS, LF_HIDPROX_TAG_ID_SIZE, buffer->buffer);
}

static data_frame_tx_t *cmd_processor_ioprox_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != LF_IOPROX_TAG_ID_SIZE) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_IOPROX);
    memcpy(buffer->buffer, data, LF_IOPROX_TAG_ID_SIZE);
    tag_emulation_load_by_buffer(TAG_TYPE_IOPROX, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_idteck_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != LF_IDTECK_TAG_ID_SIZE) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_IDTECK);
    memcpy(buffer->buffer, data, LF_IDTECK_TAG_ID_SIZE);
    tag_emulation_load_by_buffer(TAG_TYPE_IDTECK, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_idteck_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf != TAG_TYPE_IDTECK) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_IDTECK);
    return data_frame_make(cmd, STATUS_SUCCESS, LF_IDTECK_TAG_ID_SIZE, buffer->buffer);
}

static data_frame_tx_t *cmd_processor_seos_read_emu_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_SEOS);
    nfc_tag_seos_information_t *info = (nfc_tag_seos_information_t *)buffer->buffer;

    uint8_t output[1+info->diversifier_len + 1+info->oid_len + 1+info->data_tag_len + 1+info->data_len + 2];
    uint16_t offset = 0;

    output[offset++] = info->data_len;
    memcpy(output+offset, info->data, info->data_len);
    offset += info->data_len;

    output[offset++] = info->oid_len;
    memcpy(output+offset, info->oid, info->oid_len);
    offset += info->oid_len;

    output[offset++] = info->data_tag_len;
    memcpy(output+offset, info->data_tag, info->data_tag_len);
    offset += info->data_tag_len;

    output[offset++] = info->diversifier_len;
    memcpy(output+offset, info->diversifier, info->diversifier_len);
    offset += info->diversifier_len;

    output[offset++] = info->hash_alg;
    output[offset++] = info->encr_alg;

    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(output), output);
}

static data_frame_tx_t *cmd_processor_seos_write_emu_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length < 6) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_SEOS);
    nfc_tag_seos_information_t *info = (nfc_tag_seos_information_t *)buffer->buffer;

    uint16_t offset = 0;

    uint8_t len = data[offset++];
    if (len > NFC_TAG_SEOS_DATA_MAX) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    info->data_len = len;
    memcpy(info->data, data+offset, len);
    offset += len;

    len = data[offset++];
    if (len > NFC_TAG_SEOS_OID_MAX) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    info->oid_len = len;
    memcpy(info->oid, data+offset, len);
    offset += len;

    len = data[offset++];
    if (len > NFC_TAG_SEOS_DATA_TAG_MAX) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    info->data_tag_len = len;
    memcpy(info->data_tag, data+offset, len);
    offset += len;

    len = data[offset++];
    if (len > NFC_TAG_SEOS_DIVERSIFIER_MAX) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    info->diversifier_len = len;
    memcpy(info->diversifier, data+offset, len);
    offset += len;

    info->hash_alg = data[offset++];
    info->encr_alg = data[offset++];

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_seos_write_emu_keys(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 16 * 3) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_SEOS);
    nfc_tag_seos_information_t *info = (nfc_tag_seos_information_t *)buffer->buffer;

    memcpy(info->authkey, data+ 0, 16);
    memcpy(info->privenc, data+16, 16);
    memcpy(info->privmac, data+32, 16);

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

#if defined(PROJECT_CHAMELEON_ULTRA)
// T55xx clone is only available on Chameleon Ultra; the Lite firmware
// has no LF reader hardware and does not compile the write_*_to_t55xx
// helpers in lf_reader_main.c.
static data_frame_tx_t *cmd_processor_idteck_write_to_t55xx(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    typedef struct {
        uint8_t card_data[LF_IDTECK_TAG_ID_SIZE];
        uint8_t new_key[4];
        uint8_t old_keys[4];
    } PACKED payload_t;

    payload_t *payload = (payload_t *)data;

    if (length < sizeof(payload_t) ||
        (length - offsetof(payload_t, old_keys)) % sizeof(payload->old_keys) != 0) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    uint8_t old_cnt = (length - offsetof(payload_t, old_keys)) / sizeof(payload->old_keys);
    status = write_idteck_to_t55xx(payload->card_data, payload->new_key, payload->old_keys, old_cnt);
    return data_frame_make(cmd, status, 0, NULL);
}
#endif

static data_frame_tx_t *cmd_processor_ioprox_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf != TAG_TYPE_IOPROX) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);  // no data in slot, don't send garbage
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_IOPROX);
    return data_frame_make(cmd, STATUS_SUCCESS, LF_IOPROX_TAG_ID_SIZE, buffer->buffer);
}

static data_frame_tx_t *cmd_processor_viking_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != LF_VIKING_TAG_ID_SIZE) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_VIKING);
    memcpy(buffer->buffer, data, LF_VIKING_TAG_ID_SIZE);
    tag_emulation_load_by_buffer(TAG_TYPE_VIKING, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_viking_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf != TAG_TYPE_VIKING) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);  // no data in slot, don't send garbage
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_VIKING);
    return data_frame_make(cmd, STATUS_SUCCESS, LF_VIKING_TAG_ID_SIZE, buffer->buffer);
}

static data_frame_tx_t *cmd_processor_pac_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != LF_PAC_TAG_ID_SIZE) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_PAC);
    memcpy(buffer->buffer, data, LF_PAC_TAG_ID_SIZE);
    tag_emulation_load_by_buffer(TAG_TYPE_PAC, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_pac_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf != TAG_TYPE_PAC) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_PAC);
    return data_frame_make(cmd, STATUS_SUCCESS, LF_PAC_TAG_ID_SIZE, buffer->buffer);
}

static data_frame_tx_t *cmd_processor_jablotron_set_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != LF_JABLOTRON_TAG_ID_SIZE) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_JABLOTRON);
    memcpy(buffer->buffer, data, LF_JABLOTRON_TAG_ID_SIZE);
    tag_emulation_load_by_buffer(TAG_TYPE_JABLOTRON, false);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_jablotron_get_emu_id(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t tag_types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);
    if (tag_types.tag_lf != TAG_TYPE_JABLOTRON) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, data);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_JABLOTRON);
    return data_frame_make(cmd, STATUS_SUCCESS, LF_JABLOTRON_TAG_ID_SIZE, buffer->buffer);
}

static nfc_tag_14a_coll_res_reference_t *get_coll_res_data(bool write) {
    nfc_tag_14a_coll_res_reference_t *info;
    tag_slot_specific_type_t tag_types;

    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &tag_types);

    switch (tag_types.tag_hf) {
        case TAG_TYPE_MIFARE_1024:
        case TAG_TYPE_MIFARE_2048:
        case TAG_TYPE_MIFARE_4096:
        case TAG_TYPE_MIFARE_Mini:
            info = write ? get_mifare_coll_res() : get_saved_mifare_coll_res();
            break;
        case TAG_TYPE_MF0ICU1:
        case TAG_TYPE_MF0ICU2:
        case TAG_TYPE_MF0UL11:
        case TAG_TYPE_MF0UL21:
        case TAG_TYPE_NTAG_210:
        case TAG_TYPE_NTAG_212:
        case TAG_TYPE_NTAG_213:
        case TAG_TYPE_NTAG_215:
        case TAG_TYPE_NTAG_216:
            info = nfc_tag_mf0_ntag_get_coll_res();
            break;
        case TAG_TYPE_HF14A_4:
            info = nfc_tag_14a_4_get_coll_res();
            break;
        case TAG_TYPE_SEOS:
            info = nfc_tag_seos_get_coll_res();
            break;
        default:
            // no collision resolution data for slot
            info = NULL;
            break;
    }

    return info;
}

static data_frame_tx_t *cmd_processor_hf14a_get_anti_coll_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    nfc_tag_14a_coll_res_reference_t *info = get_coll_res_data(false);

    if (info == NULL) return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);

    // uidlen[1]|uid[uidlen]|atqa[2]|sak[1]|atslen[1]|ats[atslen]
    // dynamic length, so no struct
    uint8_t payload[1 + *info->size + 2 + 1 + 1 + 254];
    uint16_t offset = 0;
    payload[offset++] = *info->size;
    memcpy(&payload[offset], info->uid, *info->size);
    offset += *info->size;
    memcpy(&payload[offset], info->atqa, 2);
    offset += 2;
    payload[offset++] = *info->sak;
    if (info->ats->length > 0) {
        payload[offset++] = info->ats->length;
        memcpy(&payload[offset], info->ats->data, info->ats->length);
        offset += info->ats->length;
    } else {
        payload[offset++] = 0;
    }
    return data_frame_make(cmd, STATUS_SUCCESS, offset, payload);
}

static data_frame_tx_t *cmd_processor_mf1_set_detection_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_detection_log_clear();
    nfc_tag_mf1_set_detection_enable(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_detection_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t is_enable = nfc_tag_mf1_is_detection_enable();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, (uint8_t *)(&is_enable));
}

static data_frame_tx_t *cmd_processor_mf1_get_detection_count(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint32_t count = nfc_tag_mf1_detection_log_count();
    if (count == 0xFFFFFFFF) {
        count = 0;
    }
    uint32_t payload = U32HTONL(count);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(uint32_t), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_mf1_get_detection_log(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint32_t count;
    uint32_t index;
    uint8_t *resp = NULL;
    nfc_tag_mf1_auth_log_t *logs = mf1_get_auth_log(&count);
    if (length != 4 || count == 0xFFFFFFFF) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    index = U32NTOHL(*(uint32_t *)data);
    // NRF_LOG_INFO("index = %d", index);
    if (index >= count) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    resp = (uint8_t *)(logs + index);
    length = MIN(count - index, NETDATA_MAX_DATA_LENGTH / sizeof(nfc_tag_mf1_auth_log_t)) * sizeof(nfc_tag_mf1_auth_log_t);
    return data_frame_make(cmd, STATUS_SUCCESS, length, resp);
}

static data_frame_tx_t *cmd_processor_mf1_write_emu_block_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 0 || (((length - 1) % NFC_TAG_MF1_DATA_SIZE) != 0)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t block_index = data[0];
    uint8_t block_count = (length - 1) / NFC_TAG_MF1_DATA_SIZE;
    if (block_index + block_count > NFC_TAG_MF1_BLOCK_MAX) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_MIFARE_4096);
    nfc_tag_mf1_information_t *info = (nfc_tag_mf1_information_t *)buffer->buffer;
    for (int i = 1, j = block_index; i < length; i += NFC_TAG_MF1_DATA_SIZE, j++) {
        uint8_t *p_block = &data[i];
        memcpy(info->memory[j], p_block, NFC_TAG_MF1_DATA_SIZE);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_read_emu_block_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if ((length != 2) || (data[1] < 1) || (data[1] > 32) || (data[0] + data[1] > NFC_TAG_MF1_BLOCK_MAX)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t block_index = data[0];
    uint8_t block_count = data[1];
    tag_data_buffer_t *buffer = get_buffer_by_tag_type(TAG_TYPE_MIFARE_4096);
    nfc_tag_mf1_information_t *info = (nfc_tag_mf1_information_t *)buffer->buffer;
    uint16_t result_length = block_count * NFC_TAG_MF1_DATA_SIZE;
    uint8_t result_buffer[result_length];
    for (int i = 0, j = block_index; i < result_length; i += NFC_TAG_MF1_DATA_SIZE, j++) {
        memcpy(&result_buffer[i], info->memory[j], NFC_TAG_MF1_DATA_SIZE);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, result_length, result_buffer);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_write_emu_page_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t byte;
    uint8_t active_slot = tag_emulation_get_slot();

    tag_slot_specific_type_t active_slot_tag_types;
    tag_emulation_get_specific_types_by_slot(active_slot, &active_slot_tag_types);

    int nr_pages = nfc_tag_mf0_ntag_get_nr_pages_by_tag_type(active_slot_tag_types.tag_hf);
    // This means wrong slot type.
    if (nr_pages <= 0) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, data);

    if (length < 2) {
        byte = nr_pages;
        return data_frame_make(cmd, STATUS_PAR_ERR, 1, &byte);
    }

    int page_index = data[0];
    int pages_count = data[1];
    int byte_length = (int)pages_count * NFC_TAG_MF0_NTAG_DATA_SIZE;

    if (pages_count == 0) return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
    else if (
        (page_index >= ((int)nr_pages))
        || (pages_count > (((int)nr_pages) - page_index))
        || (((int)length - 2) < byte_length)
    ) {
        byte = nr_pages;
        return data_frame_make(cmd, STATUS_PAR_ERR, 1, &byte);
    }

    tag_data_buffer_t *buffer = get_buffer_by_tag_type(active_slot_tag_types.tag_hf);
    nfc_tag_mf0_ntag_information_t *info = (nfc_tag_mf0_ntag_information_t *)buffer->buffer;

    memcpy(&info->memory[page_index][0], &data[2], byte_length);

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_emu_page_count(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t byte;
    uint8_t active_slot = tag_emulation_get_slot();

    tag_slot_specific_type_t active_slot_tag_types;
    tag_emulation_get_specific_types_by_slot(active_slot, &active_slot_tag_types);

    int nr_pages = nfc_tag_mf0_ntag_get_nr_pages_by_tag_type(active_slot_tag_types.tag_hf);
    // This means wrong slot type.
    if (nr_pages <= 0) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, data);

    // Convert the int value to u8 value if it's valid.
    byte = nr_pages;
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &byte);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_read_emu_page_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t byte;
    uint8_t active_slot = tag_emulation_get_slot();

    tag_slot_specific_type_t active_slot_tag_types;
    tag_emulation_get_specific_types_by_slot(active_slot, &active_slot_tag_types);

    int nr_pages = nfc_tag_mf0_ntag_get_nr_pages_by_tag_type(active_slot_tag_types.tag_hf);
    // This means wrong slot type.
    if (nr_pages <= 0) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, data);

    if (length < 2) {
        byte = nr_pages;
        return data_frame_make(cmd, STATUS_PAR_ERR, 1, &byte);
    }

    int page_index = data[0];
    int pages_count = data[1];

    if (pages_count == 0) return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);

    tag_data_buffer_t *buffer = get_buffer_by_tag_type(active_slot_tag_types.tag_hf);
    nfc_tag_mf0_ntag_information_t *info = (nfc_tag_mf0_ntag_information_t *)buffer->buffer;

    return data_frame_make(cmd, STATUS_SUCCESS, pages_count * NFC_TAG_MF0_NTAG_DATA_SIZE, &info->memory[page_index][0]);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_version_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t *version_data = nfc_tag_mf0_ntag_get_version_data();
    if (version_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);

    return data_frame_make(cmd, STATUS_SUCCESS, NFC_TAG_MF0_NTAG_VER_SIZE, version_data);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_set_version_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 8) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);

    uint8_t *version_data = nfc_tag_mf0_ntag_get_version_data();
    if (version_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);
    memcpy(version_data, data, NFC_TAG_MF0_NTAG_VER_SIZE);

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_signature_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t *signature_data = nfc_tag_mf0_ntag_get_signature_data();
    if (signature_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);

    return data_frame_make(cmd, STATUS_SUCCESS, NFC_TAG_MF0_NTAG_SIG_SIZE, signature_data);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_set_signature_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != NFC_TAG_MF0_NTAG_SIG_SIZE) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);

    uint8_t *signature_data = nfc_tag_mf0_ntag_get_signature_data();
    if (signature_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);
    memcpy(signature_data, data, NFC_TAG_MF0_NTAG_SIG_SIZE);

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_counter_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);

    uint8_t index = data[0] & 0x7F;
    uint8_t *counter_data = nfc_tag_mf0_ntag_get_counter_data_by_index(index);
    if (counter_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);

    bool tearing = (counter_data[MF0_NTAG_AUTHLIM_OFF_IN_CTR] & MF0_NTAG_AUTHLIM_MASK_IN_CTR) != 0;

    uint8_t response[4];
    memcpy(response, counter_data, 3);
    response[3] = tearing ? 0x00 : 0xBD;

    return data_frame_make(cmd, STATUS_SUCCESS, 4, response);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_set_counter_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 4) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);

    uint8_t index = data[0] & 0x7F;
    uint8_t *counter_data = nfc_tag_mf0_ntag_get_counter_data_by_index(index);
    if (counter_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);

    // clear tearing event flag
    if ((data[0] & 0x80) == 0x80) {
        counter_data[MF0_NTAG_AUTHLIM_OFF_IN_CTR] &= ~MF0_NTAG_TEARING_MASK_IN_AUTHLIM;
    }

    // copy the actual counter value
    memcpy(counter_data, &data[1], 3);

    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_reset_auth_cnt(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // all tags with counters support auth
    uint8_t *counter_data = nfc_tag_mf0_ntag_get_counter_data_by_index(0);
    if (counter_data == NULL) return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);

    uint8_t old_value = counter_data[MF0_NTAG_AUTHLIM_OFF_IN_CTR] & MF0_NTAG_AUTHLIM_MASK_IN_CTR;
    counter_data[MF0_NTAG_AUTHLIM_OFF_IN_CTR] &= ~MF0_NTAG_AUTHLIM_MASK_IN_CTR;

    return data_frame_make(cmd, STATUS_SUCCESS, 1, &old_value);
}

static data_frame_tx_t *cmd_processor_hf14a_set_anti_coll_data(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    // uidlen[1]|uid[uidlen]|atqa[2]|sak[1]|atslen[1]|ats[atslen]
    // dynamic length, so no struct
    if ((length < 1) || \
            (!is_valid_uid_size(data[0])) || \
            (length < 1 + data[0] + 2 + 1 + 1) || \
            (length < 1 + data[0] + 2 + 1 + 1 + data[1 + data[0] + 2 + 1])) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_14a_coll_res_reference_t *info = get_coll_res_data(true);

    uint16_t offset = 0;
    *(info->size) = (nfc_tag_14a_uid_size)data[offset];
    offset++;
    memcpy(info->uid, &data[offset], *(info->size));
    offset += *(info->size);
    memcpy(info->atqa, &data[offset], 2);
    offset += 2;
    info->sak[0] = data[offset];
    offset ++;
    info->ats->length = data[offset];
    offset ++;
    memcpy(info->ats->data, &data[offset], info->ats->length);
    offset += info->ats->length;
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_set_slot_tag_nick(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length < 3 || length > 34) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t slot = data[0];
    uint8_t sense_type = data[1];
    fds_slot_record_map_t map_info;
    if (slot >= TAG_MAX_SLOT_NUM || (sense_type != TAG_SENSE_HF && sense_type != TAG_SENSE_LF)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    get_fds_map_by_slot_sense_type_for_nick(slot, sense_type, &map_info);

    uint8_t buffer[36];
    buffer[0] = length - 2;
    memcpy(buffer + 1, data + 2, buffer[0]);

    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(buffer), buffer);
    if (!ret) {
        return data_frame_make(cmd, STATUS_FLASH_WRITE_FAIL, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_slot_tag_nick(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 2) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t slot = data[0];
    uint8_t sense_type = data[1];
    uint8_t buffer[36];
    fds_slot_record_map_t map_info;

    if (slot >= TAG_MAX_SLOT_NUM || (sense_type != TAG_SENSE_HF && sense_type != TAG_SENSE_LF)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    get_fds_map_by_slot_sense_type_for_nick(slot, sense_type, &map_info);
    uint16_t buffer_length = sizeof(buffer);
    bool ret = fds_read_sync(map_info.id, map_info.key, &buffer_length, buffer);
    if (!ret) {
        return data_frame_make(cmd, STATUS_FLASH_READ_FAIL, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, buffer[0], &buffer[1]);
}

static data_frame_tx_t *cmd_processor_get_all_slot_nicks(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t response_buffer[TAG_MAX_SLOT_NUM * 2 * 37]; // Max possible size: 8 slots * 2 sense types * (1 byte length + 36 bytes nick)
    uint16_t response_length = 0;

    for (uint8_t slot = 0; slot < TAG_MAX_SLOT_NUM; slot++) {
        uint8_t hf_buffer[36];
        fds_slot_record_map_t hf_map_info;
        get_fds_map_by_slot_sense_type_for_nick(slot, TAG_SENSE_HF, &hf_map_info);
        uint16_t hf_buffer_length = sizeof(hf_buffer);
        bool hf_ret = fds_read_sync(hf_map_info.id, hf_map_info.key, &hf_buffer_length, hf_buffer);

        if (hf_ret && hf_buffer_length > 0) {
            response_buffer[response_length++] = hf_buffer[0];
            for (uint8_t i = 1; i <= hf_buffer[0] && i < hf_buffer_length; i++) {
                response_buffer[response_length++] = hf_buffer[i];
            }
        } else {
            response_buffer[response_length++] = 0;
        }

        uint8_t lf_buffer[36];
        fds_slot_record_map_t lf_map_info;
        get_fds_map_by_slot_sense_type_for_nick(slot, TAG_SENSE_LF, &lf_map_info);
        uint16_t lf_buffer_length = sizeof(lf_buffer);
        bool lf_ret = fds_read_sync(lf_map_info.id, lf_map_info.key, &lf_buffer_length, lf_buffer);

        if (lf_ret && lf_buffer_length > 0) {
            response_buffer[response_length++] = lf_buffer[0];
            for (uint8_t i = 1; i <= lf_buffer[0] && i < lf_buffer_length; i++) {
                response_buffer[response_length++] = lf_buffer[i];
            }
        } else {
            response_buffer[response_length++] = 0;
        }
    }

    return data_frame_make(cmd, STATUS_SUCCESS, response_length, response_buffer);
}

static data_frame_tx_t *cmd_processor_delete_slot_tag_nick(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 2) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t slot = data[0];
    uint8_t sense_type = data[1];
    fds_slot_record_map_t map_info;

    if (slot >= TAG_MAX_SLOT_NUM || (sense_type != TAG_SENSE_HF && sense_type != TAG_SENSE_LF)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    get_fds_map_by_slot_sense_type_for_nick(slot, sense_type, &map_info);
    bool ret = fds_delete_sync(map_info.id, map_info.key);
    if (!ret) {
        return data_frame_make(cmd, STATUS_FLASH_WRITE_FAIL, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_emulator_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mf1_info[5] = {};
    mf1_info[0] = nfc_tag_mf1_is_detection_enable();
    mf1_info[1] = nfc_tag_mf1_is_gen1a_magic_mode();
    mf1_info[2] = nfc_tag_mf1_is_gen2_magic_mode();
    mf1_info[3] = nfc_tag_mf1_is_use_mf1_coll_res();
    mf1_info[4] = nfc_tag_mf1_get_write_mode();
    return data_frame_make(cmd, STATUS_SUCCESS, 5, mf1_info);
}

static data_frame_tx_t *cmd_processor_mf1_get_prng_type(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t type = nfc_tag_mf1_get_prng_type();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &type);
}

static data_frame_tx_t *cmd_processor_mf1_set_prng_type(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] > 2) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_set_prng_type(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &data[0]);  // echo back the set value
}

static data_frame_tx_t *cmd_processor_mf1_get_gen1a_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mode = nfc_tag_mf1_is_gen1a_magic_mode();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &mode);
}

static data_frame_tx_t *cmd_processor_mf1_set_gen1a_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 && data[0] > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_set_gen1a_magic_mode(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_gen2_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mode = nfc_tag_mf1_is_gen2_magic_mode();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &mode);
}

static data_frame_tx_t *cmd_processor_mf1_set_gen2_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 && data[0] > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_set_gen2_magic_mode(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_block_anti_coll_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mode = nfc_tag_mf1_is_use_mf1_coll_res();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &mode);
}

static data_frame_tx_t *cmd_processor_mf1_set_block_anti_coll_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 && data[0] > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_set_use_mf1_coll_res(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_write_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mode = nfc_tag_mf1_get_write_mode();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &mode);
}

static data_frame_tx_t *cmd_processor_mf1_set_write_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] > 3) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_set_write_mode(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf1_get_field_off_do_reset(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t enable = nfc_tag_mf1_is_field_off_do_reset();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &enable);
}

static data_frame_tx_t *cmd_processor_mf1_set_field_off_do_reset(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] >= 2) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf1_set_field_off_do_reset(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_get_enabled_slots(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    struct {
        uint8_t enabled_hf;
        uint8_t enabled_lf;
    } PACKED payload[8];
    for (uint8_t slot = 0; slot < 8; slot++) {
        payload[slot].enabled_hf = is_slot_enabled(slot, TAG_SENSE_HF);
        payload[slot].enabled_lf = is_slot_enabled(slot, TAG_SENSE_LF);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_get_ble_connect_key(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    return data_frame_make(cmd, STATUS_SUCCESS, BLE_PAIRING_KEY_LEN, settings_get_ble_connect_key());
}

static data_frame_tx_t *cmd_processor_set_ble_connect_key(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != BLE_PAIRING_KEY_LEN) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    // Must be 6 ASCII characters, can only be 0-9.
    bool is_valid_key = true;
    for (uint8_t i = 0; i < BLE_PAIRING_KEY_LEN; i++) {
        if (data[i] < '0' || data[i] > '9') {
            is_valid_key = false;
            break;
        }
    }
    if (!is_valid_key) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    // Key is valid, we can update to config
    settings_set_ble_connect_key(data);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_delete_all_ble_bonds(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    advertising_stop();
    delete_bonds_all();
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

#if defined(PROJECT_CHAMELEON_ULTRA)


/**
 * before reader run, reset reader and on antenna,
 * we must to wait some time, to init picc(power).
 */
static data_frame_tx_t *before_reader_run(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    device_mode_t mode = get_device_mode();
    if (mode != DEVICE_MODE_READER) {
        return data_frame_make(cmd, STATUS_DEVICE_MODE_ERROR, 0, NULL);
    }
    return NULL;
}


/**
 * before reader run, reset reader and on antenna,
 * we must to wait some time, to init picc(power).
 */
static data_frame_tx_t *before_hf_reader_run(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    data_frame_tx_t *ret = before_reader_run(cmd, status, length, data);
    if (ret == NULL) {
        pcd_14a_reader_reset();
        pcd_14a_reader_antenna_on();
        bsp_delay_ms(8);
    }
    return ret;
}

/**
 * after reader run, off antenna, to keep battery.
 */
static data_frame_tx_t *after_hf_reader_run(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    pcd_14a_reader_antenna_off();
    return NULL;
}

#endif

// fct will be defined after m_data_cmd_map because we need to know its size
data_frame_tx_t *cmd_processor_get_device_capabilities(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data);

static data_frame_tx_t *cmd_processor_mf0_ntag_get_uid_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    int rc = nfc_tag_mf0_ntag_get_uid_mode();
    if (rc < 0) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    else {
        uint8_t mode = rc;
        return data_frame_make(cmd, STATUS_SUCCESS, 1, &mode);
    }
}

static data_frame_tx_t *cmd_processor_mf0_ntag_set_uid_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || !nfc_tag_mf0_ntag_set_uid_mode(data[0] != 0)) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_write_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mode = nfc_tag_mf0_ntag_get_write_mode();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, &mode);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_set_write_mode(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] > 4) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf0_ntag_set_write_mode(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_set_detection_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] > 1) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    nfc_tag_mf0_ntag_detection_log_clear();
    nfc_tag_mf0_ntag_set_detection_enable(data[0]);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_detection_enable(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t is_enable = nfc_tag_mf0_ntag_is_detection_enable();
    return data_frame_make(cmd, STATUS_SUCCESS, 1, (uint8_t *)(&is_enable));
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_detection_count(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint32_t count = nfc_tag_mf0_ntag_detection_log_count();
    if (count == 0xFFFFFFFF) {
        count = 0;
    }
    uint32_t payload = U32HTONL(count);
    return data_frame_make(cmd, STATUS_SUCCESS, sizeof(uint32_t), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_mf0_ntag_get_detection_log(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint32_t count;
    uint32_t index;
    uint8_t *resp = NULL;
    nfc_tag_mf0_ntag_auth_log_t *logs = mf0_get_auth_log(&count);
    if (length != 4 || count == 0xFFFFFFFF) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    index = U32NTOHL(*(uint32_t *)data);
    if (index >= count) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    resp = (uint8_t *)(logs + index);
    length = MIN(count - index, NETDATA_MAX_DATA_LENGTH / sizeof(nfc_tag_mf0_ntag_auth_log_t)) * sizeof(nfc_tag_mf0_ntag_auth_log_t);
    return data_frame_make(cmd, STATUS_SUCCESS, length, resp);
}

static data_frame_tx_t *cmd_processor_mf0_get_emulator_config(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t mf0_info[3] = {};
    mf0_info[0] = nfc_tag_mf0_ntag_is_detection_enable();
    mf0_info[1] = nfc_tag_mf0_ntag_get_uid_mode();
    mf0_info[2] = nfc_tag_mf0_ntag_get_write_mode();
    return data_frame_make(cmd, STATUS_SUCCESS, 3, mf0_info);
}

/**
 * (cmd -> processor) function map, the map struct is:
 *       cmd code                               before process               cmd processor                                after process
 */
#if defined(PROJECT_CHAMELEON_ULTRA)
static data_frame_tx_t *cmd_processor_em4x05_scan(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    em4x05_data_t tag = {0};
    status = scan_em4x05(&tag);
    if (status != STATUS_LF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    struct {
        uint32_t config;
        uint32_t uid;
        uint32_t uid_hi;
        uint8_t  is_em4x69;
    } PACKED payload;
    payload.config    = U32HTONL(tag.config);
    payload.uid       = U32HTONL(tag.uid);
    payload.uid_hi    = U32HTONL(tag.uid_hi);
    payload.is_em4x69 = tag.is_em4x69 ? 1 : 0;
    return data_frame_make(cmd, STATUS_LF_TAG_OK, sizeof(payload), (uint8_t *)&payload);
}

static data_frame_tx_t *cmd_processor_lf_sniff(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    /* Optional 2-byte big-endian timeout in ms from host (default 2000ms) */
    uint32_t timeout_ms = 2000;
    if (length >= 2) {
        timeout_ms = ((uint32_t)data[0] << 8) | data[1];
        if (timeout_ms == 0 || timeout_ms > 10000) timeout_ms = 2000;
    }

    static uint8_t sniff_buf[LF_SNIFF_MAX_SAMPLES];
    size_t outlen = 0;
    raw_read_to_buffer(sniff_buf, LF_SNIFF_MAX_SAMPLES, timeout_ms, &outlen);

    if (outlen == 0) {
        return data_frame_make(cmd, STATUS_LF_TAG_NO_FOUND, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_LF_TAG_OK, (uint16_t)outlen, sniff_buf);
}

/* ========================================================================
 * HF14A AUTH TRACE — full anticoll + Crypto1 auth flow, every frame returned.
 *
 * Performs a complete reader-side auth sequence against a real MIFARE Classic
 * tag and packs every wire frame (synthesized anticoll + actual auth) into the
 * same trace-buffer format used by `hf 14a sniff`, so the existing host-side
 * decoder can render the full exchange.
 *
 * Buffer format (identical to hf 14a sniff): [bits_be16][data...] per frame.
 * Bit15 of the bit-count header: 0 = reader→card, 1 = card→reader.
 *
 * Request payload: [type:1][block:1][key:6]   — 8 bytes total
 *   type:  PICC_AUTHENT1A (0x60) or PICC_AUTHENT1B (0x61)
 *   block: target block number
 *   key:   6-byte sector key
 *
 * Response payload: packed frame buffer, decoded host-side.
 * Status: STATUS_HF_TAG_OK if the auth completed (NT, NR||AR, AT all captured),
 *         STATUS_HF_TAG_NO if no card was found,
 *         STATUS_MF_ERR_AUTH if AT was wrong or missing (partial trace returned),
 *         STATUS_PAR_ERR on bad payload length.
 * ======================================================================== */
#define HF_AUTH_TRACE_BUF_SIZE 256

static uint8_t  m_auth_trace_buf[HF_AUTH_TRACE_BUF_SIZE];
static uint16_t m_auth_trace_len = 0;

/* Append one frame to the trace buffer, mirroring hf14a_sniff_store(). */
static void auth_trace_store(const uint8_t *data, uint16_t szBits, bool is_tx) {
    uint16_t szBytes = (szBits + 7) / 8;
    if (m_auth_trace_len + 2 + szBytes > HF_AUTH_TRACE_BUF_SIZE) return;
    uint16_t hdr = szBits | (is_tx ? 0x8000u : 0x0000u);
    m_auth_trace_buf[m_auth_trace_len++] = (hdr >> 8) & 0xFF;
    m_auth_trace_buf[m_auth_trace_len++] =  hdr        & 0xFF;
    memcpy(&m_auth_trace_buf[m_auth_trace_len], data, szBytes);
    m_auth_trace_len += szBytes;
}

/* Synthesize the anticoll/SELECT/SAK/RATS/ATS frames from a populated tag
 * struct. The wire frames during scan_auto are perfectly determined by the
 * tag descriptor, so we reconstruct them rather than tap rc522.c.
 *
 * For 4-byte UID (cascade=1): CL1 with full UID.
 * For 7-byte UID (cascade=2): CL1 with CT||UID0..2, CL2 with UID3..6.
 * For 10-byte UID (cascade=3): CL1, CL2, CL3.
 *
 * The "first SAK" for an incomplete UID has bit 2 set (cascade flag); we
 * synthesize it as 0x04 (cascade required, no further info), which matches
 * what every real cascading tag returns. Final SAK is the captured tag->sak.
 */
static void auth_trace_emit_anticoll(const picc_14a_tag_t *tag) {
    /* 1. REQA — 7 bits, reader→card */
    uint8_t reqa = PICC_REQIDL;
    auth_trace_store(&reqa, 7, false);

    /* 2. ATQA — 16 bits, card→reader */
    auth_trace_store(tag->atqa, 16, true);

    /* 3. Anticoll/SELECT cycles — one per cascade level */
    const uint8_t cascade_anticoll[3] = { PICC_ANTICOLL1, PICC_ANTICOLL2, PICC_ANTICOLL3 };
    uint8_t uid_pos = 0;
    for (uint8_t cl = 0; cl < tag->cascade; cl++) {
        bool is_last = (cl == (uint8_t)(tag->cascade - 1));

        /* Anticoll request: <SEL> 0x20 — 16 bits, reader→card */
        uint8_t anticoll[2] = { cascade_anticoll[cl], 0x20 };
        auth_trace_store(anticoll, 16, false);

        /* Anticoll response: CT||UID3 + BCC for non-last, or UID4 + BCC for last
         * with full UID inline. 5 bytes / 40 bits, card→reader. */
        uint8_t resp[5];
        if (is_last) {
            /* Last level — 4 bytes of UID at the end of tag->uid */
            memcpy(resp, &tag->uid[uid_pos], 4);
        } else {
            /* Cascading — CT (0x88) + 3 bytes UID */
            resp[0] = 0x88;
            memcpy(&resp[1], &tag->uid[uid_pos], 3);
            uid_pos += 3;
        }
        resp[4] = resp[0] ^ resp[1] ^ resp[2] ^ resp[3];  /* BCC */
        auth_trace_store(resp, 40, true);

        /* SELECT: <SEL> 0x70 + 5-byte CT/UID/BCC + 2-byte CRC = 9 bytes / 72 bits */
        uint8_t sel[9] = { cascade_anticoll[cl], 0x70 };
        memcpy(&sel[2], resp, 5);
        crc_14a_calculate(sel, 7, &sel[7]);
        auth_trace_store(sel, 72, false);

        /* SAK: 1 byte SAK + 2-byte CRC = 24 bits, card→reader.
         * Intermediate cascades: synthesize SAK=0x04 (cascade bit set, generic).
         * Last cascade: real tag->sak. */
        uint8_t sak_frame[3];
        sak_frame[0] = is_last ? tag->sak : 0x04;
        crc_14a_calculate(sak_frame, 1, &sak_frame[1]);
        auth_trace_store(sak_frame, 24, true);
    }

    /* 4. RATS / ATS — only if scan_auto did RATS and the tag responded */
    if (tag->ats_len > 0) {
        /* RATS request: 0xE0 0x40 + 2-byte CRC = 4 bytes / 32 bits, reader→card.
         * 0x40 = FSDI=4 (FSD=48), CID=0 — same as pcd_14a_reader_ats_request(). */
        uint8_t rats[4] = { PICC_RATS, 0x40 };
        crc_14a_calculate(rats, 2, &rats[2]);
        auth_trace_store(rats, 32, false);

        /* ATS response: ats_len bytes (CRC was stripped by rc522 layer) +
         * recomputed 2-byte CRC, card→reader. */
        if ((uint16_t)tag->ats_len + 2 <= 64) {
            uint8_t ats_frame[64];
            memcpy(ats_frame, tag->ats, tag->ats_len);
            crc_14a_calculate(ats_frame, tag->ats_len, &ats_frame[tag->ats_len]);
            auth_trace_store(ats_frame, (tag->ats_len + 2) * 8, true);
        }
    }
}

/* Software-side MIFARE Classic auth tap. Mirrors mf1_toolbox.c::authex() but
 * stores every TX/RX frame into the trace buffer instead of just returning a
 * status. Fixed reader nonce 12345678 is used (same as authex). */
static uint8_t auth_trace_do_auth(picc_14a_tag_t *tag, uint8_t type, uint8_t blockNo, const uint8_t *key6) {
    struct Crypto1State pcs = { 0, 0 };
    static const uint8_t nr[4] = { 0x12, 0x34, 0x56, 0x78 };  /* fixed reader nonce */
    uint8_t  par[8]            = { 0 };
    uint8_t  mf_nr_ar[8]       = { 0 };
    uint8_t  answer[8]         = { 0 };
    uint8_t  parity_resp[8]    = { 0 };
    uint16_t len               = 0;
    uint8_t  status;

    /* AUTH command frame: [type, blockNo, CRC, CRC] — 32 bits, reader→card */
    uint8_t auth_cmd[4] = { type, blockNo };
    crc_14a_calculate(auth_cmd, 2, &auth_cmd[2]);
    auth_trace_store(auth_cmd, 32, false);

    /* Send AUTH, expect 4-byte NT (plaintext on first auth). We use the same
     * primitive as authex's send_cmd() under the non-encrypted path. */
    pcd_14a_reader_bytes_transfer(PCD_TRANSCEIVE, auth_cmd, 4, answer, &len, U8ARR_BIT_LEN(answer));
    if (len != 32) {
        return STATUS_HF_ERR_STAT;  /* no NT — partial trace already in buffer */
    }

    /* Capture NT — 32 bits, card→reader */
    auth_trace_store(answer, 32, true);
    uint32_t nt = ((uint32_t)answer[0] << 24) | ((uint32_t)answer[1] << 16)
                  | ((uint32_t)answer[2] <<  8) |  (uint32_t)answer[3];

    /* Initialise Crypto1 with key (LSB-first, MIFARE convention) */
    uint64_t ui64Key = 0;
    for (int i = 0; i < 6; i++) ui64Key |= (uint64_t)key6[i] << ((5 - i) * 8);
    crypto1_init(&pcs, ui64Key);

    /* First auth: feed (nt ^ uid) as plaintext into the cipher */
    uint32_t uid32 = get_u32_tag_uid(tag);
    crypto1_word(&pcs, nt ^ uid32, 0);

    /* Encrypt NR + parity */
    for (int pos = 0; pos < 4; pos++) {
        mf_nr_ar[pos] = crypto1_byte(&pcs, nr[pos], 0) ^ nr[pos];
        par[pos]      = filter(pcs.odd) ^ oddparity8(nr[pos]);
    }
    /* Compute AR = prng_successor(nt, 32) and encrypt byte-by-byte */
    uint32_t nt_succ = prng_successor(nt, 32);
    for (int pos = 4; pos < 8; pos++) {
        nt_succ = prng_successor(nt_succ, 8);
        mf_nr_ar[pos] = crypto1_byte(&pcs, 0x00, 0) ^ (nt_succ & 0xFF);
        par[pos]      = filter(pcs.odd) ^ oddparity8(nt_succ & 0xFF);
    }

    /* Capture NR||AR (encrypted) — 64 bits, reader→card. Stored before the
     * actual transfer so we still have the trace if the transfer fails. */
    auth_trace_store(mf_nr_ar, 64, false);

    /* Send NR||AR with manual parity, expect 4-byte AT */
    pcd_14a_reader_bits_transfer(mf_nr_ar, 64, par, answer, parity_resp, &len, U8ARR_BIT_LEN(answer));
    if (len != 32) {
        return STATUS_MF_ERR_AUTH;  /* no AT — auth was rejected, partial trace */
    }

    /* Capture AT — 32 bits, card→reader (still encrypted on the wire) */
    auth_trace_store(answer, 32, true);

    /* Verify AT == prng_successor(nt, 64) ^ ks3 */
    uint32_t at_recv = ((uint32_t)answer[0] << 24) | ((uint32_t)answer[1] << 16)
                       | ((uint32_t)answer[2] <<  8) |  (uint32_t)answer[3];
    uint32_t ntpp    = prng_successor(nt_succ, 32) ^ crypto1_word(&pcs, 0, 0);
    status = (ntpp == at_recv) ? STATUS_HF_TAG_OK : STATUS_MF_ERR_AUTH;

    /* Auth state may be left armed in the RC522 — clear it for safety so
     * subsequent reader operations start clean. */
    pcd_14a_reader_mf1_unauth();
    return status;
}

static data_frame_tx_t *cmd_processor_hf14a_auth_trace(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    /* Payload: [type:1][block:1][key:6][timeout_ms_be16:2] = 10 bytes.
     * Backward-compatible short form [type:1][block:1][key:6] = 8 bytes still
     * accepted; default 5000ms. */
    uint32_t timeout_ms = 5000;
    if (length == 10) {
        timeout_ms = ((uint32_t)data[8] << 8) | data[9];
        if (timeout_ms == 0 || timeout_ms > 30000) timeout_ms = 5000;
    } else if (length != 8) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t type    = data[0];
    uint8_t block   = data[1];
    uint8_t *key    = &data[2];
    if (type != PICC_AUTHENT1A && type != PICC_AUTHENT1B) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }

    m_auth_trace_len = 0;

    /* Step 1: poll for a tag in the field until present or timeout.
     * scan_auto internally tries twice with REQA; if no card is present
     * each attempt fails fast (~3-5 ms) and we back off briefly between
     * iterations to keep the WDT happy and avoid hammering the RC522.
     * The antenna is already on (before_hf_reader_run hook) and stays on
     * for the whole polling window — same behaviour as a desktop reader. */
    picc_14a_tag_t tag;
    uint8_t scan_status = STATUS_HF_TAG_NO;
    autotimer *p_at = bsp_obtain_timer(0);
    while (NO_TIMEOUT_1MS(p_at, timeout_ms)) {
        scan_status = pcd_14a_reader_scan_auto(&tag);
        if (scan_status == STATUS_HF_TAG_OK) {
            break;
        }
        /* 50 ms back-off between attempts — yields to USB/BLE main loop
         * and keeps the WDT fed (timeout is 5000 ms). */
        for (int i = 0; i < 50; i++) {
            bsp_delay_ms(1);
            bsp_wdt_feed();
        }
    }
    bsp_return_timer(p_at);

    if (scan_status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, STATUS_HF_TAG_NO, 0, NULL);
    }

    /* Step 2: synthesize the wire frames that scan_auto just produced */
    auth_trace_emit_anticoll(&tag);

    /* Step 3: perform the auth, tapping every TX/RX into the same buffer */
    uint8_t auth_status = auth_trace_do_auth(&tag, type, block, key);

    /* Always return the buffer — even on auth failure, the partial trace is
     * useful for diagnosing why (wrong key vs. wrong block vs. no NT etc.). */
    if (m_auth_trace_len == 0) {
        return data_frame_make(cmd, auth_status, 0, NULL);
    }
    return data_frame_make(cmd, auth_status, m_auth_trace_len, m_auth_trace_buf);
}

#define HF_SNIFF_BUF_SIZE   3800   /* leave room for USB framing */
#define HF_SNIFF_MAX_FRAMES  200

static uint8_t  m_sniff_buf[HF_SNIFF_BUF_SIZE];
static uint16_t m_sniff_buf_len = 0;
static bool     m_sniff_active  = false;
static uint16_t m_sniff_cb_count = 0;   /* debug: total callback invocations */

/* Encode one frame into m_sniff_buf.
 * Format: [szBits_be16][data...]
 * Bit 15 of szBits: 0 = reader→card (RX), 1 = card→reader (TX).
 * Real szBits always < 512 so bit15 is always free in genuine frames.
 * Old parsers (bit15=0 for all frames) still work correctly. */
static void hf14a_sniff_store(const uint8_t *data, uint16_t szBits, bool is_tx) {
    uint16_t szBytes = (szBits + 7) / 8;
    if (m_sniff_buf_len + 2 + szBytes > HF_SNIFF_BUF_SIZE) return;
    uint16_t hdr = szBits | (is_tx ? 0x8000u : 0x0000u);
    m_sniff_buf[m_sniff_buf_len++] = (hdr >> 8) & 0xFF;
    m_sniff_buf[m_sniff_buf_len++] =  hdr        & 0xFF;
    memcpy(&m_sniff_buf[m_sniff_buf_len], data, szBytes);
    m_sniff_buf_len += szBytes;
}

static void hf14a_sniff_frame_cb(const uint8_t *data, uint16_t szBits) {
    m_sniff_cb_count++;   /* count even if buffer full or inactive */
    if (!m_sniff_active) return;
    hf14a_sniff_store(data, szBits, false);  /* reader→card */
}

static void hf14a_sniff_tx_frame_cb(const uint8_t *data, uint16_t szBits) {
    if (!m_sniff_active) return;
    hf14a_sniff_store(data, szBits, true);   /* card→reader */
}

static data_frame_tx_t *cmd_processor_hf14a_sniff(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    /* Optional 2-byte big-endian timeout in ms (default 5000ms) */
    uint32_t timeout_ms = 5000;
    if (length >= 2) {
        timeout_ms = ((uint32_t)data[0] << 8) | data[1];
        if (timeout_ms == 0 || timeout_ms > 30000) timeout_ms = 5000;
    }

    /* Reload active slot data before sniffing.
     * The NFCT anti-collision response is built from m_tag_information which
     * points into the shared tag data buffer. After a slot switch the buffer
     * may still contain the previous slot's UID if the FDS async load has not
     * completed. A forced reload here ensures the correct UID is presented
     * during the sniff session.
     * A short settle delay follows to allow the reload to complete before
     * the first field detection can trigger the anti-collision path. */
    tag_emulation_load_data();
    bsp_delay_ms(100);

    /* Install sniff callback into the already-running tag emulation stack.
     * Do NOT call tag_mode_enter() or sense_switch() here — those reinit
     * NFCT and wipe the anti-collision data, breaking the emulation.
     * The device must already be in emulator mode (hw mode --emulator)
     * with a slot active before running this command. */
    m_sniff_buf_len = 0;
    m_sniff_cb_count = 0;
    m_sniff_active  = true;
    /* passive mode intentionally disabled: CU acts as the card so it must
     * respond normally to the reader (ATQA/UID/SAK). TX sniff captures responses. */
    nfc_tag_14a_set_sniff_cb(hf14a_sniff_frame_cb);
    nfc_tag_14a_set_tx_sniff_cb(hf14a_sniff_tx_frame_cb);

    /* Wait for duration, yielding each ms so USB stack stays alive.
     * Feed watchdog every iteration — WDT timeout is 5000ms and the
     * main loop cannot feed it while we are blocking here. */
    autotimer *p_at = bsp_obtain_timer(0);
    while (NO_TIMEOUT_1MS(p_at, timeout_ms)) {
        bsp_delay_ms(1);
        bsp_wdt_feed();
    }
    bsp_return_timer(p_at);

    /* Remove callback and restore normal sense state */
    m_sniff_active = false;
    /* (passive mode was not enabled, nothing to restore) */
    nfc_tag_14a_clear_sniff_cb();
    nfc_tag_14a_clear_tx_sniff_cb();
    tag_emulation_sense_run();  /* restore slot-based sense state */

    if (m_sniff_buf_len == 0) {
        return data_frame_make(cmd, STATUS_HF_TAG_NO, 0, NULL);
    }
    return data_frame_make(cmd, STATUS_SUCCESS, m_sniff_buf_len, m_sniff_buf);
}

/* ========================================================================
 * HF14A-4 ISO14443-4 T=CL emulation commands (6000-range)
 * ======================================================================== */

static data_frame_tx_t *before_hf14a_4_emulator(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    tag_slot_specific_type_t types;
    tag_emulation_get_specific_types_by_slot(tag_emulation_get_slot(), &types);
    if (types.tag_hf != TAG_TYPE_HF14A_4)
        return data_frame_make(cmd, STATUS_INVALID_SLOT_TYPE, 0, NULL);
    return NULL;
}

/**
 * HF14A-4 APDU recv — non-blocking poll.
 * Returns STATUS_SUCCESS + APDU bytes if one is pending, STATUS_HF_TAG_NO otherwise.
 */
static data_frame_tx_t *cmd_processor_hf14a_4_apdu_recv(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    static uint8_t apdu_buf[NFC_14A_4_MAX_APDU];
    uint16_t apdu_len = 0;
    extern bool nfc_tag_14a_4_get_pending_apdu(uint8_t *buf, uint16_t *length);
    if (nfc_tag_14a_4_get_pending_apdu(apdu_buf, &apdu_len)) {
        return data_frame_make(cmd, STATUS_SUCCESS, apdu_len, apdu_buf);
    }
    return data_frame_make(cmd, STATUS_HF_TAG_NO, 0, NULL);
}

/**
 * HF14A-4 APDU send — push a response for the next WTX-waiting I-block.
 * payload: len_be16(2) + resp_bytes
 */
static data_frame_tx_t *cmd_processor_hf14a_4_apdu_send(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {

    if (length < 2) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    uint16_t resp_len = ((uint16_t)data[0] << 8) | data[1];
    if (resp_len < 2 || resp_len > NFC_14A_4_MAX_APDU || length != 2 + resp_len)
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    if (!nfc_tag_14a_4_set_response(&data[2], resp_len))
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

/**
 * HF14A-4 set anti-collision data (UID/ATQA/SAK/ATS).
 * payload: uid_len(1) uid(n) atqa(2) sak(1) ats_len(1) ats(m)
 */
static data_frame_tx_t *cmd_processor_hf14a_4_set_anti_coll(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length < 1 || !is_valid_uid_size(data[0]) ||
            length < 1 + data[0] + 2 + 1 + 1 ||
            length < 1 + data[0] + 2 + 1 + 1 + data[1 + data[0] + 2 + 1]) {
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    }
    uint8_t ats_len = data[data[0] + 4];
    iso_dep_reader_t validation;
    if (length != 5 + data[0] + ats_len || !(data[data[0] + 3] & 0x20) ||
            !iso_dep_reader_init(&validation, data + data[0] + 5, ats_len))
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    nfc_tag_14a_coll_res_reference_t *info = get_coll_res_data(true);
    if (info == NULL) return data_frame_make(cmd, STATUS_HF_TAG_NO, 0, NULL);
    uint16_t offset = 0;
    *(info->size) = (nfc_tag_14a_uid_size)data[offset];
    offset++;
    memcpy(info->uid,  &data[offset], *(info->size));
    offset += *(info->size);
    memcpy(info->atqa, &data[offset], 2);
    offset += 2;
    info->sak[0]      = data[offset];
    offset++;
    info->ats->length = data[offset];
    offset++;
    memcpy(info->ats->data, &data[offset], info->ats->length);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

/**
 * HF14A-4 add static APDU response pair (pre-load before hw mode -e).
 * payload: cmd_len(1) cmd(n) resp_len(1) resp(m)
 * If cmd_len==0, clears all static responses.
 */
static data_frame_tx_t *cmd_processor_hf14a_4_static_resp(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    if (length == 0) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    uint8_t cmd_len = data[0];
    if (cmd_len == 0 && length == 1) {
        nfc_tag_14a_4_clear_static_responses();
        return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
    }
    if (cmd_len == 0 || cmd_len > NFC_14A_4_MAX_STATIC_CMD_LEN || length < (uint16_t)(1 + cmd_len + 2)) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    /* resp_len is 2 bytes big-endian to support responses > 255 bytes */
    uint16_t resp_len = ((uint16_t)data[1 + cmd_len] << 8) | data[2 + cmd_len];
    if (resp_len < 2 || resp_len > NFC_14A_4_MAX_APDU || length != (uint16_t)(1 + cmd_len + 2 + resp_len)) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    if (!nfc_tag_14a_4_add_static_response(&data[1], cmd_len, &data[3 + cmd_len], resp_len))
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
}

/**
 * HF14A scan keeping field alive after completion — identical to hf14a_scan
 * but registered without after_hf_reader_run so the field stays on and the
 * card remains in T=CL state for subsequent hf14a_raw APDU calls.
 */
static data_frame_tx_t *cmd_processor_hf14a_scan_keep(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    picc_14a_tag_t taginfo;
    status = pcd_14a_reader_scan_auto(&taginfo);
    if (status != STATUS_HF_TAG_OK) {
        return data_frame_make(cmd, status, 0, NULL);
    }
    uint8_t payload[1 + sizeof(taginfo.uid) + sizeof(taginfo.atqa) + sizeof(taginfo.sak) + 1 + 254];
    uint16_t offset = 0;
    payload[offset++] = taginfo.uid_len;
    memcpy(&payload[offset], taginfo.uid, taginfo.uid_len);
    offset += taginfo.uid_len;
    memcpy(&payload[offset], taginfo.atqa, sizeof(taginfo.atqa));
    offset += sizeof(taginfo.atqa);
    payload[offset++] = taginfo.sak;
    payload[offset++] = taginfo.ats_len;
    memcpy(&payload[offset], taginfo.ats, taginfo.ats_len);
    offset += taginfo.ats_len;
    return data_frame_make(cmd, STATUS_HF_TAG_OK, offset, payload);
}


/* Reader adapter: all APDUs in a session share RF power and ISO-DEP state. */
static iso_dep_reader_t m_cpu_reader;
static uint8_t m_cpu_io_status;

static void cpu_close(void) {
    m_cpu_active = false;
    pcd_14a_reader_antenna_off();
    pcd_14a_reader_timeout_set(DEF_COM_TIMEOUT);
}

static uint8_t cpu_open(picc_14a_tag_t *tag) {
    cpu_close();
    bsp_delay_ms(5);
    pcd_14a_reader_reset();
    pcd_14a_reader_antenna_on();
    bsp_delay_ms(8);
    pcd_14a_reader_timeout_set(200);
    uint8_t st = pcd_14a_reader_scan_auto(tag);
    pcd_14a_reader_timeout_set(DEF_COM_TIMEOUT);
    if (st != STATUS_HF_TAG_OK) { cpu_close(); return st; }
    if (!(tag->sak & 0x20) || !iso_dep_reader_init(&m_cpu_reader, tag->ats, tag->ats_len)) {
        cpu_close();
        return STATUS_PAR_ERR;
    }
    m_cpu_active = true;
    return STATUS_HF_TAG_OK;
}

static bool cpu_transceive(void *context, const uint8_t *tx, uint16_t tx_size,
        uint8_t *rx, uint16_t *rx_size, uint16_t timeout_ms) {
    (void)context;
    uint16_t bits = 0;
    pcd_14a_reader_timeout_set(timeout_ms);
    bsp_wdt_feed();
    m_cpu_io_status = pcd_14a_reader_bytes_transfer(PCD_TRANSCEIVE,
        (uint8_t *)tx, (uint8_t)tx_size, rx, &bits, *rx_size * 8);
    pcd_14a_reader_timeout_set(DEF_COM_TIMEOUT);
    if (m_cpu_io_status != STATUS_HF_TAG_OK) return false;
    if (bits & 7) { m_cpu_io_status = STATUS_HF_ERR_STAT; return false; }
    *rx_size = bits / 8;
    return true;
}

static uint8_t cpu_exchange(const uint8_t *apdu, uint16_t size, uint8_t *response,
        uint16_t *response_size) {
    iso_dep_result_t result = iso_dep_reader_exchange(&m_cpu_reader, apdu, size,
        response, response_size, cpu_transceive, NULL);
    if (result == ISO_DEP_OK) return STATUS_HF_TAG_OK;
    cpu_close(); /* An uncertain exchange must never silently restart an authenticated session. */
    return result == ISO_DEP_IO_ERROR ? m_cpu_io_status : STATUS_HF_ERR_STAT;
}

/* 6007: 00=field off, 01=new select/RATS; response uses the usual scan format. */
static data_frame_tx_t *cmd_processor_hf14a_4_session(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    if (length != 1 || data[0] > 1) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    if (data[0] == 0) {
        cpu_close();
        return data_frame_make(cmd, STATUS_SUCCESS, 0, NULL);
    }
    picc_14a_tag_t tag;
    status = cpu_open(&tag);
    if (status != STATUS_HF_TAG_OK) return data_frame_make(cmd, status, 0, NULL);
    uint8_t out[272];
    uint16_t n = 0;
    out[n++] = tag.uid_len;
    memcpy(out + n, tag.uid, tag.uid_len); n += tag.uid_len;
    memcpy(out + n, tag.atqa, 2); n += 2;
    out[n++] = tag.sak; out[n++] = tag.ats_len;
    memcpy(out + n, tag.ats, tag.ats_len); n += tag.ats_len;
    return data_frame_make(cmd, STATUS_HF_TAG_OK, n, out);
}

/* 6009: atomic CFS1 file-image management; chunks are at most 200 bytes. */
static data_frame_tx_t *cmd_processor_hf14a_4_filesystem(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    uint8_t out[200]; uint16_t size = 0;
    bool valid = nfc_tag_14a_4_filesystem_command(data, length, out, &size);
    return data_frame_make(cmd, valid ? STATUS_SUCCESS : STATUS_PAR_ERR, valid ? size : 0, out);
}

/* 6008: empty request returns count; index returns command + response (BE16). */
static data_frame_tx_t *cmd_processor_hf14a_4_static_read(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    uint8_t out[1 + NFC_14A_4_MAX_STATIC_CMD_LEN + 2 + NFC_14A_4_MAX_APDU];
    if (!length) {
        out[0] = nfc_tag_14a_4_static_response_count();
        return data_frame_make(cmd, STATUS_SUCCESS, 1, out);
    }
    if (length != 1) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    const uint8_t *command, *response;
    uint8_t command_len;
    uint16_t response_len;
    if (!nfc_tag_14a_4_get_static_response(data[0], &command, &command_len, &response, &response_len))
        return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    out[0] = command_len;
    memcpy(out + 1, command, command_len);
    out[1 + command_len] = response_len >> 8;
    out[2 + command_len] = response_len & 255;
    memcpy(out + 3 + command_len, response, response_len);
    return data_frame_make(cmd, STATUS_SUCCESS, 3 + command_len + response_len, out);
}

static data_frame_tx_t *cmd_processor_hf14a_4_reader_apdu(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    if (length < 4 || length > ISO_DEP_MAX_APDU) return data_frame_make(cmd, STATUS_PAR_ERR, 0, NULL);
    if (!m_cpu_active) {
        picc_14a_tag_t tag;
        status = cpu_open(&tag);
        if (status != STATUS_HF_TAG_OK) return data_frame_make(cmd, status, 0, NULL);
    }
    static uint8_t response[512];
    uint16_t size = sizeof(response);
    status = cpu_exchange(data, length, response, &size);
    return data_frame_make(cmd, status, status == STATUS_HF_TAG_OK ? size : 0, response);
}

/* Bounded BER-TLV traversal (including constructed FCI/GPO templates). */
static bool cpu_tlv_find(const uint8_t *data, uint16_t size, uint32_t wanted,
        const uint8_t **value, uint16_t *value_size, uint8_t depth) {
    if (depth > 8) return false;
    uint16_t off = 0;
    while (off < size) {
        uint8_t first = data[off++];
        uint32_t tag = first;
        if ((first & 31) == 31) {
            uint8_t b, count = 0;
            do {
                if (off >= size || ++count > 2) return false;
                b = data[off++]; tag = (tag << 8) | b;
            } while (b & 128);
        }
        if (off >= size) return false;
        uint32_t n = data[off++];
        if (n & 128) {
            uint8_t count = n & 127;
            if (!count || count > 2 || count > size - off) return false;
            n = 0;
            while (count--) n = (n << 8) | data[off++];
        }
        if (n > size - off) return false;
        if (tag == wanted) { *value = data + off; *value_size = n; return true; }
        if ((first & 32) && cpu_tlv_find(data + off, n, wanted, value, value_size, depth + 1)) return true;
        off += n;
    }
    return false;
}

static bool cpu_sw_ok(const uint8_t *response, uint16_t size) {
    return size >= 2 && response[size-2] == 0x90 && response[size-1] == 0;
}

/* EMV discovery: PPSE -> first advertised AID -> exact PDOL -> validated AFL.
 * Keep the existing packed response format; never invent PDOL lengths or return
 * a partial transport frame as a successful APDU. */
static data_frame_tx_t *cmd_processor_hf14a_4_emv_scan(uint16_t cmd, uint16_t status,
        uint16_t length, uint8_t *data) {
    static uint8_t out[NETDATA_MAX_DATA_LENGTH], response[512];
    picc_14a_tag_t tag;
    status = cpu_open(&tag);
    if (status != STATUS_HF_TAG_OK) return data_frame_make(cmd, status, 0, NULL);
    uint16_t n = 0;
    out[n++] = tag.uid_len; memcpy(out + n, tag.uid, tag.uid_len); n += tag.uid_len;
    memcpy(out + n, tag.atqa, 2); n += 2;
    out[n++] = tag.sak; out[n++] = tag.ats_len;
    memcpy(out + n, tag.ats, tag.ats_len); n += tag.ats_len;
    uint16_t count_offset = n;
    out[n++] = 0;
    uint16_t size = 0;
#define CPU_SCAN_APDU(ap, len) do { \
        size = sizeof(response); \
        if (cpu_exchange((ap), (len), response, &size) != STATUS_HF_TAG_OK) goto done; \
        if ((uint32_t)n + 3 + (len) + size > sizeof(out) || out[count_offset] == 255) goto done; \
        out[n++] = (len); memcpy(out + n, (ap), (len)); n += (len); \
        out[n++] = size & 255; out[n++] = size >> 8; \
        memcpy(out + n, response, size); n += size; out[count_offset]++; \
    } while (0)
    static const uint8_t ppse[] = {0,0xA4,4,0,14,'2','P','A','Y','.','S','Y','S','.','D','D','F','0','1',0};
    CPU_SCAN_APDU(ppse, sizeof(ppse));
    const uint8_t *value;
    uint16_t value_size;
    if (!cpu_sw_ok(response, size) || !cpu_tlv_find(response, size-2, 0x4F, &value, &value_size, 0) ||
            value_size < 5 || value_size > 16) goto done;
    uint8_t select[22] = {0,0xA4,4,0};
    select[4] = value_size; memcpy(select+5, value, value_size); select[5+value_size] = 0;
    uint8_t select_size = value_size + 6;
    CPU_SCAN_APDU(select, select_size);
    if (!cpu_sw_ok(response, size)) goto done;
    uint8_t dol[128] = {0};
    uint16_t dol_size = 0;
    if (cpu_tlv_find(response, size-2, 0x9F38, &value, &value_size, 0)) {
        uint16_t i = 0;
        while (i < value_size) {
            uint32_t field = value[i++];
            if ((field & 31) == 31) {
                uint8_t b, count = 0;
                do {
                    if (i >= value_size || ++count > 2) goto done;
                    b = value[i++]; field = (field << 8) | b;
                } while (b & 128);
            }
            if (i >= value_size) goto done;
            uint8_t field_size = value[i++];
            if (field_size > sizeof(dol) - dol_size) goto done;
            if (field == 0x9F66 && field_size == 4) dol[dol_size] = 0xA0;
            dol_size += field_size;
        }
    }
    uint8_t gpo[138] = {0x80,0xA8,0,0};
    uint8_t g = 5;
    gpo[g++] = 0x83;
    if (dol_size >= 128) gpo[g++] = 0x81;
    gpo[g++] = dol_size;
    memcpy(gpo+g, dol, dol_size); g += dol_size;
    gpo[4] = g - 5; gpo[g++] = 0;
    CPU_SCAN_APDU(gpo, g);
    if (!cpu_sw_ok(response, size)) goto done;
    if (!cpu_tlv_find(response, size-2, 0x94, &value, &value_size, 0)) {
        if (!cpu_tlv_find(response, size-2, 0x80, &value, &value_size, 0) || value_size < 2) goto done;
        value += 2; value_size -= 2; /* skip AIP in response format 1 */
    }
    if (!value_size || value_size > 128 || (value_size & 3)) goto done;
    uint8_t afl[128]; memcpy(afl, value, value_size);
    for (uint16_t a = 0; a < value_size; a += 4) {
        uint8_t sfi = afl[a] >> 3;
        if ((afl[a] & 7) || !sfi || sfi > 30 || !afl[a+1] || afl[a+1] > afl[a+2] ||
                afl[a+3] > afl[a+2] - afl[a+1] + 1) goto done;
        for (uint16_t record = afl[a+1]; record <= afl[a+2]; record++) {
            uint8_t read_record[] = {0,0xB2,record,(sfi << 3) | 4,0};
            CPU_SCAN_APDU(read_record, sizeof(read_record));
        }
    }
done:
#undef CPU_SCAN_APDU
    cpu_close();
    return data_frame_make(cmd, STATUS_HF_TAG_OK, n, out);
}


static data_frame_tx_t *cmd_processor_hf14a_4_debug_counters(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    uint8_t buf[4];
    nfc_tag_14a_4_get_debug_counters(&buf[0], &buf[1], &buf[2], &buf[3]);
    return data_frame_make(cmd, STATUS_SUCCESS, 4, buf);
}
#endif
static cmd_data_map_t m_data_cmd_map[] = {
    {    DATA_CMD_GET_APP_VERSION,              NULL,                        cmd_processor_get_app_version,               NULL                   },
    {    DATA_CMD_CHANGE_DEVICE_MODE,           NULL,                        cmd_processor_change_device_mode,            NULL                   },
    {    DATA_CMD_GET_DEVICE_MODE,              NULL,                        cmd_processor_get_device_mode,               NULL                   },
    {    DATA_CMD_SET_ACTIVE_SLOT,              NULL,                        cmd_processor_set_active_slot,               NULL                   },
    {    DATA_CMD_SET_SLOT_TAG_TYPE,            NULL,                        cmd_processor_set_slot_tag_type,             NULL                   },
    {    DATA_CMD_SET_SLOT_DATA_DEFAULT,        NULL,                        cmd_processor_set_slot_data_default,         NULL                   },
    {    DATA_CMD_SET_SLOT_ENABLE,              NULL,                        cmd_processor_set_slot_enable,               NULL                   },
    {    DATA_CMD_SET_SLOT_TAG_NICK,            NULL,                        cmd_processor_set_slot_tag_nick,             NULL                   },
    {    DATA_CMD_GET_SLOT_TAG_NICK,            NULL,                        cmd_processor_get_slot_tag_nick,             NULL                   },
    {    DATA_CMD_SLOT_DATA_CONFIG_SAVE,        NULL,                        cmd_processor_slot_data_config_save,         NULL                   },
    {    DATA_CMD_ENTER_BOOTLOADER,             NULL,                        cmd_processor_enter_bootloader,              NULL                   },
    {    DATA_CMD_GET_DEVICE_CHIP_ID,           NULL,                        cmd_processor_get_device_chip_id,            NULL                   },
    {    DATA_CMD_GET_DEVICE_ADDRESS,           NULL,                        cmd_processor_get_device_address,            NULL                   },
    {    DATA_CMD_SAVE_SETTINGS,                NULL,                        cmd_processor_save_settings,                 NULL                   },
    {    DATA_CMD_RESET_SETTINGS,               NULL,                        cmd_processor_reset_settings,                NULL                   },
    {    DATA_CMD_SET_ANIMATION_MODE,           NULL,                        cmd_processor_set_animation_mode,            NULL                   },
    {    DATA_CMD_GET_ANIMATION_MODE,           NULL,                        cmd_processor_get_animation_mode,            NULL                   },
    {    DATA_CMD_GET_GIT_VERSION,              NULL,                        cmd_processor_get_git_version,               NULL                   },
    {    DATA_CMD_GET_ACTIVE_SLOT,              NULL,                        cmd_processor_get_active_slot,               NULL                   },
    {    DATA_CMD_GET_SLOT_INFO,                NULL,                        cmd_processor_get_slot_info,                 NULL                   },
    {    DATA_CMD_WIPE_FDS,                     NULL,                        cmd_processor_wipe_fds,                      NULL                   },
    {    DATA_CMD_DELETE_SLOT_TAG_NICK,         NULL,                        cmd_processor_delete_slot_tag_nick,          NULL                   },
    {    DATA_CMD_GET_ENABLED_SLOTS,            NULL,                        cmd_processor_get_enabled_slots,             NULL                   },
    {    DATA_CMD_DELETE_SLOT_SENSE_TYPE,       NULL,                        cmd_processor_delete_slot_sense_type,        NULL                   },
    {    DATA_CMD_GET_BATTERY_INFO,             NULL,                        cmd_processor_get_battery_info,              NULL                   },
    {    DATA_CMD_GET_BATTERY_INFO_EX,          NULL,                        cmd_processor_get_battery_info_ex,           NULL                   },
    {    DATA_CMD_GET_BUTTON_PRESS_CONFIG,      NULL,                        cmd_processor_get_button_press_config,       NULL                   },
    {    DATA_CMD_SET_BUTTON_PRESS_CONFIG,      NULL,                        cmd_processor_set_button_press_config,       NULL                   },
    {    DATA_CMD_GET_LONG_BUTTON_PRESS_CONFIG, NULL,                        cmd_processor_get_long_button_press_config,  NULL                   },
    {    DATA_CMD_SET_LONG_BUTTON_PRESS_CONFIG, NULL,                        cmd_processor_set_long_button_press_config,  NULL                   },
    {    DATA_CMD_GET_BLE_PAIRING_KEY,          NULL,                        cmd_processor_get_ble_connect_key,           NULL                   },
    {    DATA_CMD_SET_BLE_PAIRING_KEY,          NULL,                        cmd_processor_set_ble_connect_key,           NULL                   },
    {    DATA_CMD_DELETE_ALL_BLE_BONDS,         NULL,                        cmd_processor_delete_all_ble_bonds,          NULL                   },
    {    DATA_CMD_GET_DEVICE_MODEL,             NULL,                        cmd_processor_get_device_model,              NULL                   },
    {    DATA_CMD_GET_DEVICE_SETTINGS,          NULL,                        cmd_processor_get_device_settings,           NULL                   },
    {    DATA_CMD_GET_DEVICE_CAPABILITIES,      NULL,                        cmd_processor_get_device_capabilities,       NULL                   },
    {    DATA_CMD_GET_BLE_PAIRING_ENABLE,       NULL,                        cmd_processor_get_ble_pairing_enable,        NULL                   },
    {    DATA_CMD_SET_BLE_PAIRING_ENABLE,       NULL,                        cmd_processor_set_ble_pairing_enable,        NULL                   },
    {    DATA_CMD_GET_SLEEP_TIMEOUT,            NULL,                        cmd_processor_get_sleep_timeout,             NULL                   },
    {    DATA_CMD_SET_SLEEP_TIMEOUT,            NULL,                        cmd_processor_set_sleep_timeout,             NULL                   },
    {    DATA_CMD_GET_ALL_SLOT_NICKS,           NULL,                        cmd_processor_get_all_slot_nicks,            NULL                   },
    {    DATA_CMD_GET_LONG_PRESS_THRESHOLD,     NULL,                        cmd_processor_get_long_press_threshold,      NULL                   },
    {    DATA_CMD_SET_LONG_PRESS_THRESHOLD,     NULL,                        cmd_processor_set_long_press_threshold,      NULL                   },

#if defined(PROJECT_CHAMELEON_ULTRA)

    {    DATA_CMD_HF14A_SCAN,                   before_hf_reader_run,        cmd_processor_hf14a_scan,                    after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_SUPPORT,           before_hf_reader_run,        cmd_processor_mf1_detect_support,            after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_PRNG,              before_hf_reader_run,        cmd_processor_mf1_detect_prng,               after_hf_reader_run    },
    {    DATA_CMD_MF1_STATIC_NESTED_ACQUIRE,    before_hf_reader_run,        cmd_processor_mf1_static_nested_acquire,     after_hf_reader_run    },
    {    DATA_CMD_MF1_DARKSIDE_ACQUIRE,         before_hf_reader_run,        cmd_processor_mf1_darkside_acquire,          after_hf_reader_run    },
    {    DATA_CMD_MF1_DETECT_NT_DIST,           before_hf_reader_run,        cmd_processor_mf1_detect_nt_dist,            after_hf_reader_run    },
    {    DATA_CMD_MF1_NESTED_ACQUIRE,           before_hf_reader_run,        cmd_processor_mf1_nested_acquire,            after_hf_reader_run    },
    {    DATA_CMD_MF1_ENC_NESTED_ACQUIRE,       before_hf_reader_run,        cmd_processor_mf1_enc_nested_acquire,        after_hf_reader_run    },

    {    DATA_CMD_MF1_AUTH_ONE_KEY_BLOCK,       before_hf_reader_run,        cmd_processor_mf1_auth_one_key_block,        after_hf_reader_run    },
    {    DATA_CMD_MF1_READ_ONE_BLOCK,           before_hf_reader_run,        cmd_processor_mf1_read_one_block,            after_hf_reader_run    },
    {    DATA_CMD_MF1_WRITE_ONE_BLOCK,          before_hf_reader_run,        cmd_processor_mf1_write_one_block,           after_hf_reader_run    },
    {    DATA_CMD_MF0_ULC_AUTH,                 before_hf_reader_run,        cmd_processor_mf0_ulc_auth,                  after_hf_reader_run    },
    {    DATA_CMD_MF0_ULC_READ,                 before_hf_reader_run,        cmd_processor_mf0_ulc_read,                  after_hf_reader_run    },
    {    DATA_CMD_MF0_ULC_WRITE,                before_hf_reader_run,        cmd_processor_mf0_ulc_write,                 after_hf_reader_run    },
    {    DATA_CMD_MF0_ULC_SET_KEY,              before_hf_reader_run,        cmd_processor_mf0_ulc_set_key,               after_hf_reader_run    },
    {    DATA_CMD_HF14A_RAW,                    before_reader_run,           cmd_processor_hf14a_raw,                     NULL                   },
    {    DATA_CMD_MF1_MANIPULATE_VALUE_BLOCK,   before_hf_reader_run,        cmd_processor_mf1_manipulate_value_block,    after_hf_reader_run    },
    {    DATA_CMD_MF1_CHECK_KEYS_OF_SECTORS,    before_hf_reader_run,        cmd_processor_mf1_check_keys_of_sectors,     after_hf_reader_run    },
    {    DATA_CMD_MF1_HARDNESTED_ACQUIRE,       before_hf_reader_run,        cmd_processor_mf1_hardnested_nonces_acquire, after_hf_reader_run    },
    {    DATA_CMD_MF1_CHECK_KEYS_ON_BLOCK,      before_hf_reader_run,        cmd_processor_mf1_check_keys_on_block,       after_hf_reader_run    },

    {    DATA_CMD_EM410X_SCAN,                  before_reader_run,           cmd_processor_em410x_scan,                   NULL                   },
    {    DATA_CMD_EM410X_WRITE_TO_T55XX,        before_reader_run,           cmd_processor_em410x_write_to_t55xx,         NULL                   },
    {    DATA_CMD_EM410X_ELECTRA_WRITE_TO_T55XX, before_reader_run,           cmd_processor_em410x_electra_write_to_t55xx, NULL                   },
    {    DATA_CMD_HIDPROX_SCAN,                 before_reader_run,           cmd_processor_hidprox_scan,                  NULL                   },
    {    DATA_CMD_HIDPROX_WRITE_TO_T55XX,       before_reader_run,           cmd_processor_hidprox_write_to_t55xx,        NULL                   },
    {    DATA_CMD_VIKING_SCAN,                  before_reader_run,           cmd_processor_viking_scan,                   NULL                   },
    {    DATA_CMD_VIKING_WRITE_TO_T55XX,        before_reader_run,           cmd_processor_viking_write_to_t55xx,         NULL                   },
    {    DATA_CMD_IOPROX_SCAN,                  before_reader_run,           cmd_processor_ioprox_scan,                   NULL                   },
    {    DATA_CMD_IOPROX_WRITE_TO_T55XX,        before_reader_run,           cmd_processor_ioprox_write_to_t55xx,         NULL                   },
    {    DATA_CMD_PAC_SCAN,                     before_reader_run,           cmd_processor_pac_scan,                      NULL                   },
    {    DATA_CMD_PAC_WRITE_TO_T55XX,           before_reader_run,           cmd_processor_pac_write_to_t55xx,            NULL                   },
    {    DATA_CMD_JABLOTRON_SCAN,               before_reader_run,           cmd_processor_jablotron_scan,                NULL                   },
    {    DATA_CMD_JABLOTRON_WRITE_TO_T55XX,     before_reader_run,           cmd_processor_jablotron_write_to_t55xx,      NULL                   },
    {    DATA_CMD_PYRAMID_SCAN,                 before_reader_run,           cmd_processor_pyramid_scan,                  NULL                   },
    {    DATA_CMD_IDTECK_WRITE_TO_T55XX,        before_reader_run,           cmd_processor_idteck_write_to_t55xx,         NULL                   },
    {    DATA_CMD_LF_T55XX_WRITE,               before_reader_run,           cmd_processor_lf_t55xx_write,                NULL                   },
    {    DATA_CMD_ADC_GENERIC_READ,             before_reader_run,           cmd_processor_generic_read,                  NULL                   },

    {    DATA_CMD_HF14A_SET_FIELD_ON,           before_reader_run,           cmd_processor_hf14a_set_field_on,            NULL                   },
    {    DATA_CMD_HF14A_SET_FIELD_OFF,          before_reader_run,           cmd_processor_hf14a_set_field_off,           NULL                   },

    {    DATA_CMD_HF14A_GET_CONFIG,             NULL,                        cmd_processor_hf14a_get_config,              NULL                   },
    {    DATA_CMD_HF14A_SET_CONFIG,             NULL,                        cmd_processor_hf14a_set_config,              NULL                   },

    {    DATA_CMD_IOPROX_DECODE_RAW,            NULL,                        cmd_processor_ioprox_decode_raw,             NULL                   },
    {    DATA_CMD_IOPROX_COMPOSE_ID,            NULL,                        cmd_processor_ioprox_compose_id,             NULL                   },
    {    DATA_CMD_EM4X05_SCAN,                  before_reader_run,           cmd_processor_em4x05_scan,                   NULL                   },
    {    DATA_CMD_LF_SNIFF,                     before_reader_run,           cmd_processor_lf_sniff,                      NULL                   },
    {    DATA_CMD_HF14A_SNIFF,                  NULL,                        cmd_processor_hf14a_sniff,                   NULL                   },
    {    DATA_CMD_HF14A_AUTH_TRACE,             before_hf_reader_run,        cmd_processor_hf14a_auth_trace,              after_hf_reader_run    },

#endif

    {    DATA_CMD_HF14A_GET_ANTI_COLL_DATA,     NULL,                        cmd_processor_hf14a_get_anti_coll_data,      NULL                   },
    {    DATA_CMD_HF14A_SET_ANTI_COLL_DATA,     NULL,                        cmd_processor_hf14a_set_anti_coll_data,      NULL                   },

    {    DATA_CMD_MF1_WRITE_EMU_BLOCK_DATA,     NULL,                        cmd_processor_mf1_write_emu_block_data,      NULL                   },
    {    DATA_CMD_MF1_SET_DETECTION_ENABLE,     NULL,                        cmd_processor_mf1_set_detection_enable,      NULL                   },
    {    DATA_CMD_MF1_GET_DETECTION_COUNT,      NULL,                        cmd_processor_mf1_get_detection_count,       NULL                   },
    {    DATA_CMD_MF1_GET_DETECTION_LOG,        NULL,                        cmd_processor_mf1_get_detection_log,         NULL                   },
    {    DATA_CMD_MF1_GET_DETECTION_ENABLE,     NULL,                        cmd_processor_mf1_get_detection_enable,      NULL                   },
    {    DATA_CMD_MF1_READ_EMU_BLOCK_DATA,      NULL,                        cmd_processor_mf1_read_emu_block_data,       NULL                   },
    {    DATA_CMD_MF1_GET_EMULATOR_CONFIG,      NULL,                        cmd_processor_mf1_get_emulator_config,       NULL                   },
    {    DATA_CMD_MF1_GET_PRNG_TYPE,            NULL,                        cmd_processor_mf1_get_prng_type,             NULL                   },
    {    DATA_CMD_MF1_SET_PRNG_TYPE,            NULL,                        cmd_processor_mf1_set_prng_type,             NULL                   },
    {    DATA_CMD_MF1_GET_GEN1A_MODE,           NULL,                        cmd_processor_mf1_get_gen1a_mode,            NULL                   },
    {    DATA_CMD_MF1_SET_GEN1A_MODE,           NULL,                        cmd_processor_mf1_set_gen1a_mode,            NULL                   },
    {    DATA_CMD_MF1_GET_GEN2_MODE,            NULL,                        cmd_processor_mf1_get_gen2_mode,             NULL                   },
    {    DATA_CMD_MF1_SET_GEN2_MODE,            NULL,                        cmd_processor_mf1_set_gen2_mode,             NULL                   },
    {    DATA_CMD_MF1_GET_BLOCK_ANTI_COLL_MODE, NULL,                        cmd_processor_mf1_get_block_anti_coll_mode,  NULL                   },
    {    DATA_CMD_MF1_SET_BLOCK_ANTI_COLL_MODE, NULL,                        cmd_processor_mf1_set_block_anti_coll_mode,  NULL                   },
    {    DATA_CMD_MF1_GET_WRITE_MODE,           NULL,                        cmd_processor_mf1_get_write_mode,            NULL                   },
    {    DATA_CMD_MF1_SET_WRITE_MODE,           NULL,                        cmd_processor_mf1_set_write_mode,            NULL                   },
    {    DATA_CMD_MF1_GET_FIELD_OFF_DO_RESET,   NULL,                        cmd_processor_mf1_get_field_off_do_reset,    NULL                   },
    {    DATA_CMD_MF1_SET_FIELD_OFF_DO_RESET,   NULL,                        cmd_processor_mf1_set_field_off_do_reset,    NULL                   },

    {    DATA_CMD_MF0_NTAG_GET_UID_MAGIC_MODE,    NULL,                      cmd_processor_mf0_ntag_get_uid_mode,         NULL                   },
    {    DATA_CMD_MF0_NTAG_SET_UID_MAGIC_MODE,    NULL,                      cmd_processor_mf0_ntag_set_uid_mode,         NULL                   },
    {    DATA_CMD_MF0_NTAG_READ_EMU_PAGE_DATA,    NULL,                      cmd_processor_mf0_ntag_read_emu_page_data,   NULL                   },
    {    DATA_CMD_MF0_NTAG_WRITE_EMU_PAGE_DATA,   NULL,                      cmd_processor_mf0_ntag_write_emu_page_data,  NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_VERSION_DATA,      NULL,                      cmd_processor_mf0_ntag_get_version_data,     NULL                   },
    {    DATA_CMD_MF0_NTAG_SET_VERSION_DATA,      NULL,                      cmd_processor_mf0_ntag_set_version_data,     NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_SIGNATURE_DATA,    NULL,                      cmd_processor_mf0_ntag_get_signature_data,   NULL                   },
    {    DATA_CMD_MF0_NTAG_SET_SIGNATURE_DATA,    NULL,                      cmd_processor_mf0_ntag_set_signature_data,   NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_COUNTER_DATA,      NULL,                      cmd_processor_mf0_ntag_get_counter_data,     NULL                   },
    {    DATA_CMD_MF0_NTAG_SET_COUNTER_DATA,      NULL,                      cmd_processor_mf0_ntag_set_counter_data,     NULL                   },
    {    DATA_CMD_MF0_NTAG_RESET_AUTH_CNT,        NULL,                      cmd_processor_mf0_ntag_reset_auth_cnt,       NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_PAGE_COUNT,        NULL,                      cmd_processor_mf0_ntag_get_emu_page_count,   NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_WRITE_MODE,        NULL,                      cmd_processor_mf0_ntag_get_write_mode,       NULL                   },
    {    DATA_CMD_MF0_NTAG_SET_WRITE_MODE,        NULL,                      cmd_processor_mf0_ntag_set_write_mode,       NULL                   },
    {    DATA_CMD_MF0_NTAG_SET_DETECTION_ENABLE,  NULL,                      cmd_processor_mf0_ntag_set_detection_enable, NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_DETECTION_COUNT,   NULL,                      cmd_processor_mf0_ntag_get_detection_count,  NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_DETECTION_LOG,     NULL,                      cmd_processor_mf0_ntag_get_detection_log,    NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_DETECTION_ENABLE,  NULL,                      cmd_processor_mf0_ntag_get_detection_enable, NULL                   },
    {    DATA_CMD_MF0_NTAG_GET_EMULATOR_CONFIG,   NULL,                      cmd_processor_mf0_get_emulator_config,       NULL                   },

    {    DATA_CMD_EM410X_SET_EMU_ID,              NULL,                      cmd_processor_em410x_set_emu_id,             NULL                   },
    {    DATA_CMD_EM410X_GET_EMU_ID,              NULL,                      cmd_processor_em410x_get_emu_id,             NULL                   },
    {    DATA_CMD_HIDPROX_SET_EMU_ID,             NULL,                      cmd_processor_hidprox_set_emu_id,            NULL                   },
    {    DATA_CMD_HIDPROX_GET_EMU_ID,             NULL,                      cmd_processor_hidprox_get_emu_id,            NULL                   },
    {    DATA_CMD_IOPROX_SET_EMU_ID,              NULL,                      cmd_processor_ioprox_set_emu_id,             NULL                   },
    {    DATA_CMD_IOPROX_GET_EMU_ID,              NULL,                      cmd_processor_ioprox_get_emu_id,             NULL                   },
    {    DATA_CMD_VIKING_SET_EMU_ID,              NULL,                      cmd_processor_viking_set_emu_id,             NULL                   },
    {    DATA_CMD_VIKING_GET_EMU_ID,              NULL,                      cmd_processor_viking_get_emu_id,             NULL                   },
    {    DATA_CMD_PAC_SET_EMU_ID,                 NULL,                      cmd_processor_pac_set_emu_id,                NULL                   },
    {    DATA_CMD_PAC_GET_EMU_ID,                 NULL,                      cmd_processor_pac_get_emu_id,                NULL                   },
    {    DATA_CMD_JABLOTRON_SET_EMU_ID,           NULL,                      cmd_processor_jablotron_set_emu_id,          NULL                   },
    {    DATA_CMD_JABLOTRON_GET_EMU_ID,           NULL,                      cmd_processor_jablotron_get_emu_id,          NULL                   },
    {    DATA_CMD_IDTECK_SET_EMU_ID,              NULL,                      cmd_processor_idteck_set_emu_id,             NULL                   },
    {    DATA_CMD_IDTECK_GET_EMU_ID,              NULL,                      cmd_processor_idteck_get_emu_id,             NULL                   },

    {    DATA_CMD_SEOS_READ_EMU_DATA,             NULL,                      cmd_processor_seos_read_emu_data,            NULL                   },
    {    DATA_CMD_SEOS_WRITE_EMU_DATA,            NULL,                      cmd_processor_seos_write_emu_data,           NULL                   },
    {    DATA_CMD_SEOS_WRITE_EMU_KEYS,            NULL,                      cmd_processor_seos_write_emu_keys,           NULL                   },

    /* ISO14443-4 T=CL emulation */
#if defined(PROJECT_CHAMELEON_ULTRA)
    /* ISO14443-4 T=CL emulation */
    {    DATA_CMD_HF14A_4_APDU_RECV,              before_hf14a_4_emulator,                        cmd_processor_hf14a_4_apdu_recv,             NULL                   },
    {    DATA_CMD_HF14A_4_APDU_SEND,              before_hf14a_4_emulator,                        cmd_processor_hf14a_4_apdu_send,             NULL                   },
    {    DATA_CMD_HF14A_4_SET_ANTI_COLL,          before_hf14a_4_emulator,                        cmd_processor_hf14a_4_set_anti_coll,         NULL                   },
    {    DATA_CMD_HF14A_4_STATIC_RESP,            before_hf14a_4_emulator,                        cmd_processor_hf14a_4_static_resp,           NULL                   },
    {    DATA_CMD_HF14A_4_READER_APDU,            before_reader_run,        cmd_processor_hf14a_4_reader_apdu,           NULL                   },
    {    DATA_CMD_HF14A_4_SESSION,                before_reader_run,           cmd_processor_hf14a_4_session,               NULL                   },
    {    DATA_CMD_HF14A_4_FILESYSTEM,             before_hf14a_4_emulator,   cmd_processor_hf14a_4_filesystem,            NULL                   },
    {    DATA_CMD_HF14A_4_STATIC_READ,            before_hf14a_4_emulator,                        cmd_processor_hf14a_4_static_read,           NULL                   },
    {    DATA_CMD_HF14A_4_EMV_SCAN,               before_hf_reader_run,        cmd_processor_hf14a_4_emv_scan,              NULL                   },
    {    6010,                                     NULL,                        cmd_processor_hf14a_4_debug_counters,        NULL                   },
    /* HF14A scan keeping field alive */
    {    DATA_CMD_HF14A_SCAN_KEEP,                before_hf_reader_run,        cmd_processor_hf14a_scan_keep,               NULL                   },
#endif
};
data_frame_tx_t *cmd_processor_get_device_capabilities(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    size_t count = ARRAYLEN(m_data_cmd_map);
    uint16_t commands[count];
    memset(commands, 0, count * sizeof(uint16_t));

    for (size_t i = 0; i < count; i++) {
        commands[i] = U16HTONS(m_data_cmd_map[i].cmd);
    }

    return data_frame_make(cmd, STATUS_SUCCESS, count * sizeof(uint16_t), (uint8_t *)commands);
}

/**
 * @brief Auto select source to response
 *
 * @param resp data
 */
static void auto_response_data(data_frame_tx_t *resp) {
    // TODO Please select the reply source automatically according to the message source,
    //  and do not reply by checking the validity of the link layer by layer
    if (is_usb_working()) {
        usb_cdc_write(resp->buffer, resp->length);
    } else if (is_nus_working()) {
        nus_data_response(resp->buffer, resp->length);
    } else {
        NRF_LOG_ERROR("No connection valid found at response client.");
    }
}


/**@brief Function to process data frame(cmd)
 */
void on_data_frame_received(uint16_t cmd, uint16_t status, uint16_t length, uint8_t *data) {
    data_frame_tx_t *response = NULL;
    bool is_cmd_support = false;
    for (int i = 0; i < ARRAY_SIZE(m_data_cmd_map); i++) {
        if (m_data_cmd_map[i].cmd == cmd) {
            is_cmd_support = true;
            if (m_data_cmd_map[i].cmd_before != NULL) {
                data_frame_tx_t *before_resp = m_data_cmd_map[i].cmd_before(cmd, status, length, data);
                if (before_resp != NULL) {
                    // some problem found before run cmd.
                    response = before_resp;
                    break;
                }
            }
            if (m_data_cmd_map[i].cmd_processor != NULL) response = m_data_cmd_map[i].cmd_processor(cmd, status, length, data);
            if (m_data_cmd_map[i].cmd_after != NULL) {
                data_frame_tx_t *after_resp = m_data_cmd_map[i].cmd_after(cmd, status, length, data);
                if (after_resp != NULL) {
                    // some problem found after run cmd.
                    response = after_resp;
                    break;
                }
            }
            break;
        }
    }
    if (is_cmd_support) {
        // check and response
        if (response != NULL) {
            auto_response_data(response);
        }
    } else {
        // response cmd unsupported.
        response = data_frame_make(cmd, STATUS_INVALID_CMD, 0, NULL);
        auto_response_data(response);
        NRF_LOG_INFO("Data frame cmd invalid: %d,", cmd);
    }
}
