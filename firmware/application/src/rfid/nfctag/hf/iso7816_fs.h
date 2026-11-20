/* Stateful ISO 7816-4 file application. No platform, RF or flash dependencies. */
#ifndef ISO7816_FS_H
#define ISO7816_FS_H
#include <stdbool.h>
#include <stdint.h>

#define ISO7816_FS_MAX_IMAGE 3252u
#define ISO7816_FS_MAX_NODES 16u
#define ISO7816_FS_MAX_FCI 240u
#define ISO7816_FS_NONE 0xFFu
#define ISO7816_FS_DF 0u
#define ISO7816_FS_BINARY 1u
#define ISO7816_FS_RECORDS 2u
#define ISO7816_FS_READ 1u
#define ISO7816_FS_WRITE 2u
#define ISO7816_FS_READ_PIN 4u
#define ISO7816_FS_WRITE_PIN 8u
#define ISO7816_FS_READ_KEY 16u
#define ISO7816_FS_WRITE_KEY 32u
#define ISO7816_FS_SECURITY_SIZE 44u
#define ISO7816_FS_VERSION_SM4 3u
#define ISO7816_FS_AUTH_CAPS 7u /* bit 0: PIN, bit 1: DES/2-key 3DES, bit 2: SM4 */
#define ISO7816_FS_SM4_PADDED8 1u
#define ISO7816_FS_SM4_RAW16 2u

/* CFS1 / version / count / total-length-BE16, then parent,type,FID-BE16,
 * SFI,access,AID-length,FCI-length-BE16,data-length-BE16,record-length-BE16,
 * followed by AID, custom SELECT FCI (without SW), and file contents.
 * Parents precede children. Node zero is MF 3F00, parent FF, type DF. */
typedef struct {
    uint8_t parent, type, sfi, access, aid_length;
    uint16_t fid, aid_offset, fci_offset, fci_length;
    uint16_t data_offset, data_length, record_length;
} iso7816_fs_node_t;

typedef struct {
    uint8_t *image;
    uint16_t length;
    uint8_t count, selected_df, selected_ef, current_record;
    bool dirty;
    bool pin_authenticated, key_authenticated, challenge_valid;
    uint16_t security_offset;
    uint8_t challenge[16];
    bool (*random)(uint8_t *out, uint8_t length);
    iso7816_fs_node_t nodes[ISO7816_FS_MAX_NODES];
    uint8_t pending[ISO7816_FS_MAX_FCI];
    uint16_t pending_length, pending_offset;
} iso7816_fs_t;

bool iso7816_fs_open(iso7816_fs_t *fs, uint8_t *image, uint16_t length);
bool iso7816_fs_validate(const uint8_t *image, uint16_t length);
void iso7816_fs_reset(iso7816_fs_t *fs);
uint16_t iso7816_fs_exchange(iso7816_fs_t *fs, const uint8_t *command,
    uint16_t length, uint8_t *response, uint16_t capacity);
#endif
