// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The ABI between NS and the partition:
// the opcodes, the records they carry and the codes they return.
// All integers are little endian.

#pragma once

#include <stdint.h>

// Opcodes of the TFM_BITCOIN service.
// Setup, unlock and close are panel only, so a mnemonic or a PIN never passes through NS,
// and NS cannot throw away a temporary wallet.
#define TFM_BITCOIN_STATUS 1001          // out0 u32 BITCOIN_STATUS_*, out1 u32 attempts left
#define TFM_BITCOIN_GET_XPUB 1002        // in0 path, out0 xpub
#define TFM_BITCOIN_GET_FINGERPRINT 1003 // out0 the master fingerprint
#define TFM_BITCOIN_TX_BEGIN 1004        // in0 begin record
#define TFM_BITCOIN_TX_OUTPUT 1005       // in0 output record, in1 change path or empty
#define TFM_BITCOIN_TX_INPUT 1006        // in0 input record, in1 path or empty, in2 prev tx
#define TFM_BITCOIN_TX_CONFIRM 1007      // no vecs, the review opens
#define TFM_BITCOIN_TX_POLL 1008         // out0 u32 BITCOIN_TX_*
#define TFM_BITCOIN_TX_SIGN_INPUT 1009   // in0 u32 index, in1 path, out0 DER signature, out1 pubkey
#define TFM_BITCOIN_TX_ABORT 1010        // no vecs
#define TFM_BITCOIN_FILES_SET 1011       // in0 names, in1 card, in2 fw state, in3 installs
#define TFM_BITCOIN_FILES_POLL 1012      // out0 name to sign or empty, out1 u32 BITCOIN_JOB_*
#define TFM_BITCOIN_FILES_RESULT 1013    // in0 u32 BITCOIN_FILES_* or BITCOIN_INSTALL_*

// Opcodes of the TFM_BITCOIN_TEST service. Only a dev build has it.
#define TFM_BITCOIN_TEST_RUN 2001            // no vecs, runs the self-tests
#define TFM_BITCOIN_TEST_TX_APPROVE 2002     // no vecs, stands in for the approve press
#define TFM_BITCOIN_TEST_OPEN_EPHEMERAL 2003 // in0 mnemonic, in1 passphrase

// Sizes. A string size includes the NUL.
#define BITCOIN_PASSPHRASE_MAX_SIZE 128
#define BITCOIN_MNEMONIC_MAX_SIZE 256
#define BITCOIN_PATH_MAX_SIZE 128
#define BITCOIN_XPUB_MAX_SIZE 113
#define BITCOIN_ADDRESS_MAX_SIZE 91
#define BITCOIN_SIGNATURE_MAX_SIZE 72
#define BITCOIN_PUBKEY_SIZE 33
#define BITCOIN_FINGERPRINT_SIZE 4
#define BITCOIN_TXID_SIZE 32

// Wallet state, from TFM_BITCOIN_STATUS.
#define BITCOIN_STATUS_NONE 0
#define BITCOIN_STATUS_LOCKED 1
#define BITCOIN_STATUS_SETUP 2 // a create or recover on the panel, not confirmed yet
#define BITCOIN_STATUS_OPEN 3
// A stored record this app cannot read, maybe a wallet in a newer format.
// It is never overwritten.
#define BITCOIN_STATUS_UNREADABLE 4

// The attempts left in every state but LOCKED.
// It is not 0, so a caller that ignores the state cannot misread it:
// "nothing to unlock" must not look like "one more wrong PIN wipes the wallet".
#define BITCOIN_ATTEMPTS_NA 0xFFFFFFFF

// Outvecs of a fixed size. sizeof() is the transferred length, there is no padding.
typedef struct {
    uint8_t bytes[BITCOIN_FINGERPRINT_SIZE];
} bitcoin_fingerprint_t;

typedef struct {
    uint8_t bytes[BITCOIN_PUBKEY_SIZE];
} bitcoin_pubkey_t;

// Transactions. Only SIGHASH_ALL is signed.
// The partition shows at most BITCOIN_TX_MAX_SHOWN_OUTPUTS external outputs,
// and confirm refuses a tx with more.
#define BITCOIN_SIGHASH_ALL 0x01
#define BITCOIN_TX_MAX_INPUTS 16
#define BITCOIN_TX_MAX_SHOWN_OUTPUTS 8
#define BITCOIN_TX_SCRIPT_MAX_SIZE 34

// The answer of TFM_BITCOIN_TX_POLL. A rejected tx is dropped, so the poll fails.
#define BITCOIN_TX_PENDING 0
#define BITCOIN_TX_APPROVED 1

// The tx records. tx_records.c writes and reads them field by field, they are not C structs.

// version u32 | locktime u32 | num_inputs u32 | num_outputs u32 | sighash_type u32
#define BITCOIN_TX_BEGIN_REC_SIZE 20
typedef struct {
    uint8_t bytes[BITCOIN_TX_BEGIN_REC_SIZE];
} bitcoin_tx_begin_rec_t;

// amount u64 | script_len u8 | script[BITCOIN_TX_SCRIPT_MAX_SIZE]
#define BITCOIN_TX_OUTPUT_REC_SIZE (8 + 1 + BITCOIN_TX_SCRIPT_MAX_SIZE)
typedef struct {
    uint8_t bytes[BITCOIN_TX_OUTPUT_REC_SIZE];
} bitcoin_tx_output_rec_t;

// txid[32] | vout u32 | sequence u32.
// There is no amount: the partition reads it from the prev tx in in2.
#define BITCOIN_TX_INPUT_REC_SIZE (BITCOIN_TXID_SIZE + 4 + 4)
typedef struct {
    uint8_t bytes[BITCOIN_TX_INPUT_REC_SIZE];
} bitcoin_tx_input_rec_t;

// The rows of the review. TOTAL is the amount that leaves the wallet,
// OUTPUT is one external destination, FEE is what the miners take.
// Only the partition uses them.
#define BITCOIN_TX_SUMMARY_KIND_TOTAL 0
#define BITCOIN_TX_SUMMARY_KIND_OUTPUT 1
#define BITCOIN_TX_SUMMARY_KIND_FEE 2

// The card.
// NS owns it and sends the whole file list with TFM_BITCOIN_FILES_SET each time it changes:
// the PSBTs at the root, one NUL-padded BITCOIN_FILE_NAME_MAX_SIZE slot each.
// The partition only shows the list.
#define BITCOIN_FILES_MAX 32
#define BITCOIN_FILE_NAME_MAX_SIZE 32

// The largest PSBT, after base64 decoding. A file is binary (BIP174) or base64 text.
// A prev tx comes from inside a PSBT, so it is never larger.
#define BITCOIN_PSBT_FILE_MAX 4096
#define BITCOIN_PREV_TX_MAX_SIZE BITCOIN_PSBT_FILE_MAX

// The card state in TFM_BITCOIN_FILES_SET in1.
#define BITCOIN_CARD_NONE 0
#define BITCOIN_CARD_MOUNTED 1
#define BITCOIN_CARD_ERROR 2 // a card in the slot that did not start or did not mount

// The jobs. The user starts one on the panel, and NS takes it with TFM_BITCOIN_FILES_POLL:
// - SIGN: out0 is the file. NS signs it and writes <name>-signed.psbt.
// - EXPORT: NS writes the watch-only descriptor of the open wallet.
// - INSTALL_BOOT, INSTALL_APP: NS writes the file to slot1 and ends with BITCOIN_INSTALL_STAGED.
//   The partition then hashes slot1 itself and shows it.
// - INSTALL_COMMIT: after the install press, NS asks MCUboot to install slot1,
//   ends with BITCOIN_INSTALL_OK and restarts.
#define BITCOIN_JOB_SIGN 0
#define BITCOIN_JOB_INSTALL_BOOT 1
#define BITCOIN_JOB_INSTALL_APP 2
#define BITCOIN_JOB_EXPORT 3
#define BITCOIN_JOB_INSTALL_COMMIT 4

// How a sign or export job ended, in TFM_BITCOIN_FILES_RESULT.
// NS sends the codes below REJECTED. The partition sets REJECTED when the user cancels the review.
#define BITCOIN_FILES_OK 0
#define BITCOIN_FILES_NO_CARD 1
#define BITCOIN_FILES_READ_FAILED 2
#define BITCOIN_FILES_TOO_BIG 3
#define BITCOIN_FILES_BAD_PSBT 4
#define BITCOIN_FILES_NOT_SIGNED 5
#define BITCOIN_FILES_WRITE_FAILED 6
#define BITCOIN_FILES_REJECTED 7

// The firmware state in TFM_BITCOIN_FILES_SET in2, BITCOIN_FW_STATE_SIZE bytes:
// the b0 version of the running bootloader u32 (0 when unknown), then a u8 BITCOIN_FW_*.
// NS reads it from MCUboot's trailers.
#define BITCOIN_FW_STATE_SIZE 5
#define BITCOIN_FW_OK 0
#define BITCOIN_FW_FAILED 1     // the last install failed, and the old app was swapped back
#define BITCOIN_FW_CONFIRMING 2 // a new app runs as a test until NS confirms it

// The install files on the card, in TFM_BITCOIN_FILES_SET in3.
// 0 to BITCOIN_INSTALLS_MAX records, at most one per kind, BITCOIN_INSTALL_RECORD_SIZE bytes each:
// kind u8 | state u8 | major u8 | minor u8 | revision u16 | boot version u32 | app hash[32]
// The hash is the SHA-256 of the whole app file, zero for a bootloader. All of it is an NS claim.
// The partition hashes slot1 itself before the install press, MCUboot installs only that hash,
// and MCUboot and b0 check the signature.
#define BITCOIN_INSTALL_BOOT 1
#define BITCOIN_INSTALL_APP 2
#define BITCOIN_INSTALL_STATE_OK 0
#define BITCOIN_INSTALL_STATE_INVALID 1    // not a signed image for its slot
#define BITCOIN_INSTALL_STATE_INCOMPLETE 2 // a bootloader without both the s0 and the s1 file
#define BITCOIN_INSTALL_HASH_SIZE 32
#define BITCOIN_INSTALL_RECORD_SIZE (10 + BITCOIN_INSTALL_HASH_SIZE)
#define BITCOIN_INSTALLS_MAX 2

// How an install or commit job ended, in TFM_BITCOIN_FILES_RESULT.
// An install job ends with STAGED and a commit job with OK. Any other code is a failure.
#define BITCOIN_INSTALL_OK 0
#define BITCOIN_INSTALL_NO_CARD 1
#define BITCOIN_INSTALL_READ_FAILED 2
#define BITCOIN_INSTALL_BAD_FILE 3
#define BITCOIN_INSTALL_NOT_NEWER 4 // a bootloader not above the running one
#define BITCOIN_INSTALL_WRITE_FAILED 5
#define BITCOIN_INSTALL_PENDING 6 // the running app is not confirmed yet
#define BITCOIN_INSTALL_CHANGED 7 // the file is not the one the panel showed
#define BITCOIN_INSTALL_STAGED 8  // in slot1, MCUboot not asked yet
#define BITCOIN_INSTALL_CODES 9   // the number of codes
