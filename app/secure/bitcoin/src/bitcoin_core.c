// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_core.h"
#include "bip32.h"
#include "bip39.h"
#include "key_storage.h"
#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "script.h"
#include "secp256k1_context.h"
#include "shared/bitcoin_service_defs.h"
#include "shared/mem_util.h"
#include "shared/tx_records.h"
#include "tfm_log.h"
#include "tx_session.h"
#include <psa/service.h>
#include <secp256k1.h>
#include <secp256k1_preallocated.h>
#include <string.h>

#define BITCOIN_SIGHASH_SIZE 32

typedef enum {
    WALLET_SESSION_NONE,
    WALLET_SESSION_SETUP,
    WALLET_SESSION_ACTIVE,
} wallet_session_state_t;

typedef struct {
    uint8_t entropy[BITCOIN_ENTROPY_MAX_SIZE];
    size_t entropy_size;
} wallet_setup_context_t;

typedef struct {
    bip32_extended_privkey_t master_key;
    // Opened from the panel with no PS and no PIN.
    // It lives in `data`, so clear_session_data() also clears it.
    bool temporary;
} wallet_opened_context_t;

typedef union {
    wallet_setup_context_t setup;
    wallet_opened_context_t opened;
} wallet_session_union_t;

struct wallet_session {
    // Set in the static initializers below and never written again:
    // the storage and the approval source belong to the instance, not to runtime state.
    // This is the only copy of the approval source. The approve calls below check it.
    const key_storage_uids_t *uids;
    approval_source_t approval;

    wallet_session_state_t state;
    wallet_session_union_t data;
    tx_session_t tx;
};

static struct wallet_session s_wallet = {
    .uids = &key_storage_uids_production,
    .approval = APPROVAL_BUTTON,
};

wallet_session_t *bitcoin_core_session_production(void)
{
    return &s_wallet;
}

#ifdef SIGU_SELFTEST
static struct wallet_session s_test_wallet = {
    .uids = &key_storage_uids_test,
    .approval = APPROVAL_PROGRAMMATIC,
};

wallet_session_t *bitcoin_core_session_test(void)
{
    return &s_test_wallet;
}
#endif

void bitcoin_core_init(void)
{
    // Tripwire against a refactor that crosses the wires.
    // With programmatic approval or the test storage on the production wallet,
    // the confirmation gate would be gone and everything would still look fine.
    if (s_wallet.approval != APPROVAL_BUTTON || s_wallet.uids != &key_storage_uids_production) {
        psa_panic();
    }
#ifdef SIGU_SELFTEST
    if (s_test_wallet.approval != APPROVAL_PROGRAMMATIC ||
        s_test_wallet.uids != &key_storage_uids_test) {
        psa_panic();
    }
    if (s_wallet.uids->data == s_test_wallet.uids->data) {
        psa_panic();
    }
#endif
}

static void clear_session_data(wallet_session_t *w)
{
    mem_zeroize(&w->data, sizeof(w->data));
    w->state = WALLET_SESSION_NONE;
    // A signing session only means something while the wallet that authorized it is open,
    // so closing the wallet drops it too.
    tx_session_reset(&w->tx);
}

psa_status_t bitcoin_core_status(wallet_session_t *w, uint32_t *state_out, uint32_t *attempts_out)
{
    if (!w || !state_out || !attempts_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *attempts_out = BITCOIN_ATTEMPTS_NA;

    // Session state first. Only the idle case asks PS,
    // and only to tell "a wallet is there, unlock it" from "nothing here yet".
    switch (w->state) {
    case WALLET_SESSION_ACTIVE:
        *state_out = BITCOIN_STATUS_OPEN;
        return PSA_SUCCESS;
    case WALLET_SESSION_SETUP:
        *state_out = BITCOIN_STATUS_SETUP;
        return PSA_SUCCESS;
    case WALLET_SESSION_NONE:
        break;
    }

    bool exists = false;
    psa_status_t status = key_storage_exists(w->uids, &exists);
    if (status == PSA_ERROR_DATA_INVALID) {
        *state_out = BITCOIN_STATUS_UNREADABLE;
        return PSA_SUCCESS;
    }
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!exists) {
        *state_out = BITCOIN_STATUS_NONE;
        return PSA_SUCCESS;
    }

    status = key_storage_get_attempts_remaining(w->uids, attempts_out);
    if (status != PSA_SUCCESS) {
        return status;
    }
    *state_out = BITCOIN_STATUS_LOCKED;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_destroy(wallet_session_t *w, const char *pin)
{
    magic_internet_key_t keys = {0};
    psa_status_t status = key_storage_load(w->uids, pin, &keys);
    bool exists = true;

    mem_zeroize(&keys, sizeof(keys));

    if (status == PSA_SUCCESS) {
        status = key_storage_wipe(w->uids);
    }
    // The last wrong PIN removes the record too. The open wallet must not outlive it.
    if (status == PSA_SUCCESS || (status != PSA_ERROR_DOES_NOT_EXIST &&
                                  key_storage_exists(w->uids, &exists) == PSA_SUCCESS && !exists)) {
        clear_session_data(w);
    }
    return status;
}

psa_status_t bitcoin_core_stored(wallet_session_t *w, bool *exists)
{
    return key_storage_exists(w->uids, exists);
}

psa_status_t bitcoin_core_discard_unreadable(wallet_session_t *w)
{
    return key_storage_wipe_unreadable(w->uids);
}

// Create and recover start a setup only with no record and no session.
static psa_status_t may_set_up(wallet_session_t *w)
{
    bool exists = false;
    psa_status_t status = key_storage_exists(w->uids, &exists);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (exists) {
        return PSA_ERROR_ALREADY_EXISTS;
    }
    if (w->state != WALLET_SESSION_NONE) {
        return PSA_ERROR_BAD_STATE;
    }
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_create(wallet_session_t *w, size_t entropy_size, char *mnemonic_out,
                                 size_t mnemonic_size)
{
    psa_status_t status = may_set_up(w);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Checked before psa_generate_random(),
    // which would otherwise write past the entropy field into the session union.
    // BIP39 defines only 16/20/24/28/32.
    if (entropy_size < BITCOIN_ENTROPY_MIN_SIZE || entropy_size > BITCOIN_ENTROPY_MAX_SIZE ||
        (entropy_size % 4) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    wallet_setup_context_t *setup = &w->data.setup;

    setup->entropy_size = entropy_size;
    status = psa_generate_random(setup->entropy, setup->entropy_size);
    if (status == PSA_SUCCESS) {
        status = bip39_entropy_to_mnemonic(setup->entropy, setup->entropy_size, mnemonic_out,
                                           mnemonic_size);
    }
    if (status != PSA_SUCCESS) {
        mem_zeroize(mnemonic_out, mnemonic_size);
        clear_session_data(w);
        return status;
    }

    w->state = WALLET_SESSION_SETUP;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_recover(wallet_session_t *w, const char *mnemonic)
{
    psa_status_t status = may_set_up(w);
    if (status != PSA_SUCCESS) {
        return status;
    }

    wallet_setup_context_t *setup = &w->data.setup;

    memset(setup->entropy, 0, sizeof(setup->entropy));
    setup->entropy_size = sizeof(setup->entropy);
    status = bip39_mnemonic_to_entropy(mnemonic, setup->entropy, &setup->entropy_size);
    if (status != PSA_SUCCESS) {
        clear_session_data(w);
        return status;
    }

    w->state = WALLET_SESSION_SETUP;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_confirm(wallet_session_t *w, const char *pin)
{
    if (w->state != WALLET_SESSION_SETUP) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_setup_context_t *setup = &w->data.setup;
    magic_internet_key_t keys = {.version = 1, .entropy_size = setup->entropy_size};
    memcpy(keys.entropy, setup->entropy, setup->entropy_size);

    psa_status_t status = key_storage_store(w->uids, &keys, pin);

    mem_zeroize(&keys, sizeof(keys));
    clear_session_data(w);
    return status;
}

psa_status_t bitcoin_core_abort_setup(wallet_session_t *w)
{
    if (w->state != WALLET_SESSION_SETUP) {
        return PSA_ERROR_BAD_STATE;
    }
    clear_session_data(w);
    return PSA_SUCCESS;
}

// Common end of the two open paths: mnemonic + passphrase -> master key.
static psa_status_t open_from_mnemonic(wallet_session_t *w, const char *mnemonic,
                                       const char *passphrase)
{
    uint8_t seed[BIP39_SEED_SIZE];
    psa_status_t status = bip39_mnemonic_to_seed(mnemonic, passphrase, seed);
    if (status != PSA_SUCCESS) {
        mem_zeroize(seed, sizeof(seed));
        return status;
    }

    wallet_opened_context_t *opened = &w->data.opened;

    status = bip32_seed_to_master_privkey(seed, sizeof(seed), &opened->master_key);
    mem_zeroize(seed, sizeof(seed));
    if (status != PSA_SUCCESS) {
        clear_session_data(w);
        return status;
    }

    w->state = WALLET_SESSION_ACTIVE;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_open(wallet_session_t *w, const char *pin, const char *passphrase)
{
    if (w->state != WALLET_SESSION_NONE) {
        return PSA_ERROR_BAD_STATE;
    }

    magic_internet_key_t keys = {0};
    psa_status_t status = key_storage_load(w->uids, pin, &keys);
    if (status != PSA_SUCCESS) {
        mem_zeroize(&keys, sizeof(keys));
        return status;
    }

    char mnemonic[BITCOIN_MNEMONIC_MAX_SIZE];
    status = bip39_entropy_to_mnemonic(keys.entropy, keys.entropy_size, mnemonic, sizeof(mnemonic));

    mem_zeroize(&keys, sizeof(keys));

    if (status != PSA_SUCCESS) {
        mem_zeroize(mnemonic, sizeof(mnemonic));
        return status;
    }

    status = open_from_mnemonic(w, mnemonic, passphrase);
    mem_zeroize(mnemonic, sizeof(mnemonic));
    return status;
}

#ifdef SIGU_SELFTEST
psa_status_t bitcoin_core_open_ephemeral(wallet_session_t *w, const char *mnemonic,
                                         const char *passphrase)
{
    // The whole test-wallet design rests on this check:
    // on the production session, programmatic approval would apply to real keys.
    if (w->approval != APPROVAL_PROGRAMMATIC) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (!mnemonic || !passphrase) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // The test wallet has no close opcode, so a new open replaces it.
    clear_session_data(w);
    return open_from_mnemonic(w, mnemonic, passphrase);
}
#endif

psa_status_t bitcoin_core_open_temporary(wallet_session_t *w, const char *mnemonic,
                                         const char *passphrase)
{
    // The test session may only be seeded by open_ephemeral().
    // A temporary wallet holds a real key, so it must take button approval.
    if (w->approval != APPROVAL_BUTTON) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    if (w->state != WALLET_SESSION_NONE) {
        return PSA_ERROR_BAD_STATE;
    }
    if (!mnemonic || !passphrase) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // The seed entry screen checks the checksum too, but this is the input the key comes from.
    psa_status_t status = bip39_validate_mnemonic(mnemonic);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = open_from_mnemonic(w, mnemonic, passphrase);
    if (status == PSA_SUCCESS) {
        w->data.opened.temporary = true;
    }
    return status;
}

bool bitcoin_core_is_temporary(wallet_session_t *w)
{
    return w->state == WALLET_SESSION_ACTIVE && w->data.opened.temporary;
}

psa_status_t bitcoin_core_close(wallet_session_t *w)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    clear_session_data(w);
    return PSA_SUCCESS;
}

// The path decides what an answer may say:
// P2WPKH only, on the network the path names, so a caller cannot pick either.
static psa_status_t bip84_coin_type(const char *derivation_path, uint32_t *coin_type)
{
    uint32_t purpose = 0;
    psa_status_t status = bip32_path_purpose(derivation_path, &purpose);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (purpose != (84u | BIP32_HARDENED)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = bip32_path_coin_type(derivation_path, coin_type);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (*coin_type != 0 && *coin_type != 1) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

// The pubkey of the BIP84 key at `path`, and the coin type of the path.
// A key under another purpose would go into a descriptor or address this wallet cannot sign for.
static psa_status_t derive_bip84(wallet_session_t *w, const char *path, uint32_t *coin_type,
                                 bip32_extended_pubkey_t *out)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    psa_status_t status = bip84_coin_type(path, coin_type);
    if (status != PSA_SUCCESS) {
        return status;
    }

    bip32_extended_privkey_t key;
    status = bip32_extended_privkey_derive_from_path(&w->data.opened.master_key, path, &key);
    if (status == PSA_SUCCESS) {
        status = bip32_extended_pubkey_from_privkey(&key, out);
    }
    mem_zeroize(&key, sizeof(key));
    if (status != PSA_SUCCESS) {
        mem_zeroize(out, sizeof(*out));
    }
    return status;
}

psa_status_t bitcoin_core_get_xpub(wallet_session_t *w, const char *derivation_path, char *xpub,
                                   size_t xpub_size)
{
    uint32_t coin_type = 0;
    bip32_extended_pubkey_t pub;

    psa_status_t status = derive_bip84(w, derivation_path, &coin_type, &pub);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = bip32_extended_pubkey_serialize(
        &pub, coin_type == 0 ? BIP32_MAINNET_PUB_VERSION : BIP32_TESTNET_PUB_VERSION, xpub,
        &xpub_size);
    mem_zeroize(&pub, sizeof(pub));
    return status;
}

psa_status_t bitcoin_core_get_address(wallet_session_t *w, const char *derivation_path,
                                      char *address, size_t address_size)
{
    uint32_t coin_type = 0;
    bip32_extended_pubkey_t pub;
    uint8_t script[SCRIPT_P2WPKH_SIZE];

    psa_status_t status = derive_bip84(w, derivation_path, &coin_type, &pub);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = script_p2wpkh_from_pubkey(pub.pubkey, script);
    mem_zeroize(&pub, sizeof(pub));
    if (status != PSA_SUCCESS) {
        return status;
    }
    return script_to_address(script, sizeof(script), coin_type, address, address_size);
}

// Raw primitive. It does not know what it signs, so the caller decides what may be signed.
static psa_status_t sign_digest(wallet_session_t *w, const char *derivation_path,
                                const uint8_t *hash, uint8_t *signature, size_t *signature_size)
{
    wallet_opened_context_t *opened = &w->data.opened;

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&opened->master_key, derivation_path, &derived_key);
    if (status != PSA_SUCCESS) {
        mem_zeroize(&derived_key, sizeof(derived_key));
        return status;
    }

    uint8_t context_mem[secp256k1_get_context_size()];
    secp256k1_context *ctx = secp256k1_create_randomized_context(context_mem);
    if (ctx == NULL) {
        mem_zeroize(&derived_key, sizeof(derived_key));
        mem_zeroize(context_mem, sizeof(context_mem));
        return PSA_ERROR_GENERIC_ERROR;
    }
    secp256k1_ecdsa_signature sig;

    int res = secp256k1_ecdsa_sign(ctx, &sig, hash, derived_key.private_key, NULL, NULL);

    mem_zeroize(&derived_key, sizeof(derived_key));

    if (!res) {
        secp256k1_context_preallocated_destroy(ctx);
        mem_zeroize(&sig, sizeof(sig));
        mem_zeroize(context_mem, sizeof(context_mem));
        return PSA_ERROR_GENERIC_ERROR;
    }

    int serialized = secp256k1_ecdsa_signature_serialize_der(ctx, signature, signature_size, &sig);

    secp256k1_context_preallocated_destroy(ctx);
    mem_zeroize(&sig, sizeof(sig));
    mem_zeroize(context_mem, sizeof(context_mem));

    return serialized ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t bitcoin_core_get_fingerprint(wallet_session_t *w,
                                          uint8_t fingerprint[BITCOIN_FINGERPRINT_SIZE])
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    bip32_extended_pubkey_t pub;
    psa_status_t status = bip32_extended_pubkey_from_privkey(&w->data.opened.master_key, &pub);
    if (status == PSA_SUCCESS) {
        status = bip32_extended_pubkey_get_fingerprint(&pub, fingerprint);
    }
    mem_zeroize(&pub, sizeof(pub));
    return status;
}

psa_status_t bitcoin_core_tx_begin(wallet_session_t *w, const bitcoin_tx_begin_t *begin)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_begin(&w->tx, begin);
}

psa_status_t bitcoin_core_tx_output(wallet_session_t *w, const bitcoin_tx_output_t *out,
                                    const char *path)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_add_output(&w->tx, out, path, &w->data.opened.master_key);
}

psa_status_t bitcoin_core_tx_input(wallet_session_t *w, const bitcoin_tx_input_t *in,
                                   const char *path, const uint8_t *prev_tx, size_t prev_tx_len)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_add_input(&w->tx, in, path, prev_tx, prev_tx_len);
}

psa_status_t bitcoin_core_tx_confirm(wallet_session_t *w, uint8_t *tx_id32)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    psa_status_t status = tx_session_confirm(&w->tx, tx_id32);
    if (status == PSA_SUCCESS && w->approval == APPROVAL_BUTTON) {
        INFO("Press OK on the review screen to approve.\n");
    }
    return status;
}

psa_status_t bitcoin_core_tx_poll(wallet_session_t *w, uint32_t *result)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_poll(&w->tx, result);
}

psa_status_t bitcoin_core_tx_get_tx_id(wallet_session_t *w, uint8_t *tx_id32)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_get_tx_id(&w->tx, tx_id32);
}

psa_status_t bitcoin_core_tx_approve_user(wallet_session_t *w, const uint8_t *tx_id32)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    // The test wallet takes only programmatic approval.
    // A key press must not approve a transaction that the test service streamed.
    if (w->approval != APPROVAL_BUTTON) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    return tx_session_approve_user(&w->tx, tx_id32);
}

#ifdef SIGU_SELFTEST
psa_status_t bitcoin_core_tx_approve_programmatic(wallet_session_t *w)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    // The lock on this path: no production opcode reaches here,
    // and the production session is not APPROVAL_PROGRAMMATIC.
    if (w->approval != APPROVAL_PROGRAMMATIC) {
        return PSA_ERROR_NOT_PERMITTED;
    }
    return tx_session_approve_programmatic(&w->tx);
}
#endif

psa_status_t bitcoin_core_tx_sign_input(wallet_session_t *w, uint32_t index, const char *path,
                                        uint8_t *signature, size_t *signature_size, uint8_t *pubkey)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    // Checks the approval, the tx_id binding and one signature per index.
    uint8_t sighash[BITCOIN_SIGHASH_SIZE];
    psa_status_t status =
        tx_session_input_sighash(&w->tx, index, path, &w->data.opened.master_key, sighash, pubkey);
    if (status != PSA_SUCCESS) {
        mem_zeroize(sighash, sizeof(sighash));
        return status;
    }

    status = sign_digest(w, path, sighash, signature, signature_size);
    mem_zeroize(sighash, sizeof(sighash));
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Spend the index only after a signature came back,
    // so a temporary failure does not cost an input.
    return tx_session_mark_signed(&w->tx, index);
}

psa_status_t bitcoin_core_tx_abort(wallet_session_t *w)
{
    tx_session_reset(&w->tx);
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_tx_get_summary(wallet_session_t *w, uint32_t line,
                                         bitcoin_tx_summary_t *out)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_get_summary(&w->tx, line, out);
}

psa_status_t bitcoin_core_tx_get_details(wallet_session_t *w, bitcoin_tx_details_t *out)
{
    if (w->state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    return tx_session_get_details(&w->tx, out);
}
