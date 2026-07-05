#include "native/wolfssl_helper.h"

#include <glib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

static void
set_wc_error(GError** error, int rc, const char* context) {
    g_set_error(error, x3dhpq_wolfssl_error_quark(), rc, "%s (wolfSSL rc=%d)", context, rc);
}

GQuark
x3dhpq_wolfssl_error_quark(void) {
    return g_quark_from_static_string("dino-x3dhpq-wolfssl-error");
}

static GBytes*
new_bytes_take(guchar* data, gsize len) {
    return g_bytes_new_take(data, len);
}

static GBytes*
new_bytes_from_copy(const guchar* data, gsize len) {
    guchar* copy = g_malloc(len);
    memcpy(copy, data, len);
    return new_bytes_take(copy, len);
}

static const guchar*
bytes_data(GBytes* bytes, gsize* len) {
    if (bytes == NULL) {
        if (len != NULL) {
            *len = 0;
        }
        return NULL;
    }
    return g_bytes_get_data(bytes, len);
}

static int
init_rng(WC_RNG* rng, GError** error) {
    int rc = wc_InitRng(rng);
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to initialize RNG");
    }
    return rc;
}

GBytes*
x3dhpq_wolfssl_random_bytes(gsize length, GError** error) {
    GBytes* result = NULL;
    WC_RNG rng;
    guchar* buffer;
    int rc;

    if (length == 0) {
        return g_bytes_new_static("", 0);
    }

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return NULL;
    }

    buffer = g_malloc(length);
    rc = wc_RNG_GenerateBlock(&rng, buffer, (word32) length);
    wc_FreeRng(&rng);
    if (rc != 0) {
        g_free(buffer);
        set_wc_error(error, rc, "Failed to generate random bytes");
        return NULL;
    }

    result = new_bytes_take(buffer, length);
    return result;
}

void
x3dhpq_wolfssl_generate_x25519(GBytes** public_key, GBytes** private_key, GError** error) {
    curve25519_key key;
    WC_RNG rng;
    guchar* pub = NULL;
    guchar* priv = NULL;
    word32 pub_len = CURVE25519_KEYSIZE;
    word32 priv_len = CURVE25519_KEYSIZE;
    int rc;

    g_return_if_fail(public_key != NULL);
    g_return_if_fail(private_key != NULL);

    *public_key = NULL;
    *private_key = NULL;

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return;
    }

    rc = wc_curve25519_init(&key);
    if (rc != 0) {
        wc_FreeRng(&rng);
        set_wc_error(error, rc, "Failed to initialize X25519 key");
        return;
    }

    rc = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &key);
    wc_FreeRng(&rng);
    if (rc != 0) {
        wc_curve25519_free(&key);
        set_wc_error(error, rc, "Failed to generate X25519 key");
        return;
    }

    pub = g_malloc(pub_len);
    priv = g_malloc(priv_len);
    rc = wc_curve25519_export_key_raw_ex(&key, priv, &priv_len, pub, &pub_len, EC25519_LITTLE_ENDIAN);
    wc_curve25519_free(&key);
    if (rc != 0) {
        g_free(pub);
        g_free(priv);
        set_wc_error(error, rc, "Failed to export X25519 key");
        return;
    }

    *public_key = new_bytes_take(pub, pub_len);
    *private_key = new_bytes_take(priv, priv_len);
}

GBytes*
x3dhpq_wolfssl_x25519_shared_secret(GBytes* private_key, GBytes* public_key, GError** error) {
    curve25519_key priv_key;
    curve25519_key pub_key;
    GBytes* result = NULL;
    gsize priv_len = 0;
    gsize pub_len = 0;
    const guchar* priv = bytes_data(private_key, &priv_len);
    const guchar* pub = bytes_data(public_key, &pub_len);
    guchar shared[CURVE25519_KEYSIZE];
    word32 shared_len = sizeof(shared);
    int rc;

    rc = wc_curve25519_init(&priv_key);
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to initialize X25519 private key");
        return NULL;
    }
    rc = wc_curve25519_init(&pub_key);
    if (rc != 0) {
        wc_curve25519_free(&priv_key);
        set_wc_error(error, rc, "Failed to initialize X25519 public key");
        return NULL;
    }

    rc = wc_curve25519_import_private_ex(priv, (word32) priv_len, &priv_key, EC25519_LITTLE_ENDIAN);
    if (rc == 0) {
        rc = wc_curve25519_import_public_ex(pub, (word32) pub_len, &pub_key, EC25519_LITTLE_ENDIAN);
    }
    if (rc == 0) {
        rc = wc_curve25519_shared_secret_ex(&priv_key, &pub_key, shared, &shared_len, EC25519_LITTLE_ENDIAN);
    }
    wc_curve25519_free(&priv_key);
    wc_curve25519_free(&pub_key);

    if (rc != 0) {
        set_wc_error(error, rc, "Failed to compute X25519 shared secret");
        return NULL;
    }

    result = new_bytes_from_copy(shared, shared_len);
    return result;
}

void
x3dhpq_wolfssl_generate_ed25519(GBytes** public_key, GBytes** private_key, GError** error) {
    ed25519_key key;
    WC_RNG rng;
    guchar* pub = NULL;
    guchar* priv = NULL;
    word32 pub_len;
    word32 priv_len;
    int rc;

    g_return_if_fail(public_key != NULL);
    g_return_if_fail(private_key != NULL);

    *public_key = NULL;
    *private_key = NULL;

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return;
    }

    rc = wc_ed25519_init(&key);
    if (rc != 0) {
        wc_FreeRng(&rng);
        set_wc_error(error, rc, "Failed to initialize Ed25519 key");
        return;
    }

    rc = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
    wc_FreeRng(&rng);
    if (rc != 0) {
        wc_ed25519_free(&key);
        set_wc_error(error, rc, "Failed to generate Ed25519 key");
        return;
    }

    pub_len = (word32) wc_ed25519_pub_size(&key);
    priv_len = (word32) wc_ed25519_priv_size(&key);
    pub = g_malloc(pub_len);
    priv = g_malloc(priv_len);

    rc = wc_ed25519_export_public(&key, pub, &pub_len);
    if (rc == 0) {
        rc = wc_ed25519_export_private(&key, priv, &priv_len);
    }
    wc_ed25519_free(&key);

    if (rc != 0) {
        g_free(pub);
        g_free(priv);
        set_wc_error(error, rc, "Failed to export Ed25519 key");
        return;
    }

    *public_key = new_bytes_take(pub, pub_len);
    *private_key = new_bytes_take(priv, priv_len);
}

GBytes*
x3dhpq_wolfssl_ed25519_sign(GBytes* private_key, GBytes* message, GError** error) {
    ed25519_key key;
    GBytes* result = NULL;
    gsize priv_len = 0;
    gsize msg_len = 0;
    const guchar* priv = bytes_data(private_key, &priv_len);
    const guchar* msg = bytes_data(message, &msg_len);
    guchar* sig = NULL;
    word32 sig_len;
    int rc;

    rc = wc_ed25519_init(&key);
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to initialize Ed25519 signer");
        return NULL;
    }

    if (priv_len < ED25519_KEY_SIZE + ED25519_PUB_KEY_SIZE) {
        wc_ed25519_free(&key);
        set_wc_error(error, BAD_FUNC_ARG, "Ed25519 private key blob is too short");
        return NULL;
    }

    rc = wc_ed25519_import_private_key(
        priv,
        (word32) priv_len,
        priv + (priv_len - ED25519_PUB_KEY_SIZE),
        ED25519_PUB_KEY_SIZE,
        &key
    );
    if (rc == 0) {
        rc = wc_ed25519_check_key(&key);
    }
    if (rc != 0) {
        wc_ed25519_free(&key);
        set_wc_error(error, rc, "Failed to import Ed25519 private key");
        return NULL;
    }

    sig_len = (word32) wc_ed25519_sig_size(&key);
    sig = g_malloc(sig_len);
    rc = wc_ed25519_sign_msg(msg, (word32) msg_len, sig, &sig_len, &key);
    wc_ed25519_free(&key);
    if (rc != 0) {
        g_free(sig);
        set_wc_error(error, rc, "Failed to sign Ed25519 message");
        return NULL;
    }

    result = new_bytes_take(sig, sig_len);
    return result;
}

gboolean
x3dhpq_wolfssl_ed25519_verify(GBytes* public_key, GBytes* message, GBytes* signature, GError** error) {
    ed25519_key key;
    gsize pub_len = 0;
    gsize msg_len = 0;
    gsize sig_len = 0;
    const guchar* pub = bytes_data(public_key, &pub_len);
    const guchar* msg = bytes_data(message, &msg_len);
    const guchar* sig = bytes_data(signature, &sig_len);
    int res = 0;
    int rc;

    rc = wc_ed25519_init(&key);
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to initialize Ed25519 verifier");
        return FALSE;
    }

    rc = wc_ed25519_import_public(pub, (word32) pub_len, &key);
    if (rc == 0) {
        rc = wc_ed25519_verify_msg(sig, (word32) sig_len, msg, (word32) msg_len, &res, &key);
    }
    wc_ed25519_free(&key);

    if (rc != 0) {
        set_wc_error(error, rc, "Failed to verify Ed25519 signature");
        return FALSE;
    }

    return res == 1;
}

void
x3dhpq_wolfssl_generate_mldsa65(GBytes** public_key, GBytes** private_key, GError** error) {
    dilithium_key key;
    WC_RNG rng;
    guchar* pub = NULL;
    guchar* priv = NULL;
    word32 pub_len = ML_DSA_LEVEL3_PUB_KEY_SIZE;
    word32 raw_priv_len = DILITHIUM_LEVEL3_KEY_SIZE;
    int rc;

    g_return_if_fail(public_key != NULL);
    g_return_if_fail(private_key != NULL);

    *public_key = NULL;
    *private_key = NULL;

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return;
    }

    rc = wc_dilithium_init(&key);
    if (rc == 0) {
        rc = wc_dilithium_set_level(&key, 3);
    }
    if (rc == 0) {
        rc = wc_dilithium_make_key(&key, &rng);
    }
    wc_FreeRng(&rng);
    if (rc != 0) {
        wc_dilithium_free(&key);
        set_wc_error(error, rc, "Failed to generate ML-DSA-65 key");
        return;
    }

    pub = g_malloc(pub_len);
    priv = g_malloc(raw_priv_len + pub_len);
    rc = wc_dilithium_export_public(&key, pub, &pub_len);
    if (rc == 0) {
        rc = wc_dilithium_export_private(&key, priv, &raw_priv_len);
    }
    wc_dilithium_free(&key);
    if (rc != 0) {
        g_free(pub);
        g_free(priv);
        set_wc_error(error, rc, "Failed to export ML-DSA-65 key");
        return;
    }

    memcpy(priv + raw_priv_len, pub, pub_len);
    *public_key = new_bytes_take(pub, pub_len);
    *private_key = new_bytes_take(priv, raw_priv_len + pub_len);
}

GBytes*
x3dhpq_wolfssl_mldsa65_sign(GBytes* private_key, GBytes* message, GError** error) {
    dilithium_key key;
    WC_RNG rng;
    GBytes* result = NULL;
    gsize priv_len = 0;
    gsize msg_len = 0;
    const guchar* priv = bytes_data(private_key, &priv_len);
    const guchar* msg = bytes_data(message, &msg_len);
    guchar* sig = NULL;
    word32 sig_len = ML_DSA_LEVEL3_SIG_SIZE;
    const guchar* pub;
    int rc;

    if (priv_len <= ML_DSA_LEVEL3_PUB_KEY_SIZE) {
        g_set_error_literal(error, x3dhpq_wolfssl_error_quark(), WC_KEY_SIZE_E, "ML-DSA-65 private key is truncated");
        return NULL;
    }

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return NULL;
    }

    rc = wc_dilithium_init(&key);
    if (rc == 0) {
        rc = wc_dilithium_set_level(&key, 3);
    }
    pub = priv + (priv_len - ML_DSA_LEVEL3_PUB_KEY_SIZE);
    if (rc == 0) {
        rc = wc_dilithium_import_key(priv, (word32) (priv_len - ML_DSA_LEVEL3_PUB_KEY_SIZE), pub, ML_DSA_LEVEL3_PUB_KEY_SIZE, &key);
    }
    if (rc != 0) {
        wc_FreeRng(&rng);
        wc_dilithium_free(&key);
        set_wc_error(error, rc, "Failed to import ML-DSA-65 private key");
        return NULL;
    }

    sig = g_malloc(sig_len);
    rc = wc_dilithium_sign_ctx_msg(NULL, 0, msg, (word32) msg_len, sig, &sig_len, &key, &rng);
    wc_FreeRng(&rng);
    wc_dilithium_free(&key);
    if (rc != 0) {
        g_free(sig);
        set_wc_error(error, rc, "Failed to sign ML-DSA-65 message");
        return NULL;
    }

    result = new_bytes_take(sig, sig_len);
    return result;
}

gboolean
x3dhpq_wolfssl_mldsa65_verify(GBytes* public_key, GBytes* message, GBytes* signature, GError** error) {
    dilithium_key key;
    gsize pub_len = 0;
    gsize msg_len = 0;
    gsize sig_len = 0;
    const guchar* pub = bytes_data(public_key, &pub_len);
    const guchar* msg = bytes_data(message, &msg_len);
    const guchar* sig = bytes_data(signature, &sig_len);
    int res = 0;
    int rc;

    rc = wc_dilithium_init(&key);
    if (rc == 0) {
        rc = wc_dilithium_set_level(&key, 3);
    }
    if (rc == 0) {
        rc = wc_dilithium_import_public(pub, (word32) pub_len, &key);
    }
    if (rc == 0) {
        rc = wc_dilithium_verify_ctx_msg(sig, (word32) sig_len, NULL, 0, msg, (word32) msg_len, &res, &key);
    }
    wc_dilithium_free(&key);

    if (rc != 0) {
        set_wc_error(error, rc, "Failed to verify ML-DSA-65 signature");
        return FALSE;
    }

    return res == 1;
}

void
x3dhpq_wolfssl_generate_mlkem768(GBytes** public_key, GBytes** private_key, GError** error) {
    MlKemKey* key;
    WC_RNG rng;
    guchar* pub = NULL;
    guchar* priv = NULL;
    word32 pub_len = 0;
    word32 priv_len = 0;
    int rc;

    g_return_if_fail(public_key != NULL);
    g_return_if_fail(private_key != NULL);

    *public_key = NULL;
    *private_key = NULL;

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return;
    }

    key = wc_MlKemKey_New(WC_ML_KEM_768, NULL, -1);
    if (key == NULL) {
        wc_FreeRng(&rng);
        g_set_error_literal(error, x3dhpq_wolfssl_error_quark(), MEMORY_E, "Failed to allocate ML-KEM-768 key");
        return;
    }

    rc = wc_MlKemKey_MakeKey(key, &rng);
    wc_FreeRng(&rng);
    if (rc == 0) {
        rc = wc_MlKemKey_PublicKeySize(key, &pub_len);
    }
    if (rc == 0) {
        rc = wc_MlKemKey_PrivateKeySize(key, &priv_len);
    }
    if (rc != 0) {
        wc_MlKemKey_Delete(key, NULL);
        set_wc_error(error, rc, "Failed to generate ML-KEM-768 key");
        return;
    }

    pub = g_malloc(pub_len);
    priv = g_malloc(priv_len);
    rc = wc_MlKemKey_EncodePublicKey(key, pub, pub_len);
    if (rc == 0) {
        rc = wc_MlKemKey_EncodePrivateKey(key, priv, priv_len);
    }
    wc_MlKemKey_Delete(key, NULL);
    if (rc != 0) {
        g_free(pub);
        g_free(priv);
        set_wc_error(error, rc, "Failed to export ML-KEM-768 key");
        return;
    }

    *public_key = new_bytes_take(pub, pub_len);
    *private_key = new_bytes_take(priv, priv_len);
}

void
x3dhpq_wolfssl_mlkem768_encapsulate(GBytes* public_key, GBytes** ciphertext, GBytes** shared_secret, GError** error) {
    MlKemKey* key;
    gsize pub_len = 0;
    const guchar* pub = bytes_data(public_key, &pub_len);
    guchar* ct = NULL;
    guchar* ss = NULL;
    word32 ct_len = 0;
    word32 ss_len = 0;
    WC_RNG rng;
    int rc;

    g_return_if_fail(ciphertext != NULL);
    g_return_if_fail(shared_secret != NULL);

    *ciphertext = NULL;
    *shared_secret = NULL;

    rc = init_rng(&rng, error);
    if (rc != 0) {
        return;
    }

    key = wc_MlKemKey_New(WC_ML_KEM_768, NULL, -1);
    if (key == NULL) {
        wc_FreeRng(&rng);
        g_set_error_literal(error, x3dhpq_wolfssl_error_quark(), MEMORY_E, "Failed to allocate ML-KEM-768 key");
        return;
    }

    rc = wc_MlKemKey_DecodePublicKey(key, pub, (word32) pub_len);
    if (rc == 0) {
        rc = wc_MlKemKey_CipherTextSize(key, &ct_len);
    }
    if (rc == 0) {
        rc = wc_MlKemKey_SharedSecretSize(key, &ss_len);
    }
    if (rc != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Delete(key, NULL);
        set_wc_error(error, rc, "Failed to prepare ML-KEM-768 encapsulation");
        return;
    }

    ct = g_malloc(ct_len);
    ss = g_malloc(ss_len);
    rc = wc_MlKemKey_Encapsulate(key, ct, ss, &rng);
    wc_FreeRng(&rng);
    wc_MlKemKey_Delete(key, NULL);
    if (rc != 0) {
        g_free(ct);
        g_free(ss);
        set_wc_error(error, rc, "Failed to encapsulate ML-KEM-768 secret");
        return;
    }

    *ciphertext = new_bytes_take(ct, ct_len);
    *shared_secret = new_bytes_take(ss, ss_len);
}

GBytes*
x3dhpq_wolfssl_mlkem768_decapsulate(GBytes* private_key, GBytes* ciphertext, GError** error) {
    MlKemKey* key;
    GBytes* result = NULL;
    gsize priv_len = 0;
    gsize ct_len = 0;
    const guchar* priv = bytes_data(private_key, &priv_len);
    const guchar* ct = bytes_data(ciphertext, &ct_len);
    guchar* ss = NULL;
    word32 ss_len = 0;
    int rc;

    key = wc_MlKemKey_New(WC_ML_KEM_768, NULL, -1);
    if (key == NULL) {
        g_set_error_literal(error, x3dhpq_wolfssl_error_quark(), MEMORY_E, "Failed to allocate ML-KEM-768 key");
        return NULL;
    }

    rc = wc_MlKemKey_DecodePrivateKey(key, priv, (word32) priv_len);
    if (rc == 0) {
        rc = wc_MlKemKey_SharedSecretSize(key, &ss_len);
    }
    if (rc != 0) {
        wc_MlKemKey_Delete(key, NULL);
        set_wc_error(error, rc, "Failed to prepare ML-KEM-768 decapsulation");
        return NULL;
    }

    ss = g_malloc(ss_len);
    rc = wc_MlKemKey_Decapsulate(key, ss, ct, (word32) ct_len);
    wc_MlKemKey_Delete(key, NULL);
    if (rc != 0) {
        g_free(ss);
        set_wc_error(error, rc, "Failed to decapsulate ML-KEM-768 secret");
        return NULL;
    }

    result = new_bytes_take(ss, ss_len);
    return result;
}

GBytes*
x3dhpq_wolfssl_hkdf_extract_sha512(GBytes* salt, GBytes* input_key_material, GError** error) {
    gsize salt_len = 0;
    gsize ikm_len = 0;
    const guchar* salt_data = bytes_data(salt, &salt_len);
    const guchar* ikm_data = bytes_data(input_key_material, &ikm_len);
    guchar prk[WC_SHA512_DIGEST_SIZE];
    int rc;

    rc = wc_HKDF_Extract(WC_SHA512, salt_data, (word32) salt_len, ikm_data, (word32) ikm_len, prk);
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to HKDF-extract with SHA-512");
        return NULL;
    }

    return new_bytes_from_copy(prk, sizeof(prk));
}

GBytes*
x3dhpq_wolfssl_hkdf_expand_sha512(GBytes* pseudorandom_key, GBytes* info, gsize output_size, GError** error) {
    gsize prk_len = 0;
    gsize info_len = 0;
    const guchar* prk = bytes_data(pseudorandom_key, &prk_len);
    const guchar* info_data = bytes_data(info, &info_len);
    guchar* out = g_malloc(output_size);
    int rc;

    rc = wc_HKDF_Expand(WC_SHA512, prk, (word32) prk_len, info_data, (word32) info_len, out, (word32) output_size);
    if (rc != 0) {
        g_free(out);
        set_wc_error(error, rc, "Failed to HKDF-expand with SHA-512");
        return NULL;
    }

    return new_bytes_take(out, output_size);
}

GBytes*
x3dhpq_wolfssl_hmac_sha256(GBytes* key, GBytes* message, GError** error) {
    Hmac hmac;
    gsize key_len = 0;
    gsize msg_len = 0;
    const guchar* key_data = bytes_data(key, &key_len);
    const guchar* msg = bytes_data(message, &msg_len);
    guchar out[WC_SHA256_DIGEST_SIZE];
    int rc;

    rc = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_HmacSetKey(&hmac, WC_SHA256, key_data, (word32) key_len);
    }
    if (rc == 0) {
        rc = wc_HmacUpdate(&hmac, msg, (word32) msg_len);
    }
    if (rc == 0) {
        rc = wc_HmacFinal(&hmac, out);
    }
    wc_HmacFree(&hmac);
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to compute HMAC-SHA-256");
        return NULL;
    }

    return new_bytes_from_copy(out, sizeof(out));
}

GBytes*
x3dhpq_wolfssl_sha256(GBytes* message, GError** error) {
    gsize msg_len = 0;
    const guchar* msg = bytes_data(message, &msg_len);
    guchar out[WC_SHA256_DIGEST_SIZE];
    int rc = wc_Sha256Hash(msg, (word32) msg_len, out);

    if (rc != 0) {
        set_wc_error(error, rc, "Failed to compute SHA-256");
        return NULL;
    }
    return new_bytes_from_copy(out, sizeof(out));
}

GBytes*
x3dhpq_wolfssl_sha512(GBytes* message, GError** error) {
    gsize msg_len = 0;
    const guchar* msg = bytes_data(message, &msg_len);
    guchar out[WC_SHA512_DIGEST_SIZE];
    int rc = wc_Sha512Hash(msg, (word32) msg_len, out);

    if (rc != 0) {
        set_wc_error(error, rc, "Failed to compute SHA-512");
        return NULL;
    }
    return new_bytes_from_copy(out, sizeof(out));
}

GBytes*
x3dhpq_wolfssl_blake2b160(GBytes* message, GError** error) {
    Blake2b blake2b;
    gsize msg_len = 0;
    const guchar* msg = bytes_data(message, &msg_len);
    guchar out[20];
    int rc;

    rc = wc_InitBlake2b(&blake2b, sizeof(out));
    if (rc == 0) {
        rc = wc_Blake2bUpdate(&blake2b, msg, (word32) msg_len);
    }
    if (rc == 0) {
        rc = wc_Blake2bFinal(&blake2b, out, sizeof(out));
    }
    if (rc != 0) {
        set_wc_error(error, rc, "Failed to compute BLAKE2b-160");
        return NULL;
    }

    return new_bytes_from_copy(out, sizeof(out));
}

GBytes*
x3dhpq_wolfssl_scrypt(GBytes* password, GBytes* salt, guint64 cost, guint block_size, guint parallel, gsize output_size, GError** error) {
    gsize password_len = 0;
    gsize salt_len = 0;
    const guchar* password_data = bytes_data(password, &password_len);
    const guchar* salt_data = bytes_data(salt, &salt_len);
    guchar* out = g_malloc(output_size);
    int rc = wc_scrypt(out, password_data, (int) password_len, salt_data, (int) salt_len, (int) cost, (int) block_size, (int) parallel, (int) output_size);

    if (rc != 0) {
        g_free(out);
        set_wc_error(error, rc, "Failed to derive scrypt key");
        return NULL;
    }

    return new_bytes_take(out, output_size);
}

static GBytes*
aes_256_gcm_common(gboolean encrypting, GBytes* key, GBytes* nonce, GBytes* payload, GBytes* aad, GError** error) {
    Aes aes;
    gsize key_len = 0;
    gsize nonce_len = 0;
    gsize payload_len = 0;
    gsize aad_len = 0;
    const guchar* key_data = bytes_data(key, &key_len);
    const guchar* nonce_data = bytes_data(nonce, &nonce_len);
    const guchar* payload_data = bytes_data(payload, &payload_len);
    const guchar* aad_data = bytes_data(aad, &aad_len);
    const gsize tag_len = 16;
    guchar* out;
    int rc;

    if (key_len != 32) {
        g_set_error_literal(error, x3dhpq_wolfssl_error_quark(), BAD_FUNC_ARG, "AES-256-GCM requires a 32-byte key");
        return NULL;
    }

    if (!encrypting && payload_len < tag_len) {
        g_set_error_literal(error, x3dhpq_wolfssl_error_quark(), BAD_FUNC_ARG, "AES-256-GCM ciphertext is too short");
        return NULL;
    }

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_AesGcmSetKey(&aes, key_data, (word32) key_len);
    }
    if (rc != 0) {
        wc_AesFree(&aes);
        set_wc_error(error, rc, "Failed to initialize AES-256-GCM");
        return NULL;
    }

    if (encrypting) {
        out = g_malloc(payload_len + tag_len);
        rc = wc_AesGcmEncrypt(&aes, out, payload_data, (word32) payload_len, nonce_data, (word32) nonce_len, out + payload_len, (word32) tag_len, aad_data, (word32) aad_len);
        wc_AesFree(&aes);
        if (rc != 0) {
            g_free(out);
            set_wc_error(error, rc, "Failed to encrypt with AES-256-GCM");
            return NULL;
        }
        return new_bytes_take(out, payload_len + tag_len);
    } else {
        gsize ct_len = payload_len - tag_len;
        out = g_malloc(ct_len);
        rc = wc_AesGcmDecrypt(&aes, out, payload_data, (word32) ct_len, nonce_data, (word32) nonce_len, payload_data + ct_len, (word32) tag_len, aad_data, (word32) aad_len);
        wc_AesFree(&aes);
        if (rc != 0) {
            g_free(out);
            set_wc_error(error, rc, "Failed to decrypt with AES-256-GCM");
            return NULL;
        }
        return new_bytes_take(out, ct_len);
    }
}

GBytes*
x3dhpq_wolfssl_aes256gcm_encrypt(GBytes* key, GBytes* nonce, GBytes* plaintext, GBytes* aad, GError** error) {
    return aes_256_gcm_common(TRUE, key, nonce, plaintext, aad, error);
}

GBytes*
x3dhpq_wolfssl_aes256gcm_decrypt(GBytes* key, GBytes* nonce, GBytes* ciphertext_and_tag, GBytes* aad, GError** error) {
    return aes_256_gcm_common(FALSE, key, nonce, ciphertext_and_tag, aad, error);
}

/* ---------------------------------------------------------------------------
 * hash_to_curve_x25519: curve25519_XMD:SHA-512_ELL2_NU_ per RFC 9380 §6.7.
 *
 * expand_message_xmd(msg, dst, 48) → 48-byte uniform bytes
 * u = OS2IP(bytes) mod p, where p = 2^255 - 19
 * x = Elligator2 map_to_curve(u)
 * return little-endian 32-byte encoding of x
 * ---------------------------------------------------------------------------*/

/* expand_message_xmd with SHA-512 (b_in_bytes=64, s_in_bytes=128).
 * RFC 9380 §5.4.1.  lenInBytes must be <= 64 (one output block). */
static int
expand_message_xmd_sha512(const guchar* msg, gsize msg_len,
                           const guchar* dst, gsize dst_len,
                           guchar* out, gsize len_in_bytes)
{
    /* DST prime = DST || I2OSP(len(DST), 1) */
    guchar dst_prime[256];
    gsize dst_prime_len;
    guchar z_pad[128]; /* SHA-512 block size */
    guchar len_i_b[2];
    guchar b0[WC_SHA512_DIGEST_SIZE];
    guchar b1[WC_SHA512_DIGEST_SIZE];
    int rc;

    if (dst_len > 255) {
        return BAD_FUNC_ARG;
    }
    memcpy(dst_prime, dst, dst_len);
    dst_prime[dst_len] = (guchar) dst_len;
    dst_prime_len = dst_len + 1;

    memset(z_pad, 0, sizeof(z_pad));

    len_i_b[0] = (guchar)(len_in_bytes >> 8);
    len_i_b[1] = (guchar) len_in_bytes;

    /* b0 = SHA-512(Z_pad || msg || l_i_b_str || 0x00 || DST_prime) */
    {
        wc_Sha512 sha;
        rc = wc_InitSha512(&sha);
        if (rc == 0) rc = wc_Sha512Update(&sha, z_pad, sizeof(z_pad));
        if (rc == 0) rc = wc_Sha512Update(&sha, msg, (word32) msg_len);
        if (rc == 0) rc = wc_Sha512Update(&sha, len_i_b, 2);
        if (rc == 0) rc = wc_Sha512Update(&sha, (guchar*)"\x00", 1);
        if (rc == 0) rc = wc_Sha512Update(&sha, dst_prime, (word32) dst_prime_len);
        if (rc == 0) rc = wc_Sha512Final(&sha, b0);
        wc_Sha512Free(&sha);
    }
    if (rc != 0) return rc;

    /* b1 = SHA-512(b0 || 0x01 || DST_prime) */
    {
        wc_Sha512 sha;
        rc = wc_InitSha512(&sha);
        if (rc == 0) rc = wc_Sha512Update(&sha, b0, sizeof(b0));
        if (rc == 0) rc = wc_Sha512Update(&sha, (guchar*)"\x01", 1);
        if (rc == 0) rc = wc_Sha512Update(&sha, dst_prime, (word32) dst_prime_len);
        if (rc == 0) rc = wc_Sha512Final(&sha, b1);
        wc_Sha512Free(&sha);
    }
    if (rc != 0) return rc;

    /* We only need len_in_bytes=48 which fits in one 64-byte block. */
    if (len_in_bytes > (gsize) WC_SHA512_DIGEST_SIZE) {
        return BAD_FUNC_ARG;
    }
    memcpy(out, b1, len_in_bytes);
    return 0;
}

/* p = 2^255 - 19 big-endian */
static const guchar p25519_be[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
};

/* is_square_gfp: Euler's criterion — returns 1 if u is a quadratic residue mod p */
static int
is_square_gfp(mp_int* u, mp_int* p, mp_int* p_minus1_over2, mp_int* tmp)
{
    int rc = mp_exptmod(u, p_minus1_over2, p, tmp);
    if (rc != 0) return -1;
    /* square if result is 0 or 1 */
    if (mp_iszero(tmp) == MP_YES) return 1;
    if (mp_cmp_d(tmp, 1) == MP_EQ) return 1;
    return 0;
}

GBytes*
x3dhpq_wolfssl_hash_to_curve_x25519(GBytes* msg, GBytes* dst, GError** error)
{
    gsize msg_len = 0;
    gsize dst_len = 0;
    const guchar* msg_data = bytes_data(msg, &msg_len);
    const guchar* dst_data = bytes_data(dst, &dst_len);

    guchar uniform[48];
    int rc;

    /* Step 1: expand_message_xmd(msg, dst, 48) */
    rc = expand_message_xmd_sha512(msg_data, msg_len, dst_data, dst_len, uniform, 48);
    if (rc != 0) {
        set_wc_error(error, rc, "hash_to_curve: expand_message_xmd failed");
        return NULL;
    }

    /* Set up mp_int variables */
    mp_int p, exp, u, tv1, tv2, denom, x1, x1sq, gx1, t, x, neg_a, tmp;
    /* A = 486662 */
    const mp_digit A_DIGIT = 486662;

    rc  = mp_init(&p);
    rc |= mp_init(&exp);
    rc |= mp_init(&u);
    rc |= mp_init(&tv1);
    rc |= mp_init(&tv2);
    rc |= mp_init(&denom);
    rc |= mp_init(&x1);
    rc |= mp_init(&x1sq);
    rc |= mp_init(&gx1);
    rc |= mp_init(&t);
    rc |= mp_init(&x);
    rc |= mp_init(&neg_a);
    rc |= mp_init(&tmp);
    if (rc != 0) {
        set_wc_error(error, rc, "hash_to_curve: mp_init failed");
        goto cleanup;
    }

    /* Load p = 2^255 - 19 */
    rc = mp_read_unsigned_bin(&p, p25519_be, 32);
    if (rc != 0) {
        set_wc_error(error, rc, "hash_to_curve: mp_read p failed");
        goto cleanup;
    }

    /* (p - 1) / 2 for Euler criterion — computed as p >> 1 (p is odd so this is exact) */
    /* We use mp_mod then exptmod: actually build (p-1)/2 via submod + divide */
    /* Simpler: read from known big-endian constant. p-1 = 2^255-20, /2 = 2^254-10.
     * 2^254-10 big-endian: [0x3f,0xff,...,0xff,0xf6] */
    {
        static const guchar p_m1_o2_be[32] = {
            0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6,
        };
        rc = mp_read_unsigned_bin(&exp, p_m1_o2_be, 32);
        if (rc != 0) {
            set_wc_error(error, rc, "hash_to_curve: mp_read exp failed");
            goto cleanup;
        }
    }

    /* Step 2: u = OS2IP(uniform[0:48]) mod p
     * The 48-byte big-endian value is already the right length. */
    rc = mp_read_unsigned_bin(&u, uniform, 48);
    if (rc != 0) {
        set_wc_error(error, rc, "hash_to_curve: mp_read u failed");
        goto cleanup;
    }
    rc = mp_mod(&u, &p, &u);
    if (rc != 0) {
        set_wc_error(error, rc, "hash_to_curve: mp_mod u failed");
        goto cleanup;
    }

    /* Step 3: Elligator2 map_to_curve
     * tv1 = u^2 mod p */
    rc = mp_mulmod(&u, &u, &p, &tv1);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: tv1 failed"); goto cleanup; }

    /* tv2 = Z * tv1 mod p, Z=2 => tv2 = 2*tv1 mod p */
    rc = mp_addmod(&tv1, &tv1, &p, &tv2);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: tv2 failed"); goto cleanup; }

    /* denom = 1 + tv2 mod p */
    rc = mp_set(&tmp, 1);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: mp_set 1 failed"); goto cleanup; }
    rc = mp_addmod(&tmp, &tv2, &p, &denom);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: denom failed"); goto cleanup; }

    /* neg_a = (-A) mod p = p - A */
    rc = mp_set(&neg_a, A_DIGIT);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: mp_set A failed"); goto cleanup; }
    rc = mp_submod(&p, &neg_a, &p, &neg_a);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: neg_a failed"); goto cleanup; }

    if (mp_iszero(&denom) == MP_YES) {
        /* Special case: x1 = A */
        rc = mp_set(&x1, A_DIGIT);
        if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: mp_set x1=A failed"); goto cleanup; }
    } else {
        /* x1 = (-A) * inv(denom) mod p */
        rc = mp_invmod(&denom, &p, &t);
        if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: mp_invmod failed"); goto cleanup; }
        rc = mp_mulmod(&neg_a, &t, &p, &x1);
        if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: x1 mulmod failed"); goto cleanup; }
    }

    /* x1sq = x1^2 mod p */
    rc = mp_mulmod(&x1, &x1, &p, &x1sq);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: x1sq failed"); goto cleanup; }

    /* gx1 = x1^3 + A*x1^2 + x1 mod p
     *      = x1sq*x1 + A*x1sq + x1 */
    rc = mp_mulmod(&x1sq, &x1, &p, &gx1);   /* x1^3 */
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: gx1 x^3 failed"); goto cleanup; }

    rc = mp_set(&t, A_DIGIT);
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: mp_set A for gx1 failed"); goto cleanup; }
    rc = mp_mulmod(&t, &x1sq, &p, &t);      /* A*x1^2 */
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: A*x1sq failed"); goto cleanup; }
    rc = mp_addmod(&gx1, &t, &p, &gx1);     /* x1^3 + A*x1^2 */
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: gx1 +A*x1sq failed"); goto cleanup; }
    rc = mp_addmod(&gx1, &x1, &p, &gx1);   /* + x1 */
    if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: gx1 +x1 failed"); goto cleanup; }

    /* if gx1 is a quadratic residue: x = x1, else x = -A - x1 mod p */
    {
        int sq = is_square_gfp(&gx1, &p, &exp, &tmp);
        if (sq < 0) { set_wc_error(error, -1, "hash_to_curve: is_square failed"); goto cleanup; }
        if (sq) {
            rc = mp_copy(&x1, &x);
            if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: mp_copy x1 failed"); goto cleanup; }
        } else {
            /* x = -A - x1 mod p = (p - A - x1) mod p */
            /* neg_a is already p - A */
            rc = mp_submod(&neg_a, &x1, &p, &x);
            if (rc != 0) { set_wc_error(error, rc, "hash_to_curve: x2 submod failed"); goto cleanup; }
        }
    }

    /* Step 4: encode x as 32-byte little-endian */
    {
        guchar x_be[32];
        guchar* out_buf;
        int i;

        /* mp_to_unsigned_bin writes big-endian; we need little-endian */
        /* First get the big-endian bytes padded to 32 bytes */
        rc = mp_to_unsigned_bin_len(&x, x_be, 32);
        if (rc != 0) {
            set_wc_error(error, rc, "hash_to_curve: mp_to_unsigned_bin_len failed");
            goto cleanup;
        }

        out_buf = g_malloc(32);
        /* Reverse byte order: big-endian → little-endian */
        for (i = 0; i < 32; i++) {
            out_buf[i] = x_be[31 - i];
        }

        mp_clear(&p);
        mp_clear(&exp);
        mp_clear(&u);
        mp_clear(&tv1);
        mp_clear(&tv2);
        mp_clear(&denom);
        mp_clear(&x1);
        mp_clear(&x1sq);
        mp_clear(&gx1);
        mp_clear(&t);
        mp_clear(&x);
        mp_clear(&neg_a);
        mp_clear(&tmp);

        return new_bytes_take(out_buf, 32);
    }

cleanup:
    mp_clear(&p);
    mp_clear(&exp);
    mp_clear(&u);
    mp_clear(&tv1);
    mp_clear(&tv2);
    mp_clear(&denom);
    mp_clear(&x1);
    mp_clear(&x1sq);
    mp_clear(&gx1);
    mp_clear(&t);
    mp_clear(&x);
    mp_clear(&neg_a);
    mp_clear(&tmp);
    return NULL;
}
