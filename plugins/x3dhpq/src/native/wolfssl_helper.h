#ifndef DINO_X3DHPQ_WOLFSSL_HELPER_H
#define DINO_X3DHPQ_WOLFSSL_HELPER_H 1

#include <glib.h>

GQuark x3dhpq_wolfssl_error_quark(void);

GBytes* x3dhpq_wolfssl_random_bytes(gsize length, GError** error);
void x3dhpq_wolfssl_generate_x25519(GBytes** public_key, GBytes** private_key, GError** error);
GBytes* x3dhpq_wolfssl_x25519_shared_secret(GBytes* private_key, GBytes* public_key, GError** error);

void x3dhpq_wolfssl_generate_ed25519(GBytes** public_key, GBytes** private_key, GError** error);
GBytes* x3dhpq_wolfssl_ed25519_sign(GBytes* private_key, GBytes* message, GError** error);
gboolean x3dhpq_wolfssl_ed25519_verify(GBytes* public_key, GBytes* message, GBytes* signature, GError** error);

void x3dhpq_wolfssl_generate_mldsa65(GBytes** public_key, GBytes** private_key, GError** error);
GBytes* x3dhpq_wolfssl_mldsa65_sign(GBytes* private_key, GBytes* message, GError** error);
gboolean x3dhpq_wolfssl_mldsa65_verify(GBytes* public_key, GBytes* message, GBytes* signature, GError** error);

void x3dhpq_wolfssl_generate_mlkem768(GBytes** public_key, GBytes** private_key, GError** error);
void x3dhpq_wolfssl_mlkem768_encapsulate(GBytes* public_key, GBytes** ciphertext, GBytes** shared_secret, GError** error);
GBytes* x3dhpq_wolfssl_mlkem768_decapsulate(GBytes* private_key, GBytes* ciphertext, GError** error);

GBytes* x3dhpq_wolfssl_hkdf_extract_sha512(GBytes* salt, GBytes* input_key_material, GError** error);
GBytes* x3dhpq_wolfssl_hkdf_expand_sha512(GBytes* pseudorandom_key, GBytes* info, gsize output_size, GError** error);
GBytes* x3dhpq_wolfssl_hmac_sha256(GBytes* key, GBytes* message, GError** error);
GBytes* x3dhpq_wolfssl_sha256(GBytes* message, GError** error);
GBytes* x3dhpq_wolfssl_sha512(GBytes* message, GError** error);
GBytes* x3dhpq_wolfssl_blake2b160(GBytes* message, GError** error);
GBytes* x3dhpq_wolfssl_scrypt(GBytes* password, GBytes* salt, guint64 cost, guint block_size, guint parallel, gsize output_size, GError** error);

GBytes* x3dhpq_wolfssl_aes256gcm_encrypt(GBytes* key, GBytes* nonce, GBytes* plaintext, GBytes* aad, GError** error);
GBytes* x3dhpq_wolfssl_aes256gcm_decrypt(GBytes* key, GBytes* nonce, GBytes* ciphertext_and_tag, GBytes* aad, GError** error);

#endif
