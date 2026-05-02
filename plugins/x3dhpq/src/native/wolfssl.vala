namespace X3dhpq.Crypto {

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_random_bytes")]
public static extern Bytes random_bytes(size_t length) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_generate_x25519")]
public static extern void generate_x25519(out Bytes public_key, out Bytes private_key) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_x25519_shared_secret")]
public static extern Bytes x25519_shared_secret(Bytes private_key, Bytes public_key) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_generate_ed25519")]
public static extern void generate_ed25519(out Bytes public_key, out Bytes private_key) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_ed25519_sign")]
public static extern Bytes ed25519_sign(Bytes private_key, Bytes message) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_ed25519_verify")]
public static extern bool ed25519_verify(Bytes public_key, Bytes message, Bytes signature) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_generate_mldsa65")]
public static extern void generate_mldsa65(out Bytes public_key, out Bytes private_key) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_mldsa65_sign")]
public static extern Bytes mldsa65_sign(Bytes private_key, Bytes message) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_mldsa65_verify")]
public static extern bool mldsa65_verify(Bytes public_key, Bytes message, Bytes signature) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_generate_mlkem768")]
public static extern void generate_mlkem768(out Bytes public_key, out Bytes private_key) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_mlkem768_encapsulate")]
public static extern void mlkem768_encapsulate(Bytes public_key, out Bytes ciphertext, out Bytes shared_secret) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_mlkem768_decapsulate")]
public static extern Bytes mlkem768_decapsulate(Bytes private_key, Bytes ciphertext) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_hkdf_extract_sha512")]
public static extern Bytes hkdf_extract_sha512(Bytes salt, Bytes input_key_material) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_hkdf_expand_sha512")]
public static extern Bytes hkdf_expand_sha512(Bytes pseudorandom_key, Bytes info, size_t output_size) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_hmac_sha256")]
public static extern Bytes hmac_sha256(Bytes key, Bytes message) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_sha256")]
public static extern Bytes sha256(Bytes message) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_sha512")]
public static extern Bytes sha512(Bytes message) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_blake2b160")]
public static extern Bytes blake2b160(Bytes message) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_scrypt")]
public static extern Bytes scrypt(Bytes password, Bytes salt, uint64 cost, uint block_size, uint parallel, size_t output_size) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_aes256gcm_encrypt")]
public static extern Bytes aes256gcm_encrypt(Bytes key, Bytes nonce, Bytes plaintext, Bytes? aad = null) throws GLib.Error;

[CCode (cheader_filename = "native/wolfssl_helper.h", cname = "x3dhpq_wolfssl_aes256gcm_decrypt")]
public static extern Bytes aes256gcm_decrypt(Bytes key, Bytes nonce, Bytes ciphertext_and_tag, Bytes? aad = null) throws GLib.Error;

}
