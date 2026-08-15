using Gee;
using Xmpp;

namespace Dino.Plugins.X3dhpq.Protocol {

private const string INFO_X3DH = "X3DHPQ-X3DH-PQ-v0";
private const string INFO_ROOT_KEY = "X3DHPQ-RootKey-v0";
private const string INFO_MESSAGE_KEY = "X3DHPQ-MessageKey-v0";
private const string INFO_CHECKPOINT_CHAIN_SEND = "X3DHPQ-ChainSend-v1";
private const string INFO_CHECKPOINT_CHAIN_RECV = "X3DHPQ-ChainRecv-v1";
// These domain separators carry a trailing NUL (Go/Java pin
// "X3DHPQ-Checkpoint-Transcript-v1\0" (32) and "X3DHPQ-KEMHistory-v1\0" (21)).
// Vala's string.data / string_to_bytes DROPS a trailing \x00 (C terminator), so
// the label text is stored WITHOUT it here and the NUL is appended explicitly at
// use via label_with_nul() — otherwise Dino's KEM-checkpoint rekey would derive
// keys 1 byte of domain-sep short and diverge from other clients (§9).
private const string CHECKPOINT_TRANSCRIPT_LABEL = "X3DHPQ-Checkpoint-Transcript-v1";
private const string CHECKPOINT_HISTORY_LABEL = "X3DHPQ-KEMHistory-v1";

// Bound on the pairwise-ratchet skipped-message-key cache (spec §9.4.2),
// matching the Java/Go reference's MAX_SKIPPED. Named distinctly from
// senderchain.vala's (unrelated) MAX_SKIPPED, since Vala namespace-scope
// "private" consts are not file-scoped and would otherwise collide.
private const int PAIRWISE_MAX_SKIPPED = 1000;

// D3: "no checkpoint has been applied to the current chain yet".
public const uint32 CKPT_NONE = (uint32) 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// D1 (§9.1) — domain-separated pre-key signing input.
//
// Signing the naked key bytes covers neither the key id nor the key TYPE, so a
// relay can take a legitimately signed key and re-advertise it under a different
// <spk id=…>/<kemkey id=…>, or move an SPK into a KEM slot. The signature still
// verifies because it never said which slot the key was for. Binding type + id +
// length into the signed input closes both.
//
//   sig_input = "X3DHPQ-PreKeySig-v1\x00"   (20 bytes: 19 ASCII + one NUL)
//            || uint8  key_type
//            || uint32 key_id
//            || uint16 pub_len
//            || pub
//
// The label is built via label_with_nul() rather than baked into the literal —
// Vala's string.data drops a trailing \x00 (C terminator), which would silently
// make this implementation sign one byte of domain separator short.
// ---------------------------------------------------------------------------
public const string PREKEY_SIG_LABEL = "X3DHPQ-PreKeySig-v1";
public const uint8 PREKEY_TYPE_SPK = 0x01;      // X25519 signed pre-key, pub_len 32
public const uint8 PREKEY_TYPE_KEM = 0x02;      // ML-KEM-768 pre-key, pub_len 1184

public uint8[] prekey_sig_input(uint8 key_type, uint32 key_id, Bytes pub) {
    uint8[] pub_bytes = bytes_to_uint8_array(pub);
    return concat_four_byte_arrays(
        label_with_nul(PREKEY_SIG_LABEL),
        { key_type },
        uint32_to_bytes(key_id),
        concat_byte_arrays(uint16_to_bytes((uint16) pub_bytes.length), pub_bytes)
    );
}

public Bytes prekey_sig_message(uint8 key_type, uint32 key_id, Bytes pub) {
    return new Bytes(prekey_sig_input(key_type, key_id, pub));
}

public class DeviceCertificate : Object {
    public uint16 version { get; set; default = 1; }
    public uint32 device_id { get; set; }
    public Bytes dik_pub_ed25519 { get; set; }
    public Bytes dik_pub_x25519 { get; set; }
    public Bytes dik_pub_mldsa { get; set; }
    public int64 created_at { get; set; }
    public uint8 flags { get; set; }
    public Bytes signature { get; set; }
    public Bytes mldsa_signature { get; set; }

    public uint8[] signed_part() {
        return concat_four_byte_arrays(
            concat_byte_arrays(uint16_to_bytes(version), uint32_to_bytes(device_id)),
            concat_length_prefixed_bytes(bytes_to_uint8_array(dik_pub_ed25519)),
            concat_length_prefixed_bytes(bytes_to_uint8_array(dik_pub_x25519)),
            concat_byte_arrays(concat_length_prefixed_bytes(bytes_to_uint8_array(dik_pub_mldsa)), concat_byte_arrays(uint64_to_bytes((uint64) created_at), { flags }))
        );
    }

    public uint8[] marshal() {
        uint8[] signed = signed_part();
        return concat_three_byte_arrays(
            signed,
            concat_length_prefixed_bytes(bytes_to_uint8_array(signature)),
            concat_length_prefixed_bytes(bytes_to_uint8_array(mldsa_signature))
        );
    }

    public bool verify(Bytes aik_pub_ed25519, Bytes aik_pub_mldsa) throws GLib.Error {
        uint8[] signed = signed_part();
        return global::X3dhpq.Crypto.ed25519_verify(aik_pub_ed25519, new Bytes(signed), signature)
            && global::X3dhpq.Crypto.mldsa65_verify(aik_pub_mldsa, new Bytes(signed), mldsa_signature);
    }

    public static DeviceCertificate issue(
        uint32 device_id,
        Bytes dik_pub_ed25519,
        Bytes dik_pub_x25519,
        Bytes dik_pub_mldsa,
        Bytes aik_priv_ed25519,
        Bytes aik_priv_mldsa,
        uint8 flags
    ) throws GLib.Error {
        DeviceCertificate cert = new DeviceCertificate();
        cert.device_id = device_id;
        cert.dik_pub_ed25519 = dik_pub_ed25519;
        cert.dik_pub_x25519 = dik_pub_x25519;
        cert.dik_pub_mldsa = dik_pub_mldsa;
        cert.created_at = new DateTime.now_utc().to_unix();
        cert.flags = flags;
        uint8[] signed = cert.signed_part();
        cert.signature = global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed25519, new Bytes(signed));
        cert.mldsa_signature = global::X3dhpq.Crypto.mldsa65_sign(aik_priv_mldsa, new Bytes(signed));
        return cert;
    }

    public static DeviceCertificate? unmarshal(Bytes encoded) {
        uint8[] data = bytes_to_uint8_array(encoded);
        int offset = 0;
        if (data.length < 2 + 4) {
            return null;
        }

        DeviceCertificate cert = new DeviceCertificate();
        cert.version = uint16_from_bytes(data, offset);
        offset += 2;
        cert.device_id = uint32_from_bytes(data, offset);
        offset += 4;

        // Use the bool+out reader (not the nullable-return one) for the three
        // DIK fields: any of them may legitimately be empty (an Ed25519-only DIK
        // has no ML-DSA pub), and Vala coerces a returned zero-length array to
        // null, so read_length_prefixed_bytes()'s empty result is indistinguishable
        // from an underflow. read_length_prefixed_field keeps the empty case valid.
        uint8[] dik_ed;
        uint8[] dik_x;
        uint8[] dik_m;
        if (!read_length_prefixed_field(data, ref offset, out dik_ed)) return null;
        if (!read_length_prefixed_field(data, ref offset, out dik_x)) return null;
        if (!read_length_prefixed_field(data, ref offset, out dik_m)) return null;
        if (offset + 9 > data.length) {
            return null;
        }
        cert.dik_pub_ed25519 = new Bytes((owned) dik_ed);
        cert.dik_pub_x25519 = new Bytes((owned) dik_x);
        cert.dik_pub_mldsa = new Bytes((owned) dik_m);
        cert.created_at = int64_from_bytes(data, offset);
        offset += 8;
        cert.flags = data[offset++];

        uint8[]? sig = read_length_prefixed_bytes(data, ref offset);
        uint8[]? ml_sig = read_length_prefixed_bytes(data, ref offset);
        if (sig == null || ml_sig == null) {
            return null;
        }
        cert.signature = new Bytes((owned) sig);
        cert.mldsa_signature = new Bytes((owned) ml_sig);
        return cert;
    }
}

public class PublicPreKey : Object {
    public uint32 id { get; set; }
    public string public_base64 { get; set; }
    // KEM pre-keys carry a hybrid DIK signature over the public key (spec §9.1);
    // both remain null for OPKs, which are unsigned per X3DH convention.
    public string? signature_ed25519_base64 { get; set; default = null; }
    public string? signature_mldsa_base64 { get; set; default = null; }
}

public class PeerBundle : Object {
    public string bare_jid { get; set; }
    public uint32 device_id { get; set; }
    public string aik_pub_ed25519_base64 { get; set; }
    public string aik_pub_mldsa_base64 { get; set; }
    public DeviceCertificate device_certificate { get; set; }
    public string identity_pub_x25519_base64 { get; set; }
    public uint32 signed_pre_key_id { get; set; }
    public string signed_pre_key_base64 { get; set; }
    public string signed_pre_key_signature_base64 { get; set; }
    public ArrayList<PublicPreKey> kem_pre_keys { get; private set; default = new ArrayList<PublicPreKey>(); }
    public ArrayList<PublicPreKey> one_time_pre_keys { get; private set; default = new ArrayList<PublicPreKey>(); }

    public bool verify() {
        // Any crypto/verification failure means "untrusted", so return false
        // rather than throwing. wolfSSL raises SIG_VERIFY_E on a forged (but
        // well-formed) signature, and malformed base64 also throws; either way
        // the bundle must be rejected, not propagated as an error to callers.
        try {
            bool cert_ok = device_certificate.verify(
                bytes_from_base64(aik_pub_ed25519_base64),
                bytes_from_base64(aik_pub_mldsa_base64)
            );
            if (!cert_ok) {
                return false;
            }
            // D1: the SPK signature is over the domain-separated input, not the
            // naked 32-byte key, so the id and the key type are covered too.
            Bytes spk_pub = bytes_from_base64(signed_pre_key_base64);
            bool spk_ok = global::X3dhpq.Crypto.ed25519_verify(
                device_certificate.dik_pub_ed25519,
                prekey_sig_message(PREKEY_TYPE_SPK, signed_pre_key_id, spk_pub),
                bytes_from_base64(signed_pre_key_signature_base64)
            );
            if (!spk_ok) {
                return false;
            }
            // Verify the hybrid DIK signature on EVERY KEM pre-key (spec §9.1).
            //
            // §9.1 is unconditional: both signatures MUST verify, and "a bundle
            // offering no validly-signed KEM pre-key MUST be rejected". The previous
            // transitional stance — skip verification when the signatures are absent —
            // was not a compatibility shim but a downgrade oracle. The KEM pre-key is
            // the sole carrier of post-quantum (HNDL) confidentiality, so an attacker
            // who strips the signature elements in transit gets an unverified KEM
            // pre-key accepted and can substitute one whose secret they hold, defeating
            // the ML-KEM encapsulation entirely. The `||` test made it worse: with only
            // ONE half missing it skipped BOTH checks, so removing just the ML-DSA
            // signature also bypassed the Ed25519 one.
            if (kem_pre_keys.size == 0) {
                return false;
            }
            foreach (PublicPreKey kem in kem_pre_keys) {
                if (kem.signature_ed25519_base64 == null || kem.signature_ed25519_base64 == ""
                        || kem.signature_mldsa_base64 == null || kem.signature_mldsa_base64 == "") {
                    return false;
                }
                Bytes kem_pub = bytes_from_base64(kem.public_base64);
                // D1: same domain-separated input, key_type 0x02, bound to THIS
                // key's advertised id — relabelling a validly signed KEM pre-key
                // now invalidates both halves of the hybrid signature.
                Bytes kem_msg = prekey_sig_message(PREKEY_TYPE_KEM, kem.id, kem_pub);
                if (!global::X3dhpq.Crypto.ed25519_verify(
                        device_certificate.dik_pub_ed25519,
                        kem_msg,
                        bytes_from_base64((!) kem.signature_ed25519_base64))) {
                    return false;
                }
                if (!global::X3dhpq.Crypto.mldsa65_verify(
                        device_certificate.dik_pub_mldsa,
                        kem_msg,
                        bytes_from_base64((!) kem.signature_mldsa_base64))) {
                    return false;
                }
            }
            return true;
        } catch (GLib.Error e) {
            return false;
        }
    }
}

public class MessageHeader : Object {
    public Bytes dh_pub { get; set; }
    public uint32 prev_chain_len { get; set; }
    public uint32 n { get; set; }
    public Bytes? kem_ciphertext { get; set; }
    public Bytes? kem_pub_for_reply { get; set; }
    // D3.1: the chain index at which the sender last applied a checkpoint to its
    // CURRENT send chain, NOT counting a checkpoint carried by this very message,
    // or CKPT_NONE if no checkpoint has been applied since that chain began.
    //
    // It exists because a post-checkpoint message that overtakes the
    // checkpoint-bearing one leaves the receiver silently on the pre-checkpoint
    // chain: what is missing is a STATE TRANSITION, not a chain step, so the
    // skipped-key cache cannot recover it and the receiver just derives the wrong
    // key. Carrying the last-applied index lets the receiver notice and defer.
    public uint32 ckpt_n { get; set; default = CKPT_NONE; }

    // On-wire binary format matching internal/x3dhpqcrypto/header.go:Marshal.
    // Each field is 4-byte big-endian length followed by `length` bytes; nil/empty
    // fields are encoded as length=0. The two uint32 fields (prev_chain_len, n)
    // are themselves length-prefixed with len=4 then the 4-byte BE value.
    //
    // Earlier this used a Vala-private "key=value\n" text format, which broke
    // interop with Conversations and the Go reference and caused remote OOM
    // crashes because the receiver tried to allocate buffers sized by random
    // bytes from the text payload.
    public Bytes marshal() {
        uint8[] dh = bytes_to_uint8_array(dh_pub);
        uint8[] kct = kem_ciphertext != null ? bytes_to_uint8_array((!) kem_ciphertext) : new uint8[0];
        uint8[] kpr = kem_pub_for_reply != null ? bytes_to_uint8_array((!) kem_pub_for_reply) : new uint8[0];

        uint8[] buf = new uint8[0];
        buf = concat_byte_arrays(buf, length_prefixed(dh));
        buf = concat_byte_arrays(buf, u32_field(prev_chain_len));
        buf = concat_byte_arrays(buf, u32_field(n));
        buf = concat_byte_arrays(buf, length_prefixed(kct));
        buf = concat_byte_arrays(buf, length_prefixed(kpr));
        // D3.1: sixth field, encoded exactly like prev_chain_len / n.
        buf = concat_byte_arrays(buf, u32_field(ckpt_n));
        return new Bytes(buf);
    }

    public static MessageHeader? unmarshal(Bytes bytes) {
        uint8[] data = bytes_to_uint8_array(bytes);
        int off = 0;

        // read_field distinguishes "absent/short" from "present but empty" via the
        // offset, since Vala coerces a returned zero-length array to null; track the
        // failure explicitly instead so a truncated header can never be mistaken for
        // one carrying an empty optional field.
        bool ok = true;
        uint8[] dh = read_field_checked(data, ref off, ref ok);
        if (!ok) return null;
        uint32? pcl = read_u32_field(data, ref off);
        if (pcl == null) return null;
        uint32? nn = read_u32_field(data, ref off);
        if (nn == null) return null;
        uint8[] kct = read_field_checked(data, ref off, ref ok);
        if (!ok) return null;
        uint8[] kpr = read_field_checked(data, ref off, ref ok);
        if (!ok) return null;
        // D3.1: "A header that ends after five fields MUST be rejected." Without
        // CkptN the receiver cannot detect a missing checkpoint transition at all,
        // so accepting a short header would silently reinstate the defect.
        uint32? ckpt = read_u32_field(data, ref off);
        if (ckpt == null) return null;

        MessageHeader header = new MessageHeader();
        header.dh_pub = new Bytes(dh);
        header.prev_chain_len = (!) pcl;
        header.n = (!) nn;
        header.kem_ciphertext = kct.length > 0 ? new Bytes(kct) : null;
        header.kem_pub_for_reply = kpr.length > 0 ? new Bytes(kpr) : null;
        header.ckpt_n = (!) ckpt;
        return header;
    }

    // ----- binary helpers -----

    private static uint8[] u32_be(uint32 v) {
        return { (uint8)(v >> 24), (uint8)(v >> 16), (uint8)(v >> 8), (uint8) v };
    }

    private static uint8[] length_prefixed(uint8[] payload) {
        uint8[] header = u32_be((uint32) payload.length);
        return concat_byte_arrays(header, payload);
    }

    private static uint8[] u32_field(uint32 v) {
        // length=4 prefix, then the 4-byte uint32 value (mirrors Go's marshalU32)
        uint8[] buf = new uint8[8];
        buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 4;
        buf[4] = (uint8)(v >> 24);
        buf[5] = (uint8)(v >> 16);
        buf[6] = (uint8)(v >> 8);
        buf[7] = (uint8) v;
        return buf;
    }

    // Reads one length-prefixed field. Success is reported through `ok` rather
    // than through the return value: a legitimately EMPTY field (length 0) is
    // valid here, and Vala coerces a returned zero-length array to null, so a
    // nullable return cannot tell "empty" from "truncated". Conflating the two is
    // how a truncated header used to be accepted as one with absent optionals.
    private static uint8[] read_field_checked(uint8[] data, ref int off, ref bool ok) {
        if (!ok) return new uint8[0];
        if (off + 4 > data.length) { ok = false; return new uint8[0]; }
        uint32 len = ((uint32) data[off] << 24)
                   | ((uint32) data[off + 1] << 16)
                   | ((uint32) data[off + 2] << 8)
                   | (uint32) data[off + 3];
        off += 4;
        if (len > 65536) { ok = false; return new uint8[0]; }  // MAX_FIELD_LEN guard
        if ((int64) off + (int64) len > (int64) data.length) { ok = false; return new uint8[0]; }
        if (len == 0) return new uint8[0];
        uint8[] payload = new uint8[len];
        Memory.copy(payload, (uint8*) data + off, len);
        off += (int) len;
        return payload;
    }

    private static uint32? read_u32_field(uint8[] data, ref int off) {
        bool ok = true;
        uint8[] f = read_field_checked(data, ref off, ref ok);
        if (!ok || f.length != 4) return null;
        return ((uint32) f[0] << 24)
             | ((uint32) f[1] << 16)
             | ((uint32) f[2] << 8)
             | (uint32) f[3];
    }
}

public class SessionState : Object {
    public Bytes rk { get; set; }
    public Bytes? chain_send_key { get; set; }
    public Bytes? chain_recv_key { get; set; }
    public Bytes sending_dh_pub { get; set; }
    public Bytes sending_dh_priv { get; set; }
    public Bytes? remote_dh_pub { get; set; }
    public uint32 send_count { get; set; }
    public uint32 recv_count { get; set; }
    public uint32 prev_send_count { get; set; }
    public Bytes? kem_send_pub { get; set; }
    public Bytes? kem_recv_priv { get; set; }
    public Bytes? kem_recv_pub { get; set; }
    // The KEM reply private key this session advertised BEFORE its last outgoing
    // checkpoint rotated it.
    //
    // Needed for crossed checkpoints (D2): if Bob checkpoints — which mints him a
    // fresh reply keypair — before Alice's own checkpoint, encapsulated to Bob's
    // PREVIOUS reply key, reaches him, then dropping the old private key makes
    // Alice's checkpoint permanently undecryptable and the session dies. ML-KEM
    // decapsulation uses implicit rejection, so the wrong key yields a pseudorandom
    // shared secret rather than an error, and the failure only surfaces as a bogus
    // AEAD tag. Keeping exactly one generation back is enough: a checkpoint is only
    // ever encapsulated to the most recently advertised reply key.
    public Bytes? kem_recv_priv_prev { get; set; }
    public uint32 kem_since_checkpoint { get; set; }
    public int64 last_checkpoint_time { get; set; }
    public Bytes ad { get; set; }

    // D2 (§9.3): ONE accumulator per direction, never mixed.
    //
    // A single shared accumulator folded as H' = SHA-512(label || H || ss || t)[:32]
    // is not commutative, so two sides that checkpoint at about the same time fold
    // the same two checkpoints in opposite orders and end up with different values.
    // The next DH ratchet consumes dh_out || KEMHistory, so the two sides then derive
    // different root keys and the session breaks with no attacker involved. Each
    // DIRECTION's checkpoint stream is already totally ordered by its own message
    // chain, so keeping them apart removes the ordering dependency entirely.
    public Bytes kem_history_send { get; set; }   // folds checkpoints WE send
    public Bytes kem_history_recv { get; set; }   // folds checkpoints WE receive

    // D3.2 / D3.3: last checkpoint index applied to the current send / recv chain,
    // CKPT_NONE when the chain has had none. Both reset to CKPT_NONE on every DH
    // ratchet, because a new chain starts with no checkpoints.
    public uint32 send_ckpt_n { get; set; default = CKPT_NONE; }
    public uint32 recv_ckpt_n { get; set; default = CKPT_NONE; }

    // Skipped receive-chain message keys, cached for out-of-order delivery
    // (spec §9.4.2). Keyed by skipped_key_string(remote dh pub, chain index),
    // bounded at PAIRWISE_MAX_SKIPPED entries with oldest-first eviction;
    // skipped_order tracks insertion order so eviction and serialization
    // stay deterministic.
    public HashMap<string, Bytes> skipped_keys { get; private set; default = new HashMap<string, Bytes>(); }
    public ArrayList<string> skipped_order { get; private set; default = new ArrayList<string>(); }

    public string serialize() {
        StringBuilder builder = new StringBuilder();
        append_serialized(builder, "rk", bytes_to_base64(rk));
        append_serialized(builder, "chain_send_key", chain_send_key != null ? bytes_to_base64((!) chain_send_key) : "");
        append_serialized(builder, "chain_recv_key", chain_recv_key != null ? bytes_to_base64((!) chain_recv_key) : "");
        append_serialized(builder, "sending_dh_pub", bytes_to_base64(sending_dh_pub));
        append_serialized(builder, "sending_dh_priv", bytes_to_base64(sending_dh_priv));
        append_serialized(builder, "remote_dh_pub", remote_dh_pub != null ? bytes_to_base64((!) remote_dh_pub) : "");
        append_serialized(builder, "send_count", send_count.to_string());
        append_serialized(builder, "recv_count", recv_count.to_string());
        append_serialized(builder, "prev_send_count", prev_send_count.to_string());
        append_serialized(builder, "kem_send_pub", kem_send_pub != null ? bytes_to_base64((!) kem_send_pub) : "");
        append_serialized(builder, "kem_recv_priv", kem_recv_priv != null ? bytes_to_base64((!) kem_recv_priv) : "");
        append_serialized(builder, "kem_recv_pub", kem_recv_pub != null ? bytes_to_base64((!) kem_recv_pub) : "");
        append_serialized(builder, "kem_recv_priv_prev", kem_recv_priv_prev != null ? bytes_to_base64((!) kem_recv_priv_prev) : "");
        append_serialized(builder, "kem_since_checkpoint", kem_since_checkpoint.to_string());
        append_serialized(builder, "last_checkpoint_time", last_checkpoint_time.to_string());
        append_serialized(builder, "ad", bytes_to_base64(ad));
        // D2/D3: the single `kem_history` field is GONE. Its absence is what makes
        // deserialize() reject a pre-D2 blob outright (see there) instead of
        // half-loading a session whose two accumulators would then be wrong.
        append_serialized(builder, "kem_history_send", bytes_to_base64(kem_history_send));
        append_serialized(builder, "kem_history_recv", bytes_to_base64(kem_history_recv));
        append_serialized(builder, "send_ckpt_n", send_ckpt_n.to_string());
        append_serialized(builder, "recv_ckpt_n", recv_ckpt_n.to_string());

        StringBuilder skipped_builder = new StringBuilder();
        bool skipped_first = true;
        foreach (string key in skipped_order) {
            if (!skipped_first) {
                skipped_builder.append(";");
            }
            skipped_first = false;
            skipped_builder.append(key);
            skipped_builder.append(",");
            skipped_builder.append(bytes_to_base64(skipped_keys[key]));
        }
        append_serialized(builder, "skipped_keys", skipped_builder.str);
        return builder.str;
    }

    public static SessionState? deserialize(string encoded) {
        HashMap<string, string> values = new HashMap<string, string>();
        foreach (string line in encoded.split("\n")) {
            if (line == "" || !line.contains("=")) {
                continue;
            }
            string[] parts = line.split("=", 2);
            values[parts[0]] = parts[1];
        }
        // D2: a blob written before the KEMHistory split carries a single
        // `kem_history` and no per-direction accumulators. It MUST be DISCARDED,
        // not migrated: there is no way to know which of the two streams the one
        // value folded, and guessing produces a session that derives wrong root
        // keys at the next ratchet. Returning null makes the caller drop the
        // stored session and renegotiate — the existing unparseable-blob path.
        if (!values.has_key("rk") || !values.has_key("sending_dh_pub") || !values.has_key("sending_dh_priv")
                || !values.has_key("ad")
                || !values.has_key("kem_history_send") || !values.has_key("kem_history_recv")
                || !values.has_key("send_ckpt_n") || !values.has_key("recv_ckpt_n")) {
            return null;
        }
        SessionState state = new SessionState();
        state.rk = bytes_from_base64(values["rk"]);
        state.chain_send_key = values["chain_send_key"] != "" ? bytes_from_base64(values["chain_send_key"]) : null;
        state.chain_recv_key = values["chain_recv_key"] != "" ? bytes_from_base64(values["chain_recv_key"]) : null;
        state.sending_dh_pub = bytes_from_base64(values["sending_dh_pub"]);
        state.sending_dh_priv = bytes_from_base64(values["sending_dh_priv"]);
        state.remote_dh_pub = values["remote_dh_pub"] != "" ? bytes_from_base64(values["remote_dh_pub"]) : null;
        state.send_count = (uint32) int.parse(values["send_count"]);
        state.recv_count = (uint32) int.parse(values["recv_count"]);
        state.prev_send_count = (uint32) int.parse(values["prev_send_count"]);
        state.kem_send_pub = values["kem_send_pub"] != "" ? bytes_from_base64(values["kem_send_pub"]) : null;
        state.kem_recv_priv = values["kem_recv_priv"] != "" ? bytes_from_base64(values["kem_recv_priv"]) : null;
        state.kem_recv_pub = values["kem_recv_pub"] != "" ? bytes_from_base64(values["kem_recv_pub"]) : null;
        state.kem_recv_priv_prev = (values.has_key("kem_recv_priv_prev") && values["kem_recv_priv_prev"] != "")
            ? bytes_from_base64(values["kem_recv_priv_prev"]) : null;
        state.kem_since_checkpoint = (uint32) int.parse(values["kem_since_checkpoint"]);
        state.last_checkpoint_time = int64.parse(values["last_checkpoint_time"]);
        state.ad = bytes_from_base64(values["ad"]);
        state.kem_history_send = bytes_from_base64(values["kem_history_send"]);
        state.kem_history_recv = bytes_from_base64(values["kem_history_recv"]);
        state.send_ckpt_n = (uint32) uint64.parse(values["send_ckpt_n"]);
        state.recv_ckpt_n = (uint32) uint64.parse(values["recv_ckpt_n"]);

        // "skipped_keys" is optional so blobs serialized before this field was
        // introduced still deserialize (with an empty skipped-key cache).
        string skipped_blob = values.has_key("skipped_keys") ? values["skipped_keys"] : "";
        if (skipped_blob != "") {
            foreach (string entry in skipped_blob.split(";")) {
                if (entry == "") {
                    continue;
                }
                string[] parts = entry.split(",", 2);
                if (parts.length != 2) {
                    continue;
                }
                state.skipped_keys[parts[0]] = bytes_from_base64(parts[1]);
                state.skipped_order.add(parts[0]);
            }
        }
        return state;
    }

    // D3.5: an independent copy of every field decryption may touch. Decryption
    // runs against a clone and the result is adopted only once the AEAD tag has
    // verified, so a forged or corrupt ciphertext cannot advance chain keys,
    // recv_ckpt_n, either accumulator or the skipped-key cache. Bytes is
    // immutable, so sharing the references is safe; the two collections are
    // copied because they are mutated in place.
    public SessionState clone() {
        SessionState c = new SessionState();
        c.rk = rk;
        c.chain_send_key = chain_send_key;
        c.chain_recv_key = chain_recv_key;
        c.sending_dh_pub = sending_dh_pub;
        c.sending_dh_priv = sending_dh_priv;
        c.remote_dh_pub = remote_dh_pub;
        c.send_count = send_count;
        c.recv_count = recv_count;
        c.prev_send_count = prev_send_count;
        c.kem_send_pub = kem_send_pub;
        c.kem_recv_priv = kem_recv_priv;
        c.kem_recv_pub = kem_recv_pub;
        c.kem_recv_priv_prev = kem_recv_priv_prev;
        c.kem_since_checkpoint = kem_since_checkpoint;
        c.last_checkpoint_time = last_checkpoint_time;
        c.ad = ad;
        c.kem_history_send = kem_history_send;
        c.kem_history_recv = kem_history_recv;
        c.send_ckpt_n = send_ckpt_n;
        c.recv_ckpt_n = recv_ckpt_n;
        foreach (string k in skipped_order) {
            c.skipped_keys[k] = skipped_keys[k];
            c.skipped_order.add(k);
        }
        return c;
    }

    // Overwrite this state with `other` (the commit half of clone()).
    public void adopt(SessionState other) {
        rk = other.rk;
        chain_send_key = other.chain_send_key;
        chain_recv_key = other.chain_recv_key;
        sending_dh_pub = other.sending_dh_pub;
        sending_dh_priv = other.sending_dh_priv;
        remote_dh_pub = other.remote_dh_pub;
        send_count = other.send_count;
        recv_count = other.recv_count;
        prev_send_count = other.prev_send_count;
        kem_send_pub = other.kem_send_pub;
        kem_recv_priv = other.kem_recv_priv;
        kem_recv_pub = other.kem_recv_pub;
        kem_recv_priv_prev = other.kem_recv_priv_prev;
        kem_since_checkpoint = other.kem_since_checkpoint;
        last_checkpoint_time = other.last_checkpoint_time;
        ad = other.ad;
        kem_history_send = other.kem_history_send;
        kem_history_recv = other.kem_history_recv;
        send_ckpt_n = other.send_ckpt_n;
        recv_ckpt_n = other.recv_ckpt_n;
        skipped_keys.clear();
        skipped_order.clear();
        foreach (string k in other.skipped_order) {
            skipped_keys[k] = other.skipped_keys[k];
            skipped_order.add(k);
        }
    }
}

// D3.3: a message that cannot be processed until a checkpoint state transition
// we have not seen arrives. NOT a decryption failure — the caller must queue the
// message (D3.4) and retry it, and must not report it to the user or tear the
// session down.
public errordomain PairwiseSessionError {
    CHECKPOINT_DEFERRED,
}

public class SessionBootstrap : Object {
    public SessionState state { get; set; }
    public Bytes? prekey_ephemeral_pub { get; set; }
    public uint32 opk_id { get; set; }
    public uint32 kem_key_id { get; set; }
    public Bytes? kem_ciphertext { get; set; }
}

public SessionBootstrap initiate_session(
    Bytes my_dik_priv_x25519,
    Bytes my_dik_pub_x25519,
    PeerBundle peer_bundle
) throws GLib.Error {
    Bytes eph_pub;
    Bytes eph_priv;
    global::X3dhpq.Crypto.generate_x25519(out eph_pub, out eph_priv);

    // A KEM pre-key is mandatory for PQXDH. Guard the indexed access: a bundle with
    // an empty kem_pre_keys list (stale/incomplete, e.g. a sibling device whose
    // bundle wasn't fully (re)published after an account reset) must NOT hard-abort
    // the process with a Gee ArrayList index assertion. Throwing lets the caller
    // (publish_device_tracker) warn + skip that device — otherwise the reset leaves
    // such a bundle in x3dhpq.db and every startup re-crashes until the db is wiped.
    if (peer_bundle.kem_pre_keys.size == 0) {
        throw new IOError.FAILED("initiate_session: peer bundle has no KEM pre-keys");
    }
    PublicPreKey kem_pre_key = peer_bundle.kem_pre_keys[0];
    PublicPreKey? opk = peer_bundle.one_time_pre_keys.size > 0 ? peer_bundle.one_time_pre_keys[0] : null;

    Bytes dh1 = global::X3dhpq.Crypto.x25519_shared_secret(my_dik_priv_x25519, bytes_from_base64(peer_bundle.signed_pre_key_base64));
    Bytes dh2 = global::X3dhpq.Crypto.x25519_shared_secret(eph_priv, bytes_from_base64(peer_bundle.identity_pub_x25519_base64));
    Bytes dh3 = global::X3dhpq.Crypto.x25519_shared_secret(eph_priv, bytes_from_base64(peer_bundle.signed_pre_key_base64));
    uint8[] material = concat_three_byte_arrays(bytes_to_uint8_array(dh1), bytes_to_uint8_array(dh2), bytes_to_uint8_array(dh3));

    uint32 opk_id = 0;
    if (opk != null) {
        material = concat_byte_arrays(material, bytes_to_uint8_array(global::X3dhpq.Crypto.x25519_shared_secret(eph_priv, bytes_from_base64(((!) opk).public_base64))));
        opk_id = ((!) opk).id;
    }

    Bytes kem_ct;
    Bytes kem_ss;
    global::X3dhpq.Crypto.mlkem768_encapsulate(bytes_from_base64(kem_pre_key.public_base64), out kem_ct, out kem_ss);
    material = concat_byte_arrays(material, bytes_to_uint8_array(kem_ss));

    Bytes root_material = hkdf64(new Bytes(new uint8[64]), new Bytes(material), INFO_X3DH);
    SessionState state = new_sending_state(root_material, concat_byte_arrays(bytes_to_uint8_array(my_dik_pub_x25519), bytes_to_uint8_array(bytes_from_base64(peer_bundle.identity_pub_x25519_base64))), bytes_from_base64(peer_bundle.signed_pre_key_base64));
    initialize_kem_reply_state(state);

    SessionBootstrap bootstrap = new SessionBootstrap();
    bootstrap.state = state;
    bootstrap.prekey_ephemeral_pub = eph_pub;
    bootstrap.opk_id = opk_id;
    bootstrap.kem_key_id = kem_pre_key.id;
    bootstrap.kem_ciphertext = kem_ct;
    return bootstrap;
}

public SessionState respond_session(
    Bytes my_dik_priv_x25519,
    Bytes my_dik_pub_x25519,
    Bytes my_spk_priv,
    Bytes my_spk_pub,
    Bytes? my_opk_priv,
    Bytes my_kem_priv,
    DeviceCertificate peer_certificate,
    Bytes peer_aik_pub_ed25519,
    Bytes peer_aik_pub_mldsa,
    Bytes peer_eph_pub,
    Bytes kem_ciphertext
) throws GLib.Error {
    if (!peer_certificate.verify(peer_aik_pub_ed25519, peer_aik_pub_mldsa)) {
        throw new IOError.FAILED("Peer device certificate verification failed");
    }

    Bytes dh1 = global::X3dhpq.Crypto.x25519_shared_secret(my_spk_priv, peer_certificate.dik_pub_x25519);
    Bytes dh2 = global::X3dhpq.Crypto.x25519_shared_secret(my_dik_priv_x25519, peer_eph_pub);
    Bytes dh3 = global::X3dhpq.Crypto.x25519_shared_secret(my_spk_priv, peer_eph_pub);
    uint8[] material = concat_three_byte_arrays(bytes_to_uint8_array(dh1), bytes_to_uint8_array(dh2), bytes_to_uint8_array(dh3));
    if (my_opk_priv != null) {
        material = concat_byte_arrays(material, bytes_to_uint8_array(global::X3dhpq.Crypto.x25519_shared_secret((!) my_opk_priv, peer_eph_pub)));
    }
    material = concat_byte_arrays(material, bytes_to_uint8_array(global::X3dhpq.Crypto.mlkem768_decapsulate(my_kem_priv, kem_ciphertext)));

    Bytes root_material = hkdf64(new Bytes(new uint8[64]), new Bytes(material), INFO_X3DH);
    SessionState state = new_receiving_state(
        root_material,
        concat_byte_arrays(bytes_to_uint8_array(peer_certificate.dik_pub_x25519), bytes_to_uint8_array(my_dik_pub_x25519)),
        my_spk_pub,
        my_spk_priv
    );
    initialize_kem_reply_state(state);
    return state;
}

public void initialize_kem_reply_state(SessionState state) throws GLib.Error {
    Bytes kem_pub;
    Bytes kem_priv;
    global::X3dhpq.Crypto.generate_mlkem768(out kem_pub, out kem_priv);
    state.kem_recv_pub = kem_pub;
    state.kem_recv_priv = kem_priv;
}

public SessionState new_sending_state(Bytes root_material, uint8[] ad, Bytes peer_dh_pub) throws GLib.Error {
    Bytes send_pub;
    Bytes send_priv;
    global::X3dhpq.Crypto.generate_x25519(out send_pub, out send_priv);

    Bytes rk = slice_bytes(root_material, 0, 32);
    Bytes new_rk;
    Bytes send_ck;
    // D2: this step derives the SEND chain, so it folds kemHistorySend — which is
    // 32 zero bytes at session creation.
    dh_ratchet_step(rk, send_priv, peer_dh_pub, new Bytes(new uint8[32]), out new_rk, out send_ck);

    SessionState state = new SessionState();
    state.rk = new_rk;
    state.chain_send_key = send_ck;
    state.chain_recv_key = null;
    state.sending_dh_pub = send_pub;
    state.sending_dh_priv = send_priv;
    state.remote_dh_pub = peer_dh_pub;
    state.send_count = 0;
    state.recv_count = 0;
    state.prev_send_count = 0;
    state.kem_since_checkpoint = 0;
    state.last_checkpoint_time = new DateTime.now_utc().to_unix();
    state.ad = new Bytes(ad);
    state.kem_history_send = new Bytes(new uint8[32]);
    state.kem_history_recv = new Bytes(new uint8[32]);
    state.send_ckpt_n = CKPT_NONE;
    state.recv_ckpt_n = CKPT_NONE;
    return state;
}

public SessionState new_receiving_state(Bytes root_material, uint8[] ad, Bytes my_dh_pub, Bytes my_dh_priv) {
    SessionState state = new SessionState();
    state.rk = slice_bytes(root_material, 0, 32);
    state.chain_send_key = null;
    state.chain_recv_key = slice_bytes(root_material, 32, 32);
    state.sending_dh_pub = my_dh_pub;
    state.sending_dh_priv = my_dh_priv;
    state.remote_dh_pub = null;
    state.send_count = 0;
    state.recv_count = 0;
    state.prev_send_count = 0;
    state.kem_since_checkpoint = 0;
    state.last_checkpoint_time = new DateTime.now_utc().to_unix();
    state.ad = new Bytes(ad);
    state.kem_history_send = new Bytes(new uint8[32]);
    state.kem_history_recv = new Bytes(new uint8[32]);
    state.send_ckpt_n = CKPT_NONE;
    state.recv_ckpt_n = CKPT_NONE;
    return state;
}

public void encrypt_transport_key(SessionState state, Bytes transport_key, out MessageHeader header, out Bytes ciphertext) throws GLib.Error {
    header = new MessageHeader();
    header.dh_pub = state.sending_dh_pub;
    header.prev_chain_len = state.prev_send_count;
    header.n = state.send_count;
    header.kem_ciphertext = null;
    header.kem_pub_for_reply = state.kem_recv_pub;
    // D3.2 step 1: stamp the value from BEFORE this message's own checkpoint. A
    // checkpoint carried by this very message must not be advertised as already
    // applied — the receiver applies it while processing this message.
    header.ckpt_n = state.send_ckpt_n;

    // The checkpoint mix MUST happen BEFORE deriving this message's key, so the checkpoint
    // message itself is protected under the post-mix chain (spec §5.3; matches the Java/Go
    // reference and this file's own decrypt path). Deriving the key first, as an earlier
    // version did, made a checkpoint message use the PRE-mix chain while the receiver used
    // the post-mix chain — so a live count-triggered checkpoint never decrypted, even
    // Dino↔Dino. No live roundtrip exercised it, so the canned single-message KAT missed it.
    if (state.kem_send_pub != null && should_do_checkpoint(state)) {
        Bytes kem_ct;
        Bytes kem_ss;
        global::X3dhpq.Crypto.mlkem768_encapsulate((!) state.kem_send_pub, out kem_ct, out kem_ss);
        Bytes new_cks;
        Bytes new_ckr;
        Bytes new_history;
        // Unidirectional checkpoint (§5.3): mix into the SEND chain only. Rewriting the
        // recv chain here would destroy the key for any opposite-direction message still in
        // flight and never derived — the skipped-key cache cannot recover it. new_ckr is
        // therefore discarded; the receiver mixes into its matching recv chain instead.
        //
        // D2: this checkpoint belongs to OUR send stream, so it folds into
        // kemHistorySend and never touches kemHistoryRecv.
        kem_checkpoint_mix((!) state.chain_send_key, kem_ss, state.sending_dh_pub, kem_ct, state.send_count, state.kem_history_send, out new_cks, out new_ckr, out new_history);
        state.chain_send_key = new_cks;
        state.kem_history_send = new_history;
        state.kem_since_checkpoint = 0;
        state.last_checkpoint_time = new DateTime.now_utc().to_unix();
        // D3.2 step 2: record the index this checkpoint was applied at, AFTER the
        // header has already been stamped with the previous value.
        state.send_ckpt_n = state.send_count;
        Bytes new_pub;
        Bytes new_priv;
        global::X3dhpq.Crypto.generate_mlkem768(out new_pub, out new_priv);
        // Retain one generation: an opposite-direction checkpoint may already be in
        // flight, encapsulated to the key we are replacing here (D2 crossed case).
        state.kem_recv_priv_prev = state.kem_recv_priv;
        state.kem_recv_pub = new_pub;
        state.kem_recv_priv = new_priv;
        header.kem_ciphertext = kem_ct;
        header.kem_pub_for_reply = new_pub;
    }

    Bytes mk;
    Bytes next_ck;
    chain_step((!) state.chain_send_key, out mk, out next_ck);
    state.chain_send_key = next_ck;

    Bytes aes_key;
    Bytes nonce;
    derive_message_key(mk, out aes_key, out nonce);
    ciphertext = global::X3dhpq.Crypto.aes256gcm_encrypt(aes_key, nonce, transport_key, new Bytes(concat_byte_arrays(bytes_to_uint8_array(state.ad), bytes_to_uint8_array(header.marshal()))));
    state.send_count++;
    state.kem_since_checkpoint++;
}

// D3.5: decryption is TRANSACTIONAL. Every mutation runs against a private
// snapshot and is adopted into the caller's state only once the AEAD tag has
// verified. A message that fails to authenticate — forged, tampered, a duplicate
// whose index was already consumed — therefore leaves chain keys, recv_ckpt_n,
// both KEMHistory accumulators and the skipped-key cache exactly as they were.
// Without this, anyone able to place one stanza in front of the receiver could
// permanently desynchronise the session by making it ratchet on a bad message.
//
// `applied_transition` reports whether this message advanced a DH ratchet or
// applied a checkpoint, i.e. whether the caller should now drain its deferral
// queue (D3.4).
public Bytes decrypt_transport_key(SessionState state, MessageHeader header, Bytes ciphertext) throws GLib.Error {
    bool ignored;
    return decrypt_transport_key_ex(state, header, ciphertext, out ignored);
}

public Bytes decrypt_transport_key_ex(SessionState state, MessageHeader header, Bytes ciphertext,
                                      out bool applied_transition) throws GLib.Error {
    SessionState work = state.clone();
    bool transitioned = false;
    Bytes result;
    try {
        result = decrypt_transport_key_into(work, header, ciphertext, false, out transitioned);
    } catch (PairwiseSessionError.CHECKPOINT_DEFERRED de) {
        throw de;
    } catch (GLib.Error e) {
        // Crossed checkpoints (D2): this message may be encapsulated to the reply key
        // we retired when OUR last checkpoint went out. ML-KEM decapsulates under any
        // key (implicit rejection), so the mismatch only shows up as a failed AEAD
        // tag — retry once against the retained previous key before giving up. The
        // whole attempt ran on a throwaway clone, so nothing needs unwinding.
        if (header.kem_ciphertext == null || state.kem_recv_priv_prev == null) {
            throw e;
        }
        work = state.clone();
        result = decrypt_transport_key_into(work, header, ciphertext, true, out transitioned);
    }
    state.adopt(work);
    applied_transition = transitioned;
    return result;
}

private Bytes decrypt_transport_key_into(SessionState state, MessageHeader header, Bytes ciphertext,
                                         bool use_previous_kem_priv,
                                         out bool applied_transition) throws GLib.Error {
    applied_transition = false;
    if (header.kem_pub_for_reply != null) {
        state.kem_send_pub = header.kem_pub_for_reply;
    }

    // Out-of-order fast path: if we already skipped past this (dh_pub, n) while
    // advancing the chain for a later message, decrypt directly from the cache
    // instead of re-deriving/discarding via the ratchet below (spec §9.4.2).
    string skip_lookup_key = skipped_key_string(header.dh_pub, header.n);
    if (state.skipped_keys.has_key(skip_lookup_key)) {
        Bytes cached_mk = state.skipped_keys[skip_lookup_key];
        state.skipped_keys.unset(skip_lookup_key);
        state.skipped_order.remove(skip_lookup_key);
        Bytes aes_key;
        Bytes nonce;
        derive_message_key(cached_mk, out aes_key, out nonce);
        return global::X3dhpq.Crypto.aes256gcm_decrypt(aes_key, nonce, ciphertext, new Bytes(concat_byte_arrays(bytes_to_uint8_array(state.ad), bytes_to_uint8_array(header.marshal()))));
    }

    // Compare LENGTHS before contents. header.dh_pub is attacker-controlled and
    // read_field permits up to 65536 bytes, while state.remote_dh_pub is a stored
    // 32-byte X25519 key. Passing the header's length to Memory.cmp made a peer able
    // to read up to ~64 KiB past that 32-byte allocation simply by prefixing a long
    // field with the previously observed key — and this runs during header processing,
    // before the AEAD tag has authenticated anything.
    uint8[] header_dh_pub = bytes_to_uint8_array(header.dh_pub);
    bool dh_pub_changed;
    if (state.remote_dh_pub == null) {
        dh_pub_changed = true;
    } else {
        uint8[] stored_dh_pub = bytes_to_uint8_array((!) state.remote_dh_pub);
        dh_pub_changed = stored_dh_pub.length != header_dh_pub.length
            || Memory.cmp(stored_dh_pub, header_dh_pub, stored_dh_pub.length) != 0;
    }
    if (dh_pub_changed) {
        if (state.chain_recv_key != null && header.prev_chain_len > state.recv_count) {
            // Skip (and cache) the remainder of the outgoing-epoch chain before
            // the DH ratchet below moves us to a new chain. These keys are for
            // the OLD remote_dh_pub, since header.dh_pub is the new one.
            skip_recv_keys(state, dh_pub_or_empty(state.remote_dh_pub), header.prev_chain_len);
        }

        state.prev_send_count = state.send_count;
        state.send_count = 0;
        state.recv_count = 0;

        Bytes new_rk;
        Bytes recv_ck;
        // D2, step 1 of the ratchet: this derives OUR RECV chain, which mirrors the
        // peer's send chain, so it folds kemHistoryRecv.
        dh_ratchet_step(state.rk, state.sending_dh_priv, header.dh_pub, state.kem_history_recv, out new_rk, out recv_ck);
        state.rk = new_rk;
        state.chain_recv_key = recv_ck;
        state.remote_dh_pub = header.dh_pub;

        Bytes new_send_pub;
        Bytes new_send_priv;
        global::X3dhpq.Crypto.generate_x25519(out new_send_pub, out new_send_priv);
        Bytes new_rk2;
        Bytes send_ck;
        // D2, step 2: this derives our NEW SEND chain, so it folds kemHistorySend.
        dh_ratchet_step(state.rk, new_send_priv, header.dh_pub, state.kem_history_send, out new_rk2, out send_ck);
        state.rk = new_rk2;
        state.chain_send_key = send_ck;
        state.sending_dh_pub = new_send_pub;
        state.sending_dh_priv = new_send_priv;
        // D3.2/D3.3: both chains are new, so neither has had a checkpoint applied.
        state.send_ckpt_n = CKPT_NONE;
        state.recv_ckpt_n = CKPT_NONE;
        applied_transition = true;
    }

    // D3.3: checkpoint-overtake detection, evaluated AFTER any DH-ratchet step
    // so `recv_ckpt_n` refers to the same chain the header does.
    //
    // If the sender says it last checkpointed this chain at index C and we have
    // not applied that transition, the message we are holding is a POST-checkpoint
    // message that overtook the checkpoint-bearing one. Advancing the chain here
    // would derive a key from the pre-checkpoint state and produce garbage; the
    // skipped-key cache cannot help, because what is missing is a state transition,
    // not a chain step. Defer instead, and leave the ratchet untouched.
    //
    // Messages sent BEFORE the checkpoint carry a smaller CkptN and are unaffected
    // — they keep being served by the skipped-key cache above.
    if (header.ckpt_n != CKPT_NONE && state.recv_ckpt_n != header.ckpt_n) {
        throw new PairwiseSessionError.CHECKPOINT_DEFERRED(
            "missing checkpoint transition at index %u (have %u)".printf(header.ckpt_n, state.recv_ckpt_n));
    }

    // Skip ahead (and cache) to this message's position on the current chain, keyed by the
    // CURRENT header.dh_pub. This MUST precede the checkpoint mix below: the checkpoint
    // fires at a fixed sender index (header.n), so the recv chain must reach that same
    // index over the PRE-checkpoint chain — where the skipped messages live — before the
    // mix. Mixing first desynchronised the two sides under out-of-order delivery.
    skip_recv_keys(state, header.dh_pub, header.n);

    Bytes? checkpoint_priv = use_previous_kem_priv ? state.kem_recv_priv_prev : state.kem_recv_priv;
    if (header.kem_ciphertext != null && checkpoint_priv != null && state.chain_recv_key != null) {
        Bytes kem_ss = global::X3dhpq.Crypto.mlkem768_decapsulate((!) checkpoint_priv, (!) header.kem_ciphertext);
        Bytes new_cks;
        Bytes new_ckr;
        Bytes new_history;
        // Unidirectional (§5.3): mix into the RECV chain only, mirroring the sender's
        // send-only mix. chain_recv_key is now at position header.n, so the two mixes share
        // a salt and converge; the send chain is left untouched. new_ckr is discarded.
        //
        // D2: this checkpoint belongs to the peer's send stream, which is our RECV
        // stream, so it folds into kemHistoryRecv. By construction the peer's
        // kemHistorySend and our kemHistoryRecv stay equal for this direction.
        kem_checkpoint_mix((!) state.chain_recv_key, kem_ss, header.dh_pub, (!) header.kem_ciphertext, header.n, state.kem_history_recv, out new_cks, out new_ckr, out new_history);
        state.chain_recv_key = new_cks;
        state.kem_history_recv = new_history;
        // D3.3: remember the index we applied it at, so a later message that
        // advertises CkptN = this index is recognised as processable.
        state.recv_ckpt_n = header.n;
        applied_transition = true;
    }

    Bytes mk;
    Bytes next_ck;
    chain_step((!) state.chain_recv_key, out mk, out next_ck);
    state.chain_recv_key = next_ck;
    state.recv_count++;

    Bytes aes_key;
    Bytes nonce;
    derive_message_key(mk, out aes_key, out nonce);
    return global::X3dhpq.Crypto.aes256gcm_decrypt(aes_key, nonce, ciphertext, new Bytes(concat_byte_arrays(bytes_to_uint8_array(state.ad), bytes_to_uint8_array(header.marshal()))));
}

public Bytes encrypt_payload(string plaintext) throws GLib.Error {
    Bytes transport_key = global::X3dhpq.Crypto.random_bytes(44);
    return transport_key;
}

public void decrypt_payload(Bytes transport_key, Bytes payload_ciphertext, out string plaintext) throws GLib.Error {
    Bytes key = slice_bytes(transport_key, 0, 32);
    Bytes nonce = slice_bytes(transport_key, 32, 12);
    Bytes clear = global::X3dhpq.Crypto.aes256gcm_decrypt(key, nonce, payload_ciphertext);
    // bytes_to_uint8_array allocates EXACTLY the plaintext length, but a Vala string is
    // a NUL-terminated char*. Casting the bare array to string therefore handed every
    // downstream consumer a buffer with no terminator, so reading it ran past the
    // allocation until it happened to hit a zero byte — leaking adjacent heap contents
    // into the message body, or crashing. The sender controls the plaintext length, so
    // it also controls how the allocation is sized. Copy into a NUL-terminated buffer.
    uint8[] clear_bytes = bytes_to_uint8_array(clear);
    uint8[] terminated = new uint8[clear_bytes.length + 1];
    Memory.copy(terminated, clear_bytes, clear_bytes.length);
    terminated[clear_bytes.length] = 0;
    plaintext = (string) (owned) terminated;
}

// Like decrypt_payload but returns raw bytes — used for sender-chain announcements.
public Bytes decrypt_payload_bytes(Bytes transport_key, Bytes payload_ciphertext) throws GLib.Error {
    Bytes key = slice_bytes(transport_key, 0, 32);
    Bytes nonce = slice_bytes(transport_key, 32, 12);
    return global::X3dhpq.Crypto.aes256gcm_decrypt(key, nonce, payload_ciphertext);
}

public Bytes encrypt_payload_plaintext(string plaintext, Bytes transport_key) throws GLib.Error {
    Bytes key = slice_bytes(transport_key, 0, 32);
    Bytes nonce = slice_bytes(transport_key, 32, 12);
    return global::X3dhpq.Crypto.aes256gcm_encrypt(key, nonce, new Bytes((uint8[]) plaintext.data));
}

// Like encrypt_payload_plaintext but takes raw bytes (used for sender-chain
// announcements where the payload is the binary marshal() of the
// SenderChainAnnouncement, not a UTF-8 string).
public Bytes encrypt_payload_bytes(Bytes plaintext, Bytes transport_key) throws GLib.Error {
    Bytes key = slice_bytes(transport_key, 0, 32);
    Bytes nonce = slice_bytes(transport_key, 32, 12);
    return global::X3dhpq.Crypto.aes256gcm_encrypt(key, nonce, plaintext);
}

private bool should_do_checkpoint(SessionState state) {
    return state.kem_send_pub != null
        && (state.kem_since_checkpoint >= 50
            || new DateTime.now_utc().to_unix() - state.last_checkpoint_time >= 3600);
}

private void maybe_kem_checkpoint(SessionState state) { }

private void chain_step(Bytes chain_key, out Bytes message_key, out Bytes next_chain_key) throws GLib.Error {
    message_key = global::X3dhpq.Crypto.hmac_sha256(chain_key, new Bytes({ 0x01 }));
    next_chain_key = global::X3dhpq.Crypto.hmac_sha256(chain_key, new Bytes({ 0x02 }));
}

// Key format for the skipped-message-key cache: base64(dh_pub) + ":" + n.
// Mirrors the Java reference's SkippedKey(dhStr, n).
private string skipped_key_string(Bytes dh_pub, uint32 n) {
    return bytes_to_base64(dh_pub) + ":" + n.to_string();
}

private Bytes dh_pub_or_empty(Bytes? dh_pub) {
    return dh_pub != null ? (!) dh_pub : new Bytes(new uint8[0]);
}

// Inserts (dh_pub, n) -> mk into the skipped-key cache, evicting the oldest
// entry first if the cache is already at MAX_SKIPPED. Mirrors the Java
// reference's skipped.put() eviction in Session.skipKeys().
private void store_skipped_key(SessionState state, Bytes dh_pub, uint32 n, Bytes mk) {
    string key = skipped_key_string(dh_pub, n);
    if (state.skipped_keys.has_key(key)) {
        state.skipped_order.remove(key);
    } else if (state.skipped_keys.size >= PAIRWISE_MAX_SKIPPED) {
        string oldest = state.skipped_order.remove_at(0);
        state.skipped_keys.unset(oldest);
    }
    state.skipped_keys[key] = mk;
    state.skipped_order.add(key);
}

// Advances the receive chain up to (but not including) target_n, caching each
// intermediate message key under dh_pub_for_key so an out-of-order message
// arriving later can still be decrypted (spec §9.4.2). Mirrors the Java
// reference's Session.skipKeys(), including its MAX_SKIPPED gap guard.
private void skip_recv_keys(SessionState state, Bytes dh_pub_for_key, uint32 target_n) throws GLib.Error {
    if (target_n > state.recv_count && (target_n - state.recv_count) > PAIRWISE_MAX_SKIPPED) {
        throw new IOError.FAILED("too many skipped messages: would skip %u".printf(target_n - state.recv_count));
    }
    while (state.recv_count < target_n) {
        Bytes skipped_mk;
        Bytes skipped_next;
        chain_step((!) state.chain_recv_key, out skipped_mk, out skipped_next);
        state.chain_recv_key = skipped_next;
        store_skipped_key(state, dh_pub_for_key, state.recv_count, skipped_mk);
        state.recv_count++;
    }
}

private void dh_ratchet_step(Bytes rk, Bytes dh_priv, Bytes remote_pub, Bytes kem_history, out Bytes new_rk, out Bytes new_ck) throws GLib.Error {
    Bytes dh_out = global::X3dhpq.Crypto.x25519_shared_secret(dh_priv, remote_pub);
    Bytes derived = hkdf64(rk, new Bytes(concat_byte_arrays(bytes_to_uint8_array(dh_out), bytes_to_uint8_array(kem_history))), INFO_ROOT_KEY);
    new_rk = slice_bytes(derived, 0, 32);
    new_ck = slice_bytes(derived, 32, 32);
}

private void derive_message_key(Bytes mk, out Bytes aes_key, out Bytes nonce) throws GLib.Error {
    Bytes derived = hkdf_expand_44(mk, INFO_MESSAGE_KEY);
    aes_key = slice_bytes(derived, 0, 32);
    nonce = slice_bytes(derived, 32, 12);
}


private Bytes hkdf64(Bytes salt, Bytes ikm, string info) throws GLib.Error {
    Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(salt, ikm);
    return global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes((uint8[]) info.data), 64);
}

private Bytes hkdf_expand_44(Bytes prk_source, string info) throws GLib.Error {
    Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(new Bytes(new uint8[64]), prk_source);
    return global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes((uint8[]) info.data), 44);
}

private void kem_checkpoint_mix(Bytes sender_ck, Bytes kem_ss, Bytes sender_dh, Bytes kem_ct, uint32 epoch, Bytes previous_history, out Bytes new_cks, out Bytes new_ckr, out Bytes new_history) throws GLib.Error {
    uint8[] transcript_input = concat_four_byte_arrays(
        label_with_nul(CHECKPOINT_TRANSCRIPT_LABEL),
        uint32_to_bytes(epoch),
        bytes_to_uint8_array(sender_dh),
        bytes_to_uint8_array(kem_ct)
    );
    Bytes transcript_hash = global::X3dhpq.Crypto.sha512(new Bytes(transcript_input));
    Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(sender_ck, new Bytes(concat_byte_arrays(bytes_to_uint8_array(kem_ss), bytes_to_uint8_array(transcript_hash))));
    new_cks = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes((uint8[]) INFO_CHECKPOINT_CHAIN_SEND.data), 32);
    new_ckr = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes((uint8[]) INFO_CHECKPOINT_CHAIN_RECV.data), 32);
    Bytes history_hash = global::X3dhpq.Crypto.sha512(new Bytes(concat_four_byte_arrays(
        label_with_nul(CHECKPOINT_HISTORY_LABEL),
        bytes_to_uint8_array(previous_history),
        bytes_to_uint8_array(kem_ss),
        bytes_to_uint8_array(transcript_hash)
    )));
    new_history = slice_bytes(history_hash, 0, 32);
}

private void append_serialized(StringBuilder builder, string key, string value) {
    builder.append(key);
    builder.append("=");
    builder.append(value);
    builder.append("\n");
}

private Bytes slice_bytes(Bytes source, int offset, int length) {
    uint8[] data = bytes_to_uint8_array(source);
    uint8[] result = new uint8[length];
    for (int i = 0; i < length; i++) {
        result[i] = data[offset + i];
    }
    return new Bytes(result);
}

private uint8[] concat_length_prefixed_bytes(uint8[] field) {
    return concat_byte_arrays(uint16_to_bytes((uint16) field.length), field);
}

// Like read_length_prefixed_bytes but returns success via bool and the field via
// out, so a legitimately empty (length-0) field is preserved rather than being
// coerced to null (Vala treats a returned zero-length array as null). Used for
// the DeviceCertificate DIK fields, any of which may be empty.
private bool read_length_prefixed_field(uint8[] data, ref int offset, out uint8[] field) {
    field = new uint8[0];
    if (offset + 2 > data.length) {
        return false;
    }
    uint16 length = uint16_from_bytes(data, offset);
    offset += 2;
    if (offset + length > data.length) {
        return false;
    }
    if (length > 0) {
        field = new uint8[length];
        for (int i = 0; i < length; i++) {
            field[i] = data[offset + i];
        }
    }
    offset += length;
    return true;
}

private uint8[]? read_length_prefixed_bytes(uint8[] data, ref int offset) {
    if (offset + 2 > data.length) {
        return null;
    }
    uint16 length = uint16_from_bytes(data, offset);
    offset += 2;
    if (offset + length > data.length) {
        return null;
    }
    uint8[] result = new uint8[length];
    for (int i = 0; i < length; i++) {
        result[i] = data[offset + i];
    }
    offset += length;
    return result;
}

private uint8[] concat_u32_prefixed_field(uint8[] field) {
    return concat_byte_arrays(uint32_to_bytes((uint32) field.length), field);
}

private uint8[] concat_five_fields(uint8[] a, uint8[] b, uint8[] c, uint8[] d, uint8[] e) {
    return concat_byte_arrays(
        concat_byte_arrays(concat_u32_prefixed_field(a), concat_u32_prefixed_field(b)),
        concat_byte_arrays(concat_u32_prefixed_field(c), concat_byte_arrays(concat_u32_prefixed_field(d), concat_u32_prefixed_field(e)))
    );
}

private uint8[]? read_u32_prefixed_field(uint8[] data, ref int offset) {
    if (offset + 4 > data.length) {
        return null;
    }
    uint32 length = uint32_from_bytes(data, offset);
    offset += 4;
    // 64-bit comparison so a corrupt/huge length can't wrap to a negative int
    // and reach `new uint8[(int) length]` (giant-allocation abort).
    if ((int64) offset + (int64) length > (int64) data.length) {
        return null;
    }
    uint8[] result = new uint8[(int) length];
    for (int i = 0; i < length; i++) {
        result[i] = data[offset + i];
    }
    offset += (int) length;
    return result;
}

}
