using Gee;
using Xmpp;

namespace Dino.Plugins.X3dhpq.Protocol {

private const string INFO_X3DH = "X3DHPQ-X3DH-PQ-v0";
private const string INFO_ROOT_KEY = "X3DHPQ-RootKey-v0";
private const string INFO_MESSAGE_KEY = "X3DHPQ-MessageKey-v0";
private const string INFO_CHECKPOINT_CHAIN_SEND = "X3DHPQ-ChainSend-v1";
private const string INFO_CHECKPOINT_CHAIN_RECV = "X3DHPQ-ChainRecv-v1";
private const string CHECKPOINT_TRANSCRIPT_LABEL = "X3DHPQ-Checkpoint-Transcript-v1\x00";
private const string CHECKPOINT_HISTORY_LABEL = "X3DHPQ-KEMHistory-v1\x00";

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

        uint8[]? dik_ed = read_length_prefixed_bytes(data, ref offset);
        uint8[]? dik_x = read_length_prefixed_bytes(data, ref offset);
        uint8[]? dik_m = read_length_prefixed_bytes(data, ref offset);
        if (dik_ed == null || dik_x == null || dik_m == null || offset + 9 > data.length) {
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

    public bool verify() throws GLib.Error {
        bool cert_ok = device_certificate.verify(
            bytes_from_base64(aik_pub_ed25519_base64),
            bytes_from_base64(aik_pub_mldsa_base64)
        );
        if (!cert_ok) {
            return false;
        }
        Bytes spk_pub = bytes_from_base64(signed_pre_key_base64);
        return global::X3dhpq.Crypto.ed25519_verify(
            device_certificate.dik_pub_ed25519,
            spk_pub,
            bytes_from_base64(signed_pre_key_signature_base64)
        );
    }
}

public class MessageHeader : Object {
    public Bytes dh_pub { get; set; }
    public uint32 prev_chain_len { get; set; }
    public uint32 n { get; set; }
    public Bytes? kem_ciphertext { get; set; }
    public Bytes? kem_pub_for_reply { get; set; }

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
        return new Bytes(buf);
    }

    public static MessageHeader? unmarshal(Bytes bytes) {
        uint8[] data = bytes_to_uint8_array(bytes);
        int off = 0;

        uint8[]? dh = read_field(data, ref off);
        if (dh == null) return null;
        uint32? pcl = read_u32_field(data, ref off);
        if (pcl == null) return null;
        uint32? nn = read_u32_field(data, ref off);
        if (nn == null) return null;
        uint8[]? kct = read_field(data, ref off);
        if (kct == null && off > data.length) return null;
        uint8[]? kpr = read_field(data, ref off);
        if (kpr == null && off > data.length) return null;

        MessageHeader header = new MessageHeader();
        header.dh_pub = new Bytes(dh);
        header.prev_chain_len = (!) pcl;
        header.n = (!) nn;
        header.kem_ciphertext = (kct != null && kct.length > 0) ? new Bytes(kct) : null;
        header.kem_pub_for_reply = (kpr != null && kpr.length > 0) ? new Bytes(kpr) : null;
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

    private static uint8[]? read_field(uint8[] data, ref int off) {
        if (off + 4 > data.length) return null;
        uint32 len = ((uint32) data[off] << 24)
                   | ((uint32) data[off + 1] << 16)
                   | ((uint32) data[off + 2] << 8)
                   | (uint32) data[off + 3];
        off += 4;
        if (len > 65536) return null; // mirrors Conversations' MAX_FIELD_LEN guard
        if (off + (int) len > data.length) return null;
        if (len == 0) return new uint8[0];
        uint8[] payload = new uint8[len];
        Memory.copy(payload, (uint8*) data + off, len);
        off += (int) len;
        return payload;
    }

    private static uint32? read_u32_field(uint8[] data, ref int off) {
        uint8[]? f = read_field(data, ref off);
        if (f == null || f.length != 4) return null;
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
    public uint32 kem_since_checkpoint { get; set; }
    public int64 last_checkpoint_time { get; set; }
    public Bytes ad { get; set; }
    public Bytes kem_history { get; set; }

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
        append_serialized(builder, "kem_since_checkpoint", kem_since_checkpoint.to_string());
        append_serialized(builder, "last_checkpoint_time", last_checkpoint_time.to_string());
        append_serialized(builder, "ad", bytes_to_base64(ad));
        append_serialized(builder, "kem_history", bytes_to_base64(kem_history));
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
        if (!values.has_key("rk") || !values.has_key("sending_dh_pub") || !values.has_key("sending_dh_priv") || !values.has_key("ad") || !values.has_key("kem_history")) {
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
        state.kem_since_checkpoint = (uint32) int.parse(values["kem_since_checkpoint"]);
        state.last_checkpoint_time = int64.parse(values["last_checkpoint_time"]);
        state.ad = bytes_from_base64(values["ad"]);
        state.kem_history = bytes_from_base64(values["kem_history"]);
        return state;
    }
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
    state.kem_history = new Bytes(new uint8[32]);
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
    state.kem_history = new Bytes(new uint8[32]);
    return state;
}

public void encrypt_transport_key(SessionState state, Bytes transport_key, out MessageHeader header, out Bytes ciphertext) throws GLib.Error {
    maybe_kem_checkpoint(state);
    Bytes mk;
    Bytes next_ck;
    chain_step((!) state.chain_send_key, out mk, out next_ck);
    state.chain_send_key = next_ck;

    header = new MessageHeader();
    header.dh_pub = state.sending_dh_pub;
    header.prev_chain_len = state.prev_send_count;
    header.n = state.send_count;
    header.kem_ciphertext = null;
    header.kem_pub_for_reply = state.kem_recv_pub;

    if (state.kem_send_pub != null && should_do_checkpoint(state)) {
        Bytes kem_ct;
        Bytes kem_ss;
        global::X3dhpq.Crypto.mlkem768_encapsulate((!) state.kem_send_pub, out kem_ct, out kem_ss);
        Bytes new_cks;
        Bytes new_ckr;
        Bytes new_history;
        kem_checkpoint_mix((!) state.chain_send_key, kem_ss, state.sending_dh_pub, kem_ct, state.send_count, state.kem_history, out new_cks, out new_ckr, out new_history);
        state.chain_send_key = new_cks;
        state.chain_recv_key = new_ckr;
        state.kem_history = new_history;
        state.kem_since_checkpoint = 0;
        state.last_checkpoint_time = new DateTime.now_utc().to_unix();
        Bytes new_pub;
        Bytes new_priv;
        global::X3dhpq.Crypto.generate_mlkem768(out new_pub, out new_priv);
        state.kem_recv_pub = new_pub;
        state.kem_recv_priv = new_priv;
        header.kem_ciphertext = kem_ct;
        header.kem_pub_for_reply = new_pub;
    }

    Bytes aes_key;
    Bytes nonce;
    derive_message_key(mk, out aes_key, out nonce);
    ciphertext = global::X3dhpq.Crypto.aes256gcm_encrypt(aes_key, nonce, transport_key, new Bytes(concat_byte_arrays(bytes_to_uint8_array(state.ad), bytes_to_uint8_array(header.marshal()))));
    state.send_count++;
    state.kem_since_checkpoint++;
}

public Bytes decrypt_transport_key(SessionState state, MessageHeader header, Bytes ciphertext) throws GLib.Error {
    if (header.kem_pub_for_reply != null) {
        state.kem_send_pub = header.kem_pub_for_reply;
    }

    if (state.remote_dh_pub == null || Memory.cmp(bytes_to_uint8_array((!) state.remote_dh_pub), bytes_to_uint8_array(header.dh_pub), bytes_to_uint8_array(header.dh_pub).length) != 0) {
        if (state.chain_recv_key != null && header.prev_chain_len > state.recv_count) {
            while (state.recv_count < header.prev_chain_len) {
                Bytes skipped_mk;
                Bytes skipped_next;
                chain_step((!) state.chain_recv_key, out skipped_mk, out skipped_next);
                state.chain_recv_key = skipped_next;
                state.recv_count++;
            }
        }

        state.prev_send_count = state.send_count;
        state.send_count = 0;
        state.recv_count = 0;

        Bytes new_rk;
        Bytes recv_ck;
        dh_ratchet_step(state.rk, state.sending_dh_priv, header.dh_pub, state.kem_history, out new_rk, out recv_ck);
        state.rk = new_rk;
        state.chain_recv_key = recv_ck;
        state.remote_dh_pub = header.dh_pub;

        Bytes new_send_pub;
        Bytes new_send_priv;
        global::X3dhpq.Crypto.generate_x25519(out new_send_pub, out new_send_priv);
        Bytes new_rk2;
        Bytes send_ck;
        dh_ratchet_step(state.rk, new_send_priv, header.dh_pub, state.kem_history, out new_rk2, out send_ck);
        state.rk = new_rk2;
        state.chain_send_key = send_ck;
        state.sending_dh_pub = new_send_pub;
        state.sending_dh_priv = new_send_priv;
    }

    if (header.kem_ciphertext != null && state.kem_recv_priv != null && state.chain_recv_key != null) {
        Bytes kem_ss = global::X3dhpq.Crypto.mlkem768_decapsulate((!) state.kem_recv_priv, (!) header.kem_ciphertext);
        Bytes new_cks;
        Bytes new_ckr;
        Bytes new_history;
        kem_checkpoint_mix((!) state.chain_recv_key, kem_ss, header.dh_pub, (!) header.kem_ciphertext, header.n, state.kem_history, out new_cks, out new_ckr, out new_history);
        state.chain_recv_key = new_cks;
        state.chain_send_key = new_ckr;
        state.kem_history = new_history;
    }

    while (state.recv_count < header.n) {
        Bytes skipped_mk;
        Bytes skipped_next;
        chain_step((!) state.chain_recv_key, out skipped_mk, out skipped_next);
        state.chain_recv_key = skipped_next;
        state.recv_count++;
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
    plaintext = (string) (uint8[]) bytes_to_uint8_array(clear);
}

public Bytes encrypt_payload_plaintext(string plaintext, Bytes transport_key) throws GLib.Error {
    Bytes key = slice_bytes(transport_key, 0, 32);
    Bytes nonce = slice_bytes(transport_key, 32, 12);
    return global::X3dhpq.Crypto.aes256gcm_encrypt(key, nonce, new Bytes((uint8[]) plaintext.data));
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
        string_to_bytes(CHECKPOINT_TRANSCRIPT_LABEL),
        uint32_to_bytes(epoch),
        bytes_to_uint8_array(sender_dh),
        bytes_to_uint8_array(kem_ct)
    );
    Bytes transcript_hash = global::X3dhpq.Crypto.sha512(new Bytes(transcript_input));
    Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(sender_ck, new Bytes(concat_byte_arrays(bytes_to_uint8_array(kem_ss), bytes_to_uint8_array(transcript_hash))));
    new_cks = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes((uint8[]) INFO_CHECKPOINT_CHAIN_SEND.data), 32);
    new_ckr = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes((uint8[]) INFO_CHECKPOINT_CHAIN_RECV.data), 32);
    Bytes history_hash = global::X3dhpq.Crypto.sha512(new Bytes(concat_four_byte_arrays(
        string_to_bytes(CHECKPOINT_HISTORY_LABEL),
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
    if (offset + (int) length > data.length) {
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
