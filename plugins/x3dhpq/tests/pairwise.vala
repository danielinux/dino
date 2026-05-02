namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class Pairwise : Gee.TestCase {

    public Pairwise() {
        base("Pairwise");
        add_test("device_certificate_roundtrip", test_device_certificate_roundtrip);
        add_test("session_roundtrip", test_session_roundtrip);
    }

    private void test_device_certificate_roundtrip() {
        try {
            Bytes aik_pub_ed;
            Bytes aik_priv_ed;
            Bytes aik_pub_m;
            Bytes aik_priv_m;
            Bytes dik_pub_ed;
            Bytes dik_priv_ed;
            Bytes dik_pub_x;
            Bytes dik_priv_x;
            Bytes dik_pub_m;
            Bytes dik_priv_m;

            Crypto.generate_ed25519(out aik_pub_ed, out aik_priv_ed);
            Crypto.generate_mldsa65(out aik_pub_m, out aik_priv_m);
            Crypto.generate_ed25519(out dik_pub_ed, out dik_priv_ed);
            Crypto.generate_x25519(out dik_pub_x, out dik_priv_x);
            Crypto.generate_mldsa65(out dik_pub_m, out dik_priv_m);

            DeviceCertificate cert = DeviceCertificate.issue(23, dik_pub_ed, dik_pub_x, dik_pub_m, aik_priv_ed, aik_priv_m, 1);
            DeviceCertificate? restored = DeviceCertificate.unmarshal(new Bytes(cert.marshal()));

            fail_if(restored == null, "device cert roundtrip failed");
            fail_if_not(((!) restored).verify(aik_pub_ed, aik_pub_m), "device cert verify failed");
            fail_if_not_eq_int((int) ((!) restored).device_id, 23, "device id mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_session_roundtrip() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();

            PeerBundle peer_bundle = bob.to_peer_bundle();
            fail_if_not(peer_bundle.verify(), "peer bundle verify failed");

            SessionBootstrap alice_bootstrap = initiate_session(alice.dik_priv_x25519, alice.dik_pub_x25519, peer_bundle);
            SessionState bob_state = respond_session(
                bob.dik_priv_x25519,
                bob.dik_pub_x25519,
                bob.spk_priv_x25519,
                bob.spk_pub_x25519,
                bob.opk_priv_x25519,
                bob.kem_priv,
                alice.device_certificate,
                alice.aik_pub_ed25519,
                alice.aik_pub_mldsa,
                alice_bootstrap.prekey_ephemeral_pub,
                alice_bootstrap.kem_ciphertext
            );

            Bytes transport_key = Crypto.random_bytes(44);
            MessageHeader header;
            Bytes encrypted_transport_key;
            encrypt_transport_key(alice_bootstrap.state, transport_key, out header, out encrypted_transport_key);
            Bytes clear_transport_key = decrypt_transport_key(bob_state, header, encrypted_transport_key);
            fail_if_not_eq_uint8_arr(bytes_to_array(transport_key), bytes_to_array(clear_transport_key), "transport key mismatch");

            Bytes payload = encrypt_payload_plaintext("hello world", transport_key);
            string plaintext;
            decrypt_payload(clear_transport_key, payload, out plaintext);
            fail_if_not_eq_str(plaintext, "hello world", "payload mismatch");

            Bytes reply_transport_key = Crypto.random_bytes(44);
            MessageHeader reply_header;
            Bytes reply_encrypted_transport_key;
            encrypt_transport_key(bob_state, reply_transport_key, out reply_header, out reply_encrypted_transport_key);
            Bytes alice_reply_transport_key = decrypt_transport_key(alice_bootstrap.state, reply_header, reply_encrypted_transport_key);
            fail_if_not_eq_uint8_arr(bytes_to_array(reply_transport_key), bytes_to_array(alice_reply_transport_key), "reply transport key mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
}

private static uint8[] bytes_to_array(Bytes bytes) {
    unowned uint8[] data = bytes.get_data();
    uint8[] copy = new uint8[data.length];
    Memory.copy(copy, data, data.length);
    return copy;
}

private static string bytes_b64(Bytes bytes) {
    return Base64.encode(bytes.get_data());
}

private static uint8[] u32be(uint32 value) {
    return {
        (uint8) ((value >> 24) & 0xff),
        (uint8) ((value >> 16) & 0xff),
        (uint8) ((value >> 8) & 0xff),
        (uint8) (value & 0xff),
    };
}

private static uint8[] join_arrays(uint8[] a, uint8[] b) {
    uint8[] result = new uint8[a.length + b.length];
    int offset = 0;
    foreach (uint8 v in a) result[offset++] = v;
    foreach (uint8 v in b) result[offset++] = v;
    return result;
}

    private class TestIdentity : Object {
        public Bytes aik_pub_ed25519;
        public Bytes aik_priv_ed25519;
        public Bytes aik_pub_mldsa;
        public Bytes aik_priv_mldsa;
        public Bytes dik_pub_ed25519;
        public Bytes dik_priv_ed25519;
        public Bytes dik_pub_x25519;
        public Bytes dik_priv_x25519;
        public Bytes dik_pub_mldsa;
        public Bytes dik_priv_mldsa;
        public DeviceCertificate device_certificate;
        public Bytes spk_pub_x25519;
        public Bytes spk_priv_x25519;
        public uint32 spk_id = 1;
        public Bytes spk_signature_ed25519;
        public Bytes kem_pub;
        public Bytes kem_priv;
        public Bytes opk_pub_x25519;
        public Bytes opk_priv_x25519;
        public uint32 opk_id = 1;
        public uint32 kem_id = 1;

        public TestIdentity() throws Error {
            Crypto.generate_ed25519(out aik_pub_ed25519, out aik_priv_ed25519);
            Crypto.generate_mldsa65(out aik_pub_mldsa, out aik_priv_mldsa);
            Crypto.generate_ed25519(out dik_pub_ed25519, out dik_priv_ed25519);
            Crypto.generate_x25519(out dik_pub_x25519, out dik_priv_x25519);
            Crypto.generate_mldsa65(out dik_pub_mldsa, out dik_priv_mldsa);
            device_certificate = DeviceCertificate.issue(1, dik_pub_ed25519, dik_pub_x25519, dik_pub_mldsa, aik_priv_ed25519, aik_priv_mldsa, 1);
            Crypto.generate_x25519(out spk_pub_x25519, out spk_priv_x25519);
            spk_signature_ed25519 = Crypto.ed25519_sign(dik_priv_ed25519, new Bytes(Pairwise.join_arrays(Pairwise.u32be(spk_id), Pairwise.bytes_to_array(spk_pub_x25519))));
            Crypto.generate_mlkem768(out kem_pub, out kem_priv);
            Crypto.generate_x25519(out opk_pub_x25519, out opk_priv_x25519);
        }

        public PeerBundle to_peer_bundle() {
            PeerBundle bundle = new PeerBundle();
            bundle.bare_jid = "bob@example.com";
            bundle.device_id = 1;
            bundle.aik_pub_ed25519_base64 = Pairwise.bytes_b64(aik_pub_ed25519);
            bundle.aik_pub_mldsa_base64 = Pairwise.bytes_b64(aik_pub_mldsa);
            bundle.device_certificate = device_certificate;
            bundle.identity_pub_x25519_base64 = Pairwise.bytes_b64(dik_pub_x25519);
            bundle.signed_pre_key_id = spk_id;
            bundle.signed_pre_key_base64 = Pairwise.bytes_b64(spk_pub_x25519);
            bundle.signed_pre_key_signature_base64 = Pairwise.bytes_b64(spk_signature_ed25519);
            PublicPreKey kem = new PublicPreKey();
            kem.id = kem_id;
            kem.public_base64 = Pairwise.bytes_b64(kem_pub);
            bundle.kem_pre_keys.add(kem);
            PublicPreKey opk = new PublicPreKey();
            opk.id = opk_id;
            opk.public_base64 = Pairwise.bytes_b64(opk_pub_x25519);
            bundle.one_time_pre_keys.add(opk);
            return bundle;
        }
    }
}

}
