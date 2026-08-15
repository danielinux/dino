namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class Pairwise : Gee.TestCase {

    public Pairwise() {
        base("Pairwise");
        add_test("device_certificate_roundtrip", test_device_certificate_roundtrip);
        add_test("session_roundtrip", test_session_roundtrip);
        add_test("bundle_rejects_bad_kem_sig", test_bundle_rejects_bad_kem_sig);
        add_test("bundle_rejects_missing_kem_sig", test_bundle_rejects_missing_kem_sig);
        add_test("bundle_rejects_half_kem_sig", test_bundle_rejects_half_kem_sig);
        add_test("late_messages_from_abandoned_chain", test_late_messages_from_abandoned_chain);
        add_test("checkpoint_keeps_in_flight_opposite_message", test_checkpoint_keeps_in_flight_opposite_message);
        add_test("cross_vector_from_pqonversations", test_cross_vector_from_pqonversations);
        add_test("cross_vector_ratchet_from_pqonversations", test_cross_vector_ratchet_from_pqonversations);
    }

    // A KEM pre-key signed by a foreign key (not the bundle's DIK) MUST be
    // rejected by PeerBundle.verify() (spec §9.1).
    private void test_bundle_rejects_bad_kem_sig() {
        try {
            TestIdentity bob = new TestIdentity();
            Bytes wrong_pub_ed;
            Bytes wrong_priv_ed;
            Crypto.generate_ed25519(out wrong_pub_ed, out wrong_priv_ed);
            bob.kem_signature_ed25519 = Crypto.ed25519_sign(wrong_priv_ed, bob.kem_pub);
            PeerBundle peer_bundle = bob.to_peer_bundle();
            fail_if(peer_bundle.verify(), "bundle with forged KEM sig must not verify");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // §9.1 is unconditional: "a bundle offering no validly-signed KEM pre-key MUST be
    // rejected". Tolerating an unsigned KEM pre-key is not a compatibility shim but a
    // downgrade oracle — the KEM pre-key is the sole carrier of post-quantum (HNDL)
    // confidentiality, so an attacker who strips the signature elements in transit gets
    // an unverified key accepted and can substitute one whose secret they hold.
    private void test_bundle_rejects_missing_kem_sig() {
        try {
            TestIdentity bob = new TestIdentity();
            PeerBundle peer_bundle = bob.to_peer_bundle();
            peer_bundle.kem_pre_keys[0].signature_ed25519_base64 = null;
            peer_bundle.kem_pre_keys[0].signature_mldsa_base64 = null;
            fail_if(peer_bundle.verify(), "bundle with an unsigned KEM pre-key must not verify");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // Stripping only ONE half of the hybrid signature must not bypass verification of
    // the other half — that would leave the post-quantum key authenticated by Ed25519
    // alone, which a post-quantum active attacker can forge.
    private void test_bundle_rejects_half_kem_sig() {
        try {
            TestIdentity bob = new TestIdentity();
            PeerBundle drop_mldsa = bob.to_peer_bundle();
            drop_mldsa.kem_pre_keys[0].signature_mldsa_base64 = null;
            fail_if(drop_mldsa.verify(), "bundle missing the ML-DSA KEM signature must not verify");

            PeerBundle drop_ed = bob.to_peer_bundle();
            drop_ed.kem_pre_keys[0].signature_ed25519_base64 = null;
            fail_if(drop_ed.verify(), "bundle missing the Ed25519 KEM signature must not verify");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
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

    // Late delivery across a DH ratchet step.
    //
    // Observed against a live peer: the sender emits four messages while this side is
    // offline, this side comes back and takes only the first two, replies (which makes
    // the sender DH-ratchet), and the sender writes again on the new chain. The two
    // still in flight from the OLD chain then arrive and MUST still decrypt. They are
    // recoverable only from the skipped keys derived when this side ratchets, and those
    // are derived purely from the sender's prev_chain_len — so if either the field or
    // the skip is wrong, the messages are lost for good.
    // Cross-implementation vector across a DH RATCHET STEP.
    //
    // Companion to test_cross_vector_from_pqonversations, which stays inside one chain
    // and therefore proves only that the symmetric half agrees. This one loads a
    // receiver state captured BEFORE the peer minted a new sending DH, then decrypts a
    // message bearing that new key — so it runs dh_ratchet_step against inputs produced
    // by the other implementation. If the two derive different root/chain keys from the
    // same (rk, our send priv, their new pub, kem_history), this is where it shows.
    // Cross-implementation vector, same chain.
    //
    // Session state and wire bytes produced by PQonversations' x3dhpq-core
    // (CrossVectorGeneratorTest): a receiving session mid-chain plus the next two
    // messages it emitted. Both clients pass their own round-trip tests, so a
    // divergence could only live in something crossing the boundary — the chain KDF,
    // the AAD, or the header encoding. This asserts THIS implementation derives the
    // same message keys the other one used. No DH ratchet here; see the companion test.
    private void test_cross_vector_from_pqonversations() {
        try {
            string blob = ""
            + "rk=BMiHjdKK7qH1ygGpNigfUw4iDcVrbRahiQSV/0qZHlU=\n"
            + "chain_send_key=\n"
            + "chain_recv_key=3DbaBA2d9n+2y/D1VhagoVTAaJ3/V6chER7ntRcinLM=\n"
            + "sending_dh_pub=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "sending_dh_priv=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "remote_dh_pub=T9p8wpNGwvqy1Xz0TmPVeGIhSKPBP3FfJg3Qnok+v08=\n"
            + "send_count=0\n"
            + "recv_count=1\n"
            + "prev_send_count=0\n"
            + "kem_send_pub=\n"
            + "kem_recv_priv=\n"
            + "kem_recv_pub=\n"
            + "kem_since_checkpoint=0\n"
            + "last_checkpoint_time=0\n"
            + "ad=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==\n"
            + "kem_history=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            ;
            SessionState? st = SessionState.deserialize(blob);
            fail_if(st == null, "could not load the cross-vector session state");
            check_cross_vector_message((!) st, "000000204fda7cc29346c2fab2d57cf44e63d578622148a3c13f715f260dd09e893ebf4f000000040000000000000004000000010000000000000000", "4c83931b8c6f519b0bfe486044b9d05e2c71d0075b202f50192ff8d074d9f5063b7050a890f62bb7ff6c3921ad4cff0ddf33eba31c585ccf2c34d69e", "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", "msg1");
            check_cross_vector_message((!) st, "000000204fda7cc29346c2fab2d57cf44e63d578622148a3c13f715f260dd09e893ebf4f000000040000000000000004000000020000000000000000", "840925e301560f289475e0c445eadd4a1f30f5bf00435c5a073bb0af2a18e2a7e41aeccb8ca41a69d38fb4a3fa7226707d1155996ecc3f2a791d725d", "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2", "msg2");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_cross_vector_ratchet_from_pqonversations() {
        try {
            string blob = ""
            + "rk=SoTv9My+zY6BqNvwdATGNoEk4QLVQHX1meV9hXmUtaQ=\n"
            + "chain_send_key=cmGzf1IgNYAzNzu7KJLsbeB9Q/Lutvv6RUODDG6bwL0=\n"
            + "chain_recv_key=dEZVPTfh2TAO+BpretB1SPKwbHDKxEyItMIH9K/FWQA=\n"
            + "sending_dh_pub=pr6PddEokZB4PJG1woIi3ehl+iC4u4/yHXPQQ6igQyQ=\n"
            + "sending_dh_priv=MKIvVnLYiFnZ3RgQlWPbnQkmygv9W8AMomC5m/1wDlE=\n"
            + "remote_dh_pub=ffrTsmauG5rMmPwWLnOP/VHVsFbgksFVIxt1n8jrZmk=\n"
            + "send_count=1\n"
            + "recv_count=3\n"
            + "prev_send_count=0\n"
            + "kem_send_pub=\n"
            + "kem_recv_priv=\n"
            + "kem_recv_pub=\n"
            + "kem_since_checkpoint=1\n"
            + "last_checkpoint_time=0\n"
            + "ad=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==\n"
            + "kem_history=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            ;
            SessionState? st = SessionState.deserialize(blob);
            fail_if(st == null, "could not load the ratchet cross-vector session state");
            check_cross_vector_message((!) st, "0000002054c90785341bc0b756c1d06570ced5b5975dea1498f1855c3c29544071998a57000000040000000300000004000000000000000000000000", "f5a6886c0144e6e7a6ac61df68a08f0db8c6c05cf92ef4b9b65570fc7457055bc52b954c73b7e56c1250aa054596d83e90e424d5ca7cce72f6b209b0", "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4", "ratchet");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void check_cross_vector_message(SessionState st, string hdr_hex, string ct_hex,
                                            string want_hex, string label) throws Error {
        MessageHeader? h = MessageHeader.unmarshal(new Bytes(hex_to_bin(hdr_hex)));
        fail_if(h == null, label + ": header failed to unmarshal");
        Bytes got = decrypt_transport_key(st, (!) h, new Bytes(hex_to_bin(ct_hex)));
        fail_if_not_eq_uint8_arr(hex_to_bin(want_hex), bytes_to_array(got),
            label + ": decrypted transport key does not match the other implementation");
    }

    private static uint8[] hex_to_bin(string hex) {
        uint8[] outb = new uint8[hex.length / 2];
        for (int i = 0; i < outb.length; i++) {
            outb[i] = (uint8) ("0123456789abcdef".index_of_char(hex[i * 2]) * 16
                             + "0123456789abcdef".index_of_char(hex[i * 2 + 1]));
        }
        return outb;
    }

    private void test_late_messages_from_abandoned_chain() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();

            PeerBundle peer_bundle = bob.to_peer_bundle();
            SessionBootstrap a = initiate_session(alice.dik_priv_x25519, alice.dik_pub_x25519, peer_bundle);
            SessionState b = respond_session(
                bob.dik_priv_x25519, bob.dik_pub_x25519,
                bob.spk_priv_x25519, bob.spk_pub_x25519,
                bob.opk_priv_x25519, bob.kem_priv,
                alice.device_certificate, alice.aik_pub_ed25519, alice.aik_pub_mldsa,
                a.prekey_ephemeral_pub, a.kem_ciphertext);

            // Alice sends four; Bob is "offline" and takes none of them yet.
            Bytes[] keys = new Bytes[4];
            MessageHeader[] headers = new MessageHeader[4];
            Bytes[] cts = new Bytes[4];
            for (int i = 0; i < 4; i++) {
                keys[i] = Crypto.random_bytes(44);
                MessageHeader h;
                Bytes ct;
                encrypt_transport_key(a.state, keys[i], out h, out ct);
                headers[i] = h;
                cts[i] = ct;
            }
            fail_if_not_eq_int((int) headers[0].n, 0, "first message of the chain is n=0");
            fail_if_not_eq_int((int) headers[3].n, 3, "fourth message of the chain is n=3");

            // Bob comes online far enough to take the first two.
            Bytes got0 = decrypt_transport_key(b, headers[0], cts[0]);
            fail_if_not_eq_uint8_arr(bytes_to_array(keys[0]), bytes_to_array(got0), "n=0 mismatch");
            Bytes got1 = decrypt_transport_key(b, headers[1], cts[1]);
            fail_if_not_eq_uint8_arr(bytes_to_array(keys[1]), bytes_to_array(got1), "n=1 mismatch");

            // Bob replies; Alice processes it and DH-ratchets, ending the chain above.
            Bytes reply_key = Crypto.random_bytes(44);
            MessageHeader reply_h;
            Bytes reply_ct;
            encrypt_transport_key(b, reply_key, out reply_h, out reply_ct);
            decrypt_transport_key(a.state, reply_h, reply_ct);

            // Alice's next message opens a new chain and must declare the abandoned
            // chain's length, or Bob cannot know how many keys to retain for it.
            Bytes fresh_key = Crypto.random_bytes(44);
            MessageHeader fresh_h;
            Bytes fresh_ct;
            encrypt_transport_key(a.state, fresh_key, out fresh_h, out fresh_ct);
            fail_if_not_eq_int((int) fresh_h.n, 0, "new chain restarts at n=0");
            fail_if_not_eq_int((int) fresh_h.prev_chain_len, 4,
                "prev_chain_len must be the number of messages sent on the chain just ended");

            // Bob takes the ratchet message — the point at which it must stash the
            // remaining keys of the chain being abandoned.
            Bytes got_fresh = decrypt_transport_key(b, fresh_h, fresh_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(fresh_key), bytes_to_array(got_fresh), "new-chain n=0 mismatch");

            // The two that were in flight finally arrive. This is the regression.
            Bytes got2 = decrypt_transport_key(b, headers[2], cts[2]);
            fail_if_not_eq_uint8_arr(bytes_to_array(keys[2]), bytes_to_array(got2),
                "message stranded on the abandoned chain must still decrypt (n=2)");
            Bytes got3 = decrypt_transport_key(b, headers[3], cts[3]);
            fail_if_not_eq_uint8_arr(bytes_to_array(keys[3]), bytes_to_array(got3),
                "message stranded on the abandoned chain must still decrypt (n=3)");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // A checkpoint in one direction MUST NOT strand an in-flight message in the OTHER
    // direction. Regression test for the bidirectional-checkpoint bug: Alice sending a
    // checkpoint used to rewrite her own recv chain, destroying the key for a Bob→Alice
    // message already in flight. The unidirectional fix touches only the send chain.
    private void test_checkpoint_keeps_in_flight_opposite_message() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();

            PeerBundle peer_bundle = bob.to_peer_bundle();
            SessionBootstrap a = initiate_session(alice.dik_priv_x25519, alice.dik_pub_x25519, peer_bundle);
            SessionState b = respond_session(
                bob.dik_priv_x25519, bob.dik_pub_x25519,
                bob.spk_priv_x25519, bob.spk_pub_x25519,
                bob.opk_priv_x25519, bob.kem_priv,
                alice.device_certificate, alice.aik_pub_ed25519, alice.aik_pub_mldsa,
                a.prekey_ephemeral_pub, a.kem_ciphertext);

            // Bootstrap: Alice→Bob, then Bob→Alice so Alice learns Bob's KEM pub (needed
            // before Alice can checkpoint).
            Bytes k0 = Crypto.random_bytes(44);
            MessageHeader h0; Bytes ct0;
            encrypt_transport_key(a.state, k0, out h0, out ct0);
            decrypt_transport_key(b, h0, ct0);

            Bytes rk0 = Crypto.random_bytes(44);
            MessageHeader rh0; Bytes rct0;
            encrypt_transport_key(b, rk0, out rh0, out rct0);
            decrypt_transport_key(a.state, rh0, rct0);

            // Bob sends B1 on the Bob→Alice chain; DELAYED, not delivered to Alice yet.
            Bytes b1_key = Crypto.random_bytes(44);
            MessageHeader b1_h; Bytes b1_ct;
            encrypt_transport_key(b, b1_key, out b1_h, out b1_ct);

            // Alice sends 49 fillers + the checkpoint message. kem_since_checkpoint was 1
            // after the bootstrap send, so the 50th send here carries the checkpoint.
            for (int i = 0; i < 49; i++) {
                Bytes fk = Crypto.random_bytes(44);
                MessageHeader fh; Bytes fct;
                encrypt_transport_key(a.state, fk, out fh, out fct);
                decrypt_transport_key(b, fh, fct);
            }
            Bytes ck_key = Crypto.random_bytes(44);
            MessageHeader ck_h; Bytes ck_ct;
            encrypt_transport_key(a.state, ck_key, out ck_h, out ck_ct);
            fail_if_not(ck_h.kem_ciphertext != null, "Alice's message must carry a checkpoint");
            decrypt_transport_key(b, ck_h, ck_ct);

            // The delayed Bob→Alice message finally arrives; it MUST still decrypt.
            Bytes got_b1 = decrypt_transport_key(a.state, b1_h, b1_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(b1_key), bytes_to_array(got_b1),
                "in-flight opposite-direction message must survive an outbound checkpoint");
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
        public Bytes kem_signature_ed25519;
        public Bytes kem_signature_mldsa;
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
            spk_signature_ed25519 = Crypto.ed25519_sign(dik_priv_ed25519, spk_pub_x25519);
            Crypto.generate_mlkem768(out kem_pub, out kem_priv);
            kem_signature_ed25519 = Crypto.ed25519_sign(dik_priv_ed25519, kem_pub);
            kem_signature_mldsa = Crypto.mldsa65_sign(dik_priv_mldsa, kem_pub);
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
            kem.signature_ed25519_base64 = Pairwise.bytes_b64(kem_signature_ed25519);
            kem.signature_mldsa_base64 = Pairwise.bytes_b64(kem_signature_mldsa);
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
