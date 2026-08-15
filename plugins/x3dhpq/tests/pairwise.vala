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
        // D1
        add_test("prekey_sig_input_kat", test_prekey_sig_input_kat);
        add_test("bundle_rejects_legacy_naked_key_signature", test_bundle_rejects_legacy_naked_key_signature);
        add_test("bundle_rejects_relabelled_prekey_id", test_bundle_rejects_relabelled_prekey_id);
        // D2
        add_test("crossed_checkpoints_then_ratchet_both_ways", test_crossed_checkpoints_then_ratchet_both_ways);
        // D3
        add_test("header_kat_and_five_field_rejection", test_header_kat_and_five_field_rejection);
        add_test("checkpoint_overtake_defers_then_recovers", test_checkpoint_overtake_defers_then_recovers);
        add_test("failed_auth_leaves_state_unchanged", test_failed_auth_leaves_state_unchanged);
        // D2 persistence
        add_test("legacy_session_blob_is_discarded", test_legacy_session_blob_is_discarded);
        // D2+D3 combined
        add_test("crossed_checkpoints_with_overtake", test_crossed_checkpoints_with_overtake);
        add_test("ratchet_step_precedes_checkpoint_mix", test_ratchet_precedes_checkpoint_mix);
    }

    // ------------------------------------------------------------ D2 + D3 ----

    // D2 and D3 are ONE fix, not two.
    //
    // D2's convergence argument — per-direction accumulators agree because each
    // direction's checkpoints are totally ordered by its own message chain — holds
    // only if the receiver APPLIES that direction's checkpoints in the order the
    // sender emitted them, which is exactly what D3's deferral rule enforces. D2
    // without D3 still diverges under reordering; D3 without D2 still diverges under
    // concurrency. This is the combined trace: crossed checkpoints AND one of them
    // delivered after its own successor.
    //
    // The assertion is on the ACCUMULATORS, not only on decryptability: a trace that
    // merely decrypts can leave the state already diverged in a way that only breaks
    // at the next ratchet.
    private void test_crossed_checkpoints_with_overtake() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();
            SessionBootstrap a;
            SessionState b;
            establish(alice, bob, out a, out b);

            // Both directions live, so each side knows the other's KEM reply key.
            roundtrip(a.state, b);
            roundtrip(b, a.state);

            // Both sides checkpoint on their next send, neither having seen the other's.
            a.state.last_checkpoint_time = 0;
            b.last_checkpoint_time = 0;

            Bytes a_ck_key = Crypto.random_bytes(44);
            MessageHeader a_ck_h; Bytes a_ck_ct;
            encrypt_transport_key(a.state, a_ck_key, out a_ck_h, out a_ck_ct);
            fail_if(a_ck_h.kem_ciphertext == null, "A's checkpoint message");

            Bytes a_next_key = Crypto.random_bytes(44);
            MessageHeader a_next_h; Bytes a_next_ct;
            encrypt_transport_key(a.state, a_next_key, out a_next_h, out a_next_ct);
            fail_if_not(a_next_h.ckpt_n == a_ck_h.n, "A's successor advertises the checkpoint index");

            Bytes b_ck_key = Crypto.random_bytes(44);
            MessageHeader b_ck_h; Bytes b_ck_ct;
            encrypt_transport_key(b, b_ck_key, out b_ck_h, out b_ck_ct);
            fail_if(b_ck_h.kem_ciphertext == null, "B's checkpoint message");

            Bytes b_next_key = Crypto.random_bytes(44);
            MessageHeader b_next_h; Bytes b_next_ct;
            encrypt_transport_key(b, b_next_key, out b_next_h, out b_next_ct);

            // ── Delivery, deliberately out of order in the A->B direction ────────
            // A's successor arrives FIRST and must be deferred, untouched.
            string b_before = b.serialize();
            bool deferred = false;
            try {
                decrypt_transport_key(b, a_next_h, a_next_ct);
            } catch (PairwiseSessionError.CHECKPOINT_DEFERRED de) {
                deferred = true;
            }
            fail_if_not(deferred, "the overtaking message must be deferred");
            fail_if_not_eq_str(b_before, b.serialize(), "deferral must not touch state");

            // B->A is delivered in order.
            Bytes a_got_ck = decrypt_transport_key(a.state, b_ck_h, b_ck_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(b_ck_key), bytes_to_array(a_got_ck), "A reads B's checkpoint");
            Bytes a_got_next = decrypt_transport_key(a.state, b_next_h, b_next_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(b_next_key), bytes_to_array(a_got_next), "A reads B's successor");

            // A's checkpoint finally lands, then the drained successor.
            Bytes b_got_ck = decrypt_transport_key(b, a_ck_h, a_ck_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(a_ck_key), bytes_to_array(b_got_ck), "B reads A's checkpoint");
            Bytes b_got_next = decrypt_transport_key(b, a_next_h, a_next_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(a_next_key), bytes_to_array(b_got_next),
                "the deferred successor must decrypt once the checkpoint has been applied");

            // ── The load-bearing assertion: accumulators agree PAIRWISE ─────────
            fail_if_not_eq_str(Base64.encode(bytes_to_array(a.state.kem_history_send)),
                Base64.encode(bytes_to_array(b.kem_history_recv)),
                "A->B: A.kem_history_send must equal B.kem_history_recv");
            fail_if_not_eq_str(Base64.encode(bytes_to_array(b.kem_history_send)),
                Base64.encode(bytes_to_array(a.state.kem_history_recv)),
                "B->A: B.kem_history_send must equal A.kem_history_recv");
            // ...and the two DIRECTIONS must not have been conflated into one value.
            fail_if(Base64.encode(bytes_to_array(a.state.kem_history_send))
                    == Base64.encode(bytes_to_array(a.state.kem_history_recv)),
                "the two accumulators must be independent, not a single shared value");

            // ── A DH ratchet in each direction must still decrypt ───────────────
            Bytes a_dh_before = a.state.sending_dh_pub;
            roundtrip(a.state, b);      // B ratchets on A's (already-current) chain
            Bytes b_dh_before = b.sending_dh_pub;
            roundtrip(b, a.state);      // A ratchets onto B's new DH
            fail_if(Base64.encode(bytes_to_array(a_dh_before))
                    == Base64.encode(bytes_to_array(a.state.sending_dh_pub)),
                "A must have performed a DH ratchet");
            roundtrip(a.state, b);      // B ratchets onto A's new DH
            fail_if(Base64.encode(bytes_to_array(b_dh_before))
                    == Base64.encode(bytes_to_array(b.sending_dh_pub)),
                "B must have performed a DH ratchet");
            roundtrip(b, a.state);
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // Ordering is fixed and MUST be: DH ratchet step FIRST, then this message's
    // checkpoint mix — on both the send and the receive path. A checkpoint riding on
    // a ratchet-bearing message therefore does not affect that message's own ratchet
    // derivation on either side.
    //
    // The check is not cosmetic: the ratchet consumes dh_out || KEMHistory, so a
    // receiver that folded the message's own checkpoint into kemHistoryRecv BEFORE
    // ratcheting would derive a different root and chain key than the sender, which
    // ratcheted before its checkpoint. The message would simply not decrypt, and the
    // session would be dead from that point on.
    private void test_ratchet_precedes_checkpoint_mix() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();
            SessionBootstrap a;
            SessionState b;
            establish(alice, bob, out a, out b);

            roundtrip(a.state, b);
            roundtrip(b, a.state);   // Alice now holds a fresh send chain (she ratcheted)

            Bytes send_hist_before = a.state.kem_history_send;
            Bytes recv_hist_before = b.kem_history_recv;
            Bytes a_dh_at_send = a.state.sending_dh_pub;

            // The next Alice→Bob message is BOTH ratchet-bearing (Bob has not seen
            // this DH public yet) and checkpoint-bearing.
            a.state.last_checkpoint_time = 0;
            Bytes key = Crypto.random_bytes(44);
            MessageHeader h; Bytes ct;
            encrypt_transport_key(a.state, key, out h, out ct);
            fail_if(h.kem_ciphertext == null, "the message must carry a checkpoint");
            fail_if_not_eq_str(Base64.encode(bytes_to_array(h.dh_pub)),
                Base64.encode(bytes_to_array(a_dh_at_send)),
                "the message must carry the DH public Bob has not ratcheted onto yet");
            fail_if_not(h.ckpt_n == CKPT_NONE,
                "a checkpoint on a fresh send chain must advertise CkptN = 0xFFFFFFFF,"
                + " i.e. NOT its own checkpoint");
            // Send side: the checkpoint mix advanced kemHistorySend, but only AFTER
            // the chain this message rides on was already derived.
            fail_if(Base64.encode(bytes_to_array(send_hist_before))
                    == Base64.encode(bytes_to_array(a.state.kem_history_send)),
                "the outgoing checkpoint must have folded kemHistorySend");

            // Receive side: Bob ratchets, THEN mixes. If the order were reversed the
            // ratchet would consume a different accumulator and this would not decrypt.
            Bytes got = decrypt_transport_key(b, h, ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(key), bytes_to_array(got),
                "a checkpoint riding on a ratchet-bearing message must decrypt");
            fail_if(Base64.encode(bytes_to_array(recv_hist_before))
                    == Base64.encode(bytes_to_array(b.kem_history_recv)),
                "the incoming checkpoint must have folded kemHistoryRecv");
            fail_if_not_eq_str(Base64.encode(bytes_to_array(a.state.kem_history_send)),
                Base64.encode(bytes_to_array(b.kem_history_recv)),
                "both sides must have folded the same value for this direction");

            // The chain keeps working on both sides afterwards.
            roundtrip(a.state, b);
            roundtrip(b, a.state);
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // ---------------------------------------------------------------- D1 -----

    // The signing input is cross-client wire, so pin it byte-for-byte:
    //   "X3DHPQ-PreKeySig-v1\x00" (20) | uint8 type | uint32 id | uint16 len | pub
    private void test_prekey_sig_input_kat() {
        uint8[] pub = new uint8[32];
        for (int i = 0; i < 32; i++) pub[i] = (uint8) i;
        uint8[] got = prekey_sig_input(PREKEY_TYPE_SPK, 0x01020304, new Bytes(pub));
        string want = "5833444850512d5072654b65795369672d763100"   // label + NUL
             + "01"                                          // key_type
             + "01020304"                                    // key_id
             + "0020"                                        // pub_len = 32
             + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        fail_if_not_eq_uint8_arr(hex_to_bin(want), got, "pre-key signing input is not the pinned encoding");
        fail_if_not_eq_int(got.length, 20 + 1 + 4 + 2 + 32, "pre-key signing input length");
    }

    // A signature made the OLD way — Ed25519/ML-DSA over the naked public key —
    // must no longer verify. That signature says nothing about which slot or id the
    // key was advertised under, which is exactly what let a relay relabel it.
    private void test_bundle_rejects_legacy_naked_key_signature() {
        try {
            TestIdentity bob = new TestIdentity();
            PeerBundle legacy_spk = bob.to_peer_bundle();
            legacy_spk.signed_pre_key_signature_base64 =
                Pairwise.bytes_b64(Crypto.ed25519_sign(bob.dik_priv_ed25519, bob.spk_pub_x25519));
            fail_if(legacy_spk.verify(), "SPK signed over the naked key must not verify");

            PeerBundle legacy_kem = bob.to_peer_bundle();
            legacy_kem.kem_pre_keys[0].signature_ed25519_base64 =
                Pairwise.bytes_b64(Crypto.ed25519_sign(bob.dik_priv_ed25519, bob.kem_pub));
            legacy_kem.kem_pre_keys[0].signature_mldsa_base64 =
                Pairwise.bytes_b64(Crypto.mldsa65_sign(bob.dik_priv_mldsa, bob.kem_pub));
            fail_if(legacy_kem.verify(), "KEM pre-key signed over the naked key must not verify");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // Taking a validly signed key and re-advertising it under a DIFFERENT id must
    // fail: the id is inside the signed input now.
    private void test_bundle_rejects_relabelled_prekey_id() {
        try {
            TestIdentity bob = new TestIdentity();

            PeerBundle relabelled_spk = bob.to_peer_bundle();
            fail_if_not(relabelled_spk.verify(), "control: an untouched bundle must verify");
            relabelled_spk.signed_pre_key_id = bob.spk_id + 1;
            fail_if(relabelled_spk.verify(), "SPK re-advertised under a different id must not verify");

            PeerBundle relabelled_kem = bob.to_peer_bundle();
            relabelled_kem.kem_pre_keys[0].id = bob.kem_id + 1;
            fail_if(relabelled_kem.verify(), "KEM pre-key re-advertised under a different id must not verify");

            // Type confusion: an SPK signature replayed into a KEM slot (and vice
            // versa) must fail even when the id happens to line up.
            PeerBundle swapped = bob.to_peer_bundle();
            swapped.signed_pre_key_signature_base64 = Pairwise.bytes_b64(
                Crypto.ed25519_sign(bob.dik_priv_ed25519,
                    prekey_sig_message(PREKEY_TYPE_KEM, bob.spk_id, bob.spk_pub_x25519)));
            fail_if(swapped.verify(), "SPK signed under the KEM key type must not verify");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // ---------------------------------------------------------------- D2 -----

    // Crossed checkpoints. Alice and Bob each emit a checkpoint before receiving the
    // other's, so with ONE shared accumulator Alice folds (A, then B) and Bob folds
    // (B, then A). The fold is not commutative, so the two accumulators diverge and
    // the next DH ratchet — which consumes dh_out || KEMHistory — derives different
    // root keys on the two sides. With one accumulator per DIRECTION there is
    // nothing to reorder, and both directions keep working.
    private void test_crossed_checkpoints_then_ratchet_both_ways() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();
            SessionBootstrap a;
            SessionState b;
            establish(alice, bob, out a, out b);

            // Bootstrap both directions so each side knows the other's KEM pub
            // (required before either can checkpoint).
            roundtrip(a.state, b);
            roundtrip(b, a.state);

            // Force BOTH sides to checkpoint on their next send.
            a.state.last_checkpoint_time = 0;
            b.last_checkpoint_time = 0;

            Bytes a_key = Crypto.random_bytes(44);
            MessageHeader a_h; Bytes a_ct;
            encrypt_transport_key(a.state, a_key, out a_h, out a_ct);
            fail_if(a_h.kem_ciphertext == null, "Alice's message must carry a checkpoint");

            Bytes b_key = Crypto.random_bytes(44);
            MessageHeader b_h; Bytes b_ct;
            encrypt_transport_key(b, b_key, out b_h, out b_ct);
            fail_if(b_h.kem_ciphertext == null, "Bob's message must carry a checkpoint");

            // Both cross on the wire and are delivered.
            Bytes b_got = decrypt_transport_key(b, a_h, a_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(a_key), bytes_to_array(b_got), "Bob could not read Alice's checkpoint message");
            Bytes a_got = decrypt_transport_key(a.state, b_h, b_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(b_key), bytes_to_array(a_got), "Alice could not read Bob's checkpoint message");

            // The accumulators must agree PER DIRECTION, which is what the next
            // ratchet in each direction depends on.
            fail_if_not_eq_str(Base64.encode(bytes_to_array(a.state.kem_history_send)),
                Base64.encode(bytes_to_array(b.kem_history_recv)),
                "A->B stream: Alice's send accumulator must equal Bob's recv accumulator");
            fail_if_not_eq_str(Base64.encode(bytes_to_array(b.kem_history_send)),
                Base64.encode(bytes_to_array(a.state.kem_history_recv)),
                "B->A stream: Bob's send accumulator must equal Alice's recv accumulator");

            // A DH ratchet in each direction must still decrypt. The ratchet folds
            // the accumulator of the chain it derives, so a divergence shows here.
            roundtrip(a.state, b);
            roundtrip(b, a.state);
            roundtrip(a.state, b);
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // A blob written before the KEMHistory split must be DISCARDED, not migrated:
    // there is no way to know which direction's stream the single accumulator
    // folded, and guessing derives wrong root keys at the next ratchet.
    private void test_legacy_session_blob_is_discarded() {
        string legacy = ""
            + "rk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "chain_send_key=\n"
            + "chain_recv_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "sending_dh_pub=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "sending_dh_priv=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "remote_dh_pub=\n"
            + "send_count=0\nrecv_count=0\nprev_send_count=0\n"
            + "kem_send_pub=\nkem_recv_priv=\nkem_recv_pub=\n"
            + "kem_since_checkpoint=0\nlast_checkpoint_time=0\n"
            + "ad=AAA=\n"
            + "kem_history=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
        fail_if(SessionState.deserialize(legacy) != null,
            "a pre-split session blob must be rejected so the session renegotiates");
    }

    // ---------------------------------------------------------------- D3 -----

    // The header is cross-client wire: pin the six-field encoding, and prove that a
    // header ending after five fields is rejected (without CkptN the receiver cannot
    // detect a missing checkpoint transition at all).
    private void test_header_kat_and_five_field_rejection() {
        MessageHeader h = new MessageHeader();
        uint8[] dh = new uint8[32];
        for (int i = 0; i < 32; i++) dh[i] = 0xAB;
        h.dh_pub = new Bytes(dh);
        h.prev_chain_len = 3;
        h.n = 7;
        h.kem_ciphertext = null;
        h.kem_pub_for_reply = null;
        h.ckpt_n = 5;

        string want = "00000020"
            + "abababababababababababababababababababababababababababababababab"
            + "0000000400000003"   // prev_chain_len
            + "0000000400000007"   // n
            + "00000000"           // kem_ciphertext absent
            + "00000000"           // kem_pub_for_reply absent
            + "0000000400000005";  // CkptN
        uint8[] marshalled = bytes_to_array(h.marshal());
        fail_if_not_eq_uint8_arr(hex_to_bin(want), marshalled, "MessageHeader v6-field encoding mismatch");

        MessageHeader? round = MessageHeader.unmarshal(new Bytes(marshalled));
        fail_if(round == null, "six-field header must unmarshal");
        fail_if_not_eq_int((int) ((!) round).ckpt_n, 5, "CkptN did not round-trip");

        // The same header truncated to five fields: MUST be rejected.
        uint8[] five = hex_to_bin(want.substring(0, want.length - 16));
        fail_if(MessageHeader.unmarshal(new Bytes(five)) != null,
            "a header that ends after five fields must be rejected");

        // CKPT_NONE must round-trip as 0xFFFFFFFF, not be normalised away.
        MessageHeader none = new MessageHeader();
        none.dh_pub = new Bytes(dh);
        MessageHeader? none_round = MessageHeader.unmarshal(none.marshal());
        fail_if(none_round == null, "default header must unmarshal");
        fail_if_not(((!) none_round).ckpt_n == CKPT_NONE, "default CkptN must be 0xFFFFFFFF");
    }

    // Message N+1 (post-checkpoint) overtakes checkpoint-bearing message N.
    //
    // Pre-fix, the receiver had no way to know a STATE TRANSITION was missing: it
    // advanced the pre-checkpoint chain and derived the wrong key, and the
    // skipped-key cache could not help. Now N+1 is deferred with state untouched,
    // and decrypts once N arrives.
    private void test_checkpoint_overtake_defers_then_recovers() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();
            SessionBootstrap a;
            SessionState b;
            establish(alice, bob, out a, out b);

            roundtrip(a.state, b);      // A->B
            roundtrip(b, a.state);      // B->A, so Alice learns Bob's KEM pub

            // Alice checkpoints on message N, then sends N+1 on the post-checkpoint chain.
            a.state.last_checkpoint_time = 0;
            Bytes n_key = Crypto.random_bytes(44);
            MessageHeader n_h; Bytes n_ct;
            encrypt_transport_key(a.state, n_key, out n_h, out n_ct);
            fail_if(n_h.kem_ciphertext == null, "message N must carry the checkpoint");
            fail_if_not(n_h.ckpt_n == CKPT_NONE,
                "the checkpoint-bearing message must advertise the value from BEFORE its own checkpoint");

            Bytes n1_key = Crypto.random_bytes(44);
            MessageHeader n1_h; Bytes n1_ct;
            encrypt_transport_key(a.state, n1_key, out n1_h, out n1_ct);
            fail_if_not(n1_h.ckpt_n == n_h.n,
                "the next message must advertise the index the checkpoint was applied at");

            string before = b.serialize();

            // N+1 arrives first: deferred, and the ratchet must be untouched.
            bool deferred = false;
            try {
                decrypt_transport_key(b, n1_h, n1_ct);
            } catch (PairwiseSessionError.CHECKPOINT_DEFERRED de) {
                deferred = true;
            }
            fail_if_not(deferred, "a message that overtook a checkpoint must be deferred");
            fail_if_not_eq_str(before, b.serialize(), "deferral must not touch ratchet state");

            // N arrives and applies the checkpoint.
            Bytes got_n = decrypt_transport_key(b, n_h, n_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(n_key), bytes_to_array(got_n), "checkpoint message must decrypt");

            // The drained N+1 now decrypts.
            Bytes got_n1 = decrypt_transport_key(b, n1_h, n1_ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(n1_key), bytes_to_array(got_n1),
                "the deferred message must decrypt once the checkpoint transition has been applied");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // D3.5: a message that fails authentication must leave chain keys, recv_ckpt_n,
    // both accumulators and the skipped-key cache exactly as they were. Asserted on
    // the full serialized state, which is the digest of everything decryption
    // touches.
    private void test_failed_auth_leaves_state_unchanged() {
        try {
            TestIdentity alice = new TestIdentity();
            TestIdentity bob = new TestIdentity();
            SessionBootstrap a;
            SessionState b;
            establish(alice, bob, out a, out b);

            roundtrip(a.state, b);

            Bytes key = Crypto.random_bytes(44);
            MessageHeader h; Bytes ct;
            encrypt_transport_key(a.state, key, out h, out ct);

            // Flip a bit in the ciphertext so the GCM tag fails.
            uint8[] tampered = bytes_to_array(ct);
            tampered[0] = tampered[0] ^ 0x01;

            string before = b.serialize();
            bool threw = false;
            try {
                decrypt_transport_key(b, h, new Bytes(tampered));
            } catch (Error e) {
                threw = true;
            }
            fail_if_not(threw, "a tampered ciphertext must not decrypt");
            fail_if_not_eq_str(before, b.serialize(),
                "a message that fails authentication must leave ratchet state unchanged");

            // And the genuine message must still decrypt afterwards.
            Bytes got = decrypt_transport_key(b, h, ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(key), bytes_to_array(got),
                "the genuine message must still decrypt after a forgery attempt");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // ------------------------------------------------------------- helpers ---

    private void establish(TestIdentity alice, TestIdentity bob,
                           out SessionBootstrap a, out SessionState b) throws Error {
        PeerBundle peer_bundle = bob.to_peer_bundle();
        a = initiate_session(alice.dik_priv_x25519, alice.dik_pub_x25519, peer_bundle);
        b = respond_session(
            bob.dik_priv_x25519, bob.dik_pub_x25519,
            bob.spk_priv_x25519, bob.spk_pub_x25519,
            bob.opk_priv_x25519, bob.kem_priv,
            alice.device_certificate, alice.aik_pub_ed25519, alice.aik_pub_mldsa,
            a.prekey_ephemeral_pub, a.kem_ciphertext);
    }

    private void roundtrip(SessionState from, SessionState to) throws Error {
        Bytes k = Crypto.random_bytes(44);
        MessageHeader h; Bytes ct;
        encrypt_transport_key(from, k, out h, out ct);
        Bytes got = decrypt_transport_key(to, h, ct);
        fail_if_not_eq_uint8_arr(bytes_to_array(k), bytes_to_array(got), "roundtrip transport key mismatch");
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
    // Cross-implementation vector, same chain.
    //
    // The receiving session state below is PQonversations' CrossVectorGeneratorTest
    // fixture, carried forward unchanged apart from the two per-direction
    // accumulators and the two checkpoint indices D2/D3 introduced. The message
    // bytes had to be re-derived: D3.1 appends CkptN to the header, and the header
    // is part of the AAD, so the original ciphertexts can no longer authenticate.
    //
    // They are re-derived DETERMINISTICALLY from the same fixture — the peer's send
    // chain IS this state's recv chain, so mirroring it reproduces exactly what the
    // other implementation would emit — and then pinned, so the vector stays a
    // cross-client KAT rather than a self-consistency check.
    private void test_cross_vector_from_pqonversations() {
        try {
            SessionState? st = SessionState.deserialize(cross_vector_blob());
            fail_if(st == null, "could not load the cross-vector session state");

            // Mirror the peer's sending half of this same chain.
            SessionState peer = new SessionState();
            peer.rk = ((!) st).rk;
            peer.chain_send_key = ((!) st).chain_recv_key;
            peer.chain_recv_key = null;
            peer.sending_dh_pub = (!) ((!) st).remote_dh_pub;
            peer.sending_dh_priv = new Bytes(new uint8[32]);
            peer.remote_dh_pub = null;
            peer.send_count = ((!) st).recv_count;
            peer.recv_count = 0;
            peer.prev_send_count = 0;
            peer.kem_since_checkpoint = 0;
            peer.last_checkpoint_time = 0;
            peer.ad = ((!) st).ad;
            peer.kem_history_send = new Bytes(new uint8[32]);
            peer.kem_history_recv = new Bytes(new uint8[32]);
            peer.send_ckpt_n = CKPT_NONE;
            peer.recv_ckpt_n = CKPT_NONE;

            check_pinned_message(peer, (!) st,
                "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
                "000000204fda7cc29346c2fab2d57cf44e63d578622148a3c13f715f260dd09e893ebf4f00000004000000000000000400000001000000000000000000000004ffffffff",
                "4c83931b8c6f519b0bfe486044b9d05e2c71d0075b202f50192ff8d074d9f5063b7050a890f62bb7ff6c39218ed5a82dfd296d913e2adddd5068b4eb",
                "msg1");
            check_pinned_message(peer, (!) st,
                "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2",
                "000000204fda7cc29346c2fab2d57cf44e63d578622148a3c13f715f260dd09e893ebf4f00000004000000000000000400000002000000000000000000000004ffffffff",
                "840925e301560f289475e0c445eadd4a1f30f5bf00435c5a073bb0af2a18e2a7e41aeccb8ca41a69d38fb4a3c111adbe9dcc6cf505a542a7494eb7d8",
                "msg2");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private static string cross_vector_blob() {
        return ""
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
            + "kem_history_send=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "kem_history_recv=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "send_ckpt_n=4294967295\n"
            + "recv_ckpt_n=4294967295\n";
    }

    // Cross-implementation vector across a DH RATCHET STEP.
    //
    // Companion to the same-chain vector above, which proves only that the symmetric
    // half agrees. This one loads the receiver state captured BEFORE the peer minted
    // a new sending DH and decrypts a message bearing that new key, so it exercises
    // dh_ratchet_step — and, after D2, specifically that step 1 of the ratchet folds
    // kemHistoryRECV. If the two implementations disagree on which accumulator that
    // step consumes, this is where it shows.
    //
    // The canned message bytes could NOT be carried forward: the header now includes
    // CkptN and is covered by the AAD, and re-deriving a ratchet message needs the
    // generator's ephemeral private key, which the fixture never contained. The peer
    // side is therefore reconstructed with new_sending_state() against the fixture's
    // rk and DH public — identical inputs, freshly minted ephemeral.
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
            + "kem_history_send=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "kem_history_recv=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            + "send_ckpt_n=4294967295\n"
            + "recv_ckpt_n=4294967295\n"
            ;
            SessionState? st = SessionState.deserialize(blob);
            fail_if(st == null, "could not load the ratchet cross-vector session state");

            // Root material: only the first 32 bytes (the root key) are consumed.
            uint8[] root = new uint8[64];
            uint8[] rk = bytes_to_array(((!) st).rk);
            Memory.copy(root, rk, 32);
            SessionState peer = new_sending_state(new Bytes(root),
                bytes_to_array(((!) st).ad), ((!) st).sending_dh_pub);

            Bytes k = Crypto.random_bytes(44);
            MessageHeader h; Bytes ct;
            encrypt_transport_key(peer, k, out h, out ct);
            fail_if_not(h.ckpt_n == CKPT_NONE, "a fresh send chain must advertise CkptN = 0xFFFFFFFF");
            Bytes got = decrypt_transport_key((!) st, h, ct);
            fail_if_not_eq_uint8_arr(bytes_to_array(k), bytes_to_array(got),
                "message across a DH ratchet step must decrypt");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // Encrypt `want_hex` from `sender`, assert the resulting header/ciphertext match
    // the pinned cross-client bytes, then assert `receiver` decrypts them back.
    private void check_pinned_message(SessionState sender, SessionState receiver, string want_hex,
                                      string hdr_hex, string ct_hex, string label) throws Error {
        MessageHeader h;
        Bytes ct;
        encrypt_transport_key(sender, new Bytes(hex_to_bin(want_hex)), out h, out ct);
        fail_if_not_eq_uint8_arr(hex_to_bin(hdr_hex), bytes_to_array(h.marshal()),
            label + ": header bytes differ from the pinned cross-client vector");
        fail_if_not_eq_uint8_arr(hex_to_bin(ct_hex), bytes_to_array(ct),
            label + ": ciphertext differs from the pinned cross-client vector");
        Bytes got = decrypt_transport_key(receiver, h, ct);
        fail_if_not_eq_uint8_arr(hex_to_bin(want_hex), bytes_to_array(got),
            label + ": decrypted transport key does not match");
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
        public uint32 kem_id = 7;

        public TestIdentity() throws Error {
            Crypto.generate_ed25519(out aik_pub_ed25519, out aik_priv_ed25519);
            Crypto.generate_mldsa65(out aik_pub_mldsa, out aik_priv_mldsa);
            Crypto.generate_ed25519(out dik_pub_ed25519, out dik_priv_ed25519);
            Crypto.generate_x25519(out dik_pub_x25519, out dik_priv_x25519);
            Crypto.generate_mldsa65(out dik_pub_mldsa, out dik_priv_mldsa);
            device_certificate = DeviceCertificate.issue(1, dik_pub_ed25519, dik_pub_x25519, dik_pub_mldsa, aik_priv_ed25519, aik_priv_mldsa, 1);
            Crypto.generate_x25519(out spk_pub_x25519, out spk_priv_x25519);
            // D1: sign the domain-separated input, not the naked key.
            spk_signature_ed25519 = Crypto.ed25519_sign(dik_priv_ed25519,
                prekey_sig_message(PREKEY_TYPE_SPK, spk_id, spk_pub_x25519));
            Crypto.generate_mlkem768(out kem_pub, out kem_priv);
            kem_signature_ed25519 = Crypto.ed25519_sign(dik_priv_ed25519,
                prekey_sig_message(PREKEY_TYPE_KEM, kem_id, kem_pub));
            kem_signature_mldsa = Crypto.mldsa65_sign(dik_priv_mldsa,
                prekey_sig_message(PREKEY_TYPE_KEM, kem_id, kem_pub));
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
