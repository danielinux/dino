namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class GroupSessionTest : Gee.TestCase {

    public GroupSessionTest() {
        base("GroupSession");
        add_test("senderchain_step_ratchet", test_senderchain_step_ratchet);
        add_test("senderchain_marshal_roundtrip", test_senderchain_marshal_roundtrip);
        add_test("senderchain_skipped_keys", test_senderchain_skipped_keys);
        add_test("groupmsg_header_roundtrip", test_groupmsg_header_roundtrip);
        add_test("groupmsg_nonce_aad", test_groupmsg_nonce_aad);
        add_test("groupmsg_aad_binds_heads", test_groupmsg_aad_binds_heads);
        add_test("groupshare_marshal_roundtrip", test_groupshare_marshal_roundtrip);
        add_test("groupsession_encrypt_decrypt", test_groupsession_encrypt_decrypt);
        add_test("groupsession_epoch_rotation_on_add", test_groupsession_epoch_rotation_on_add);
        add_test("groupsession_epoch_rotation_on_remove", test_groupsession_epoch_rotation_on_remove);
        add_test("groupsession_removed_member_rejected", test_groupsession_removed_member_rejected);
        add_test("groupsession_serialize_deserialize", test_groupsession_serialize_deserialize);
        add_test("groupsession_checkpoint_bounds_history", test_groupsession_checkpoint_bounds_history);
        add_test("member_cannot_forge_another_senders_signature", test_member_cannot_forge_signature);
    }

    private static uint8[] make_aik_bytes(uint8[] ed32, uint8[] mldsa) {
        // canonical: uint16(1) | uint8(1) | ed32(32) | mldsa
        uint8[] buf = new uint8[2 + 1 + 32 + mldsa.length];
        buf[0] = 0; buf[1] = 1; buf[2] = 1;
        Memory.copy((uint8*) buf + 3, ed32, 32);
        if (mldsa.length > 0) {
            Memory.copy((uint8*) buf + 35, mldsa, mldsa.length);
        }
        return buf;
    }

    private static GroupMember make_member(uint8[] aik_bytes, uint32 device_id) {
        GroupMember m = new GroupMember();
        m.aik_pub_bytes = aik_bytes.copy();
        m.device_ids.add(device_id);
        return m;
    }

    private void test_senderchain_step_ratchet() {
        try {
            SenderChain sc = SenderChain.new_random(0);
            uint32 idx0;
            uint8[]? mk0 = sc.step(out idx0);
            fail_if(mk0 == null, "step returned null");
            fail_if_not_eq_int((int) idx0, 0, "first index should be 0");
            fail_if_not_eq_int((int) sc.next_index, 1, "next_index should advance");

            uint32 idx1;
            uint8[]? mk1 = sc.step(out idx1);
            fail_if(mk1 == null, "step2 returned null");
            fail_if_not_eq_int((int) idx1, 1, "second index should be 1");
            // keys must differ
            fail_if(Base64.encode(mk0) == Base64.encode(mk1), "message keys must differ");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_senderchain_marshal_roundtrip() {
        try {
            SenderChain sc = SenderChain.new_random(7);
            uint32 idx;
            sc.step(out idx);  // advance once
            uint8[] marshalled = sc.marshal();
            SenderChain? restored = SenderChain.unmarshal(marshalled);
            fail_if(restored == null, "unmarshal returned null");
            fail_if_not_eq_int((int)(!) restored.epoch, 7, "epoch mismatch");
            fail_if_not_eq_int((int)(!) restored.next_index, 1, "next_index mismatch");
            fail_if_not_eq_uint8_arr(sc.chain_key, ((!) restored).chain_key, "chain_key mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_senderchain_skipped_keys() {
        try {
            SenderChain sender = SenderChain.new_random(0);
            // Sender advances to index 5.
            uint8[] mk5 = null;
            for (uint32 i = 0; i <= 5; i++) {
                uint32 idx;
                uint8[]? mk = sender.step(out idx);
                if (idx == 5) mk5 = mk;
            }
            fail_if(mk5 == null, "mk5 should be set");

            // Receiver gets chain from start, but asks for index 5 directly.
            SenderChain recv = SenderChain.restore(0, sender.chain_key.copy(), 0);
            // Give the recv chain a clone with the original key.
            SenderChain recv2 = SenderChain.new_random(0);
            // Re-create from original ck (epoch 0):
            // We need the original chain key. Restart a fresh sender.
            SenderChain sender2 = SenderChain.new_random(0);
            uint8[] mk5_s = null;
            for (uint32 i = 0; i <= 5; i++) {
                uint32 idx;
                uint8[]? mk = sender2.step(out idx);
                if (idx == 5) mk5_s = mk;
            }
            // Receiver shares the same starting ck — we copy it before any steps.
            SenderChain sender3 = SenderChain.new_random(0);
            uint8[] orig_ck = sender3.chain_key.copy();
            SenderChain recv3 = SenderChain.restore(0, orig_ck, 0);
            // Advance sender3 to step 5.
            uint8[] mk5_sender3 = null;
            for (uint32 i = 0; i <= 5; i++) {
                uint32 idx;
                uint8[]? mk = sender3.step(out idx);
                if (idx == 5) mk5_sender3 = mk;
            }
            // Receiver asks for index 5 — should cache 0..4 and return 5.
            uint8[]? mk5_recv = recv3.message_key_at(5);
            fail_if(mk5_recv == null, "message_key_at returned null");
            fail_if_not_eq_uint8_arr(mk5_sender3, mk5_recv, "skipped key mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_groupmsg_header_roundtrip() {
        GroupMessageHeader h = new GroupMessageHeader();
        h.version = 1;
        h.epoch = 3;
        h.sender_device_id = (uint32) 0xdeadbeef;
        h.chain_index = 42;
        uint8[] bytes = h.marshal();
        fail_if_not_eq_int(bytes.length, 14, "header must be 14 bytes");
        GroupMessageHeader? h2 = GroupMessageHeader.unmarshal(bytes);
        fail_if(h2 == null, "unmarshal returned null");
        fail_if_not_eq_int((int)((!) h2).epoch, 3, "epoch mismatch");
        fail_if_not_eq_int((int)((!) h2).chain_index, 42, "chain_index mismatch");
    }

    private void test_groupmsg_nonce_aad() {
        GroupMessageHeader h = new GroupMessageHeader();
        h.version = 1; h.epoch = 1; h.sender_device_id = 2; h.chain_index = 3;
        uint8[] nonce = h.aead_nonce();
        fail_if_not_eq_int(nonce.length, 12, "nonce must be 12 bytes");
        fail_if_not_eq_int((int) nonce[0], (int) 'G', "nonce[0] must be G");
        fail_if_not_eq_int((int) nonce[1], (int) 'M', "nonce[1] must be M");
        fail_if_not_eq_int((int) nonce[2], (int) 'S', "nonce[2] must be S");
        fail_if_not_eq_int((int) nonce[3], (int) 'G', "nonce[3] must be G");
        uint8[] aad = h.aad("room@example.org");
        fail_if_not_eq_int(aad.length, 14 + "room@example.org".length + 1,
            "aad = header + roomJID + 1-byte absent-heads marker");
        fail_if_not_eq_int((int) aad[aad.length - 1], 0x00,
            "absent <heads> must be encoded as a 0x00 marker");
    }

    // §13.1b: the advertisement is bound into the AAD by value AND presence, so a relay
    // that strips it, blanks it, or substitutes another frontier produces a different AAD
    // and the tag fails. Without the marker, "stripped" would be indistinguishable from
    // "sender had no frontier" — exactly the forgery the binding prevents.
    private void test_groupmsg_aad_binds_heads() {
        GroupMessageHeader h = new GroupMessageHeader();
        h.version = 1; h.epoch = 7; h.sender_device_id = 1; h.chain_index = 3;
        string room = "room@example.org";

        uint8[] heads_a = new uint8[34];
        heads_a[1] = 1; // n_heads = 1
        for (int i = 2; i < 34; i++) heads_a[i] = 0xAA;
        uint8[] heads_b = heads_a.copy();
        heads_b[33] = 0xBB; // same length, different frontier

        uint8[] absent = h.aad_with_heads(room, null);
        uint8[] present = h.aad_with_heads(room, heads_a);
        uint8[] other = h.aad_with_heads(room, heads_b);

        fail_if_not_eq_int(present.length, 14 + room.length + 3 + heads_a.length,
            "present <heads> contributes marker + uint16 length + payload");
        fail_if_not_eq_int((int) present[14 + room.length], 0x01,
            "present <heads> must be encoded with a 0x01 marker");

        fail_if(absent.length == present.length && Memory.cmp(absent, present, absent.length) == 0,
            "stripping <heads> must change the AAD");
        fail_if(Memory.cmp(present, other, present.length) == 0,
            "substituting a different frontier must change the AAD");
    }

    private void test_groupshare_marshal_roundtrip() {
        try {
            Bytes ed_pub;
            Bytes ed_priv;
            Bytes mldsa_pub;
            Bytes mldsa_priv;
            Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Crypto.generate_mldsa65(out mldsa_pub, out mldsa_priv);
            uint8[] ed = bytes_to_arr(ed_pub);
            uint8[] mldsa = bytes_to_arr(mldsa_pub);
            uint8[] aik_bytes = make_aik_bytes(ed, mldsa);

            SenderChainAnnouncement ann = new SenderChainAnnouncement();
            uint8[] test_sig_pub = new uint8[32];
            for (int i = 0; i < 32; i++) test_sig_pub[i] = 0x5A;
            ann.sig_pub = test_sig_pub;
            ann.sender_aik_pub_bytes = aik_bytes;
            ann.sender_device_id = 99;
            ann.room_jid = "test@conference.example.org";
            ann.epoch = 2;
            ann.chain_key = bytes_to_arr(Crypto.random_bytes(32));
            ann.next_index = 7;

            uint8[] wire = ann.marshal();
            SenderChainAnnouncement? ann2 = SenderChainAnnouncement.unmarshal(wire);
            fail_if(ann2 == null, "unmarshal returned null");
            fail_if_not_eq_int((int)((!) ann2).sender_device_id, 99, "device_id mismatch");
            fail_if_not_eq_str(((!) ann2).room_jid, "test@conference.example.org", "room_jid mismatch");
            fail_if_not_eq_int((int)((!) ann2).epoch, 2, "epoch mismatch");
            fail_if_not_eq_int((int)((!) ann2).next_index, 7, "next_index mismatch");
            fail_if_not_eq_uint8_arr(ann.chain_key, ((!) ann2).chain_key, "chain_key mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_groupsession_encrypt_decrypt() {
        try {
            Bytes alice_ed_pub; Bytes alice_ed_priv;
            Bytes alice_mldsa_pub; Bytes alice_mldsa_priv;
            Crypto.generate_ed25519(out alice_ed_pub, out alice_ed_priv);
            Crypto.generate_mldsa65(out alice_mldsa_pub, out alice_mldsa_priv);
            uint8[] alice_aik = make_aik_bytes(bytes_to_arr(alice_ed_pub), bytes_to_arr(alice_mldsa_pub));

            Bytes bob_ed_pub; Bytes bob_ed_priv;
            Bytes bob_mldsa_pub; Bytes bob_mldsa_priv;
            Crypto.generate_ed25519(out bob_ed_pub, out bob_ed_priv);
            Crypto.generate_mldsa65(out bob_mldsa_pub, out bob_mldsa_priv);
            uint8[] bob_aik = make_aik_bytes(bytes_to_arr(bob_ed_pub), bytes_to_arr(bob_mldsa_pub));

            string room = "room@conference.example.org";
            GroupSession alice_gs = GroupSession.new_session(room, alice_aik, 1);
            GroupSession bob_gs = GroupSession.new_session(room, bob_aik, 2);

            // Add each other as members.
            GroupMember alice_member = make_member(alice_aik, 1);
            GroupMember bob_member = make_member(bob_aik, 2);
            alice_gs.add_member(bob_member);
            bob_gs.add_member(alice_member);

            // Alice announces her sender chain to Bob.
            SenderChainAnnouncement ann = alice_gs.announce_sender_chain();
            bob_gs.accept_sender_chain(ann);

            // Alice encrypts.
            uint8[] plaintext = string_to_bytes("hello group");
            GroupMessageHeader hdr;
            uint8[] ciphertext;
            uint8[] gsig;
            alice_gs.encrypt(plaintext, out hdr, out ciphertext, out gsig);

            // Bob decrypts, verifying Alice's §13.3a sender signature.
            string alice_fp = ann.aik_fingerprint();
            uint8[] decrypted = bob_gs.decrypt(alice_fp, hdr, ciphertext, gsig);
            fail_if_not_eq_uint8_arr(plaintext, decrypted, "group encrypt/decrypt mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    /* §13.3a — THE forgery test. Mirrors PQonversations'
     * GroupSessionTest.memberHoldingAnotherSenderChainCannotForgeTheirSignature.
     *
     * Alice announces her sender chain. Mallory is an ordinary member, so she legitimately
     * receives Alice's chain key and can derive every future message key on Alice's chain —
     * she can produce a ciphertext that decrypts cleanly and whose header names Alice. What
     * she cannot do is sign it: the per-epoch signing key stays private to Alice and only
     * its public half is distributed. That asymmetry is the entire mechanism. */
    private void test_member_cannot_forge_signature() {
        try {
            Bytes ed1; Bytes priv1; Crypto.generate_ed25519(out ed1, out priv1);
            Bytes ml1; Bytes mlpriv1; Crypto.generate_mldsa65(out ml1, out mlpriv1);
            uint8[] alice_aik = make_aik_bytes(bytes_to_arr(ed1), bytes_to_arr(ml1));

            GroupSession alice = GroupSession.new_session("r@x", alice_aik, 1);
            SenderChainAnnouncement ann = alice.announce_sender_chain();

            /* The announcement really does hand over the symmetric chain key — Mallory is a
             * full member and nothing here is stolen. */
            fail_if_not_eq_uint8_arr(alice.send_chain.chain_key, ann.chain_key,
                "the announcement carries the symmetric chain key");
            /* ...but only the PUBLIC half of the signing key travels. */
            fail_if_not_eq_uint8_arr(alice.send_chain.sig_pub, ann.sig_pub,
                "the announcement carries the public verification key");
            fail_if_not_eq_int(alice.send_chain.sig_priv.length, 64,
                "Alice retains a signing private key");

            uint8[] msg = string_to_bytes("forged group message");

            /* A signature made with any key Mallory can construct does not verify under
             * Alice's advertised key. */
            Bytes m_pub; Bytes m_priv;
            Crypto.generate_ed25519(out m_pub, out m_priv);
            Bytes forged = Crypto.ed25519_sign(m_priv, new Bytes(msg));
            /* wolfSSL raises SIG_VERIFY_E rather than returning false, so a rejected
             * forgery may arrive as either shape. Both count as "not verified". */
            bool forged_verified;
            try {
                forged_verified = Crypto.ed25519_verify(new Bytes(ann.sig_pub), new Bytes(msg), forged);
            } catch (GLib.Error e) {
                forged_verified = false;
            }
            fail_if(forged_verified,
                "a member holding the chain key must not be able to sign as the chain owner");

            /* And the genuine sender's signature does verify, so the scheme is usable. */
            Bytes genuine = Crypto.ed25519_sign(new Bytes(alice.send_chain.sig_priv), new Bytes(msg));
            fail_if_not(Crypto.ed25519_verify(new Bytes(ann.sig_pub), new Bytes(msg), genuine),
                "the real sender's signature must verify under the advertised key");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_groupsession_epoch_rotation_on_add() {
        try {
            Bytes ed1; Bytes priv1; Crypto.generate_ed25519(out ed1, out priv1);
            Bytes ml1; Bytes mlpriv1; Crypto.generate_mldsa65(out ml1, out mlpriv1);
            uint8[] aik1 = make_aik_bytes(bytes_to_arr(ed1), bytes_to_arr(ml1));
            GroupSession gs = GroupSession.new_session("r@x", aik1, 1);
            fail_if_not_eq_int((int) gs.epoch, 0, "initial epoch should be 0");

            Bytes ed2; Bytes priv2; Crypto.generate_ed25519(out ed2, out priv2);
            Bytes ml2; Bytes mlpriv2; Crypto.generate_mldsa65(out ml2, out mlpriv2);
            uint8[] aik2 = make_aik_bytes(bytes_to_arr(ed2), bytes_to_arr(ml2));
            gs.add_member(make_member(aik2, 2));
            fail_if_not_eq_int((int) gs.epoch, 1, "epoch should be 1 after add");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_groupsession_epoch_rotation_on_remove() {
        try {
            Bytes ed1; Bytes priv1; Crypto.generate_ed25519(out ed1, out priv1);
            Bytes ml1; Bytes mlpriv1; Crypto.generate_mldsa65(out ml1, out mlpriv1);
            uint8[] aik1 = make_aik_bytes(bytes_to_arr(ed1), bytes_to_arr(ml1));
            GroupSession gs = GroupSession.new_session("r@x", aik1, 1);

            Bytes ed2; Bytes priv2; Crypto.generate_ed25519(out ed2, out priv2);
            Bytes ml2; Bytes mlpriv2; Crypto.generate_mldsa65(out ml2, out mlpriv2);
            uint8[] aik2 = make_aik_bytes(bytes_to_arr(ed2), bytes_to_arr(ml2));
            GroupMember m2 = make_member(aik2, 2);
            gs.add_member(m2);
            string fp2 = m2.fingerprint();
            uint32 epoch_after_add = gs.epoch;
            gs.remove_member_by_fp(fp2);
            fail_if_not(gs.epoch > epoch_after_add, "epoch should increase after remove");
            fail_if_not(gs.is_removed(fp2), "removed member should be in removed_aiks");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_groupsession_removed_member_rejected() {
        try {
            Bytes ed1; Bytes priv1; Crypto.generate_ed25519(out ed1, out priv1);
            Bytes ml1; Bytes mlpriv1; Crypto.generate_mldsa65(out ml1, out mlpriv1);
            uint8[] aik1 = make_aik_bytes(bytes_to_arr(ed1), bytes_to_arr(ml1));
            GroupSession gs = GroupSession.new_session("r@x", aik1, 1);

            Bytes ed2; Bytes priv2; Crypto.generate_ed25519(out ed2, out priv2);
            Bytes ml2; Bytes mlpriv2; Crypto.generate_mldsa65(out ml2, out mlpriv2);
            uint8[] aik2 = make_aik_bytes(bytes_to_arr(ed2), bytes_to_arr(ml2));
            GroupMember m2 = make_member(aik2, 2);
            gs.add_member(m2);
            string fp2 = m2.fingerprint();

            // Install a recv chain for m2 so we can test rejection.
            SenderChainAnnouncement ann = new SenderChainAnnouncement();
            uint8[] test_sig_pub = new uint8[32];
            for (int i = 0; i < 32; i++) test_sig_pub[i] = 0x5A;
            ann.sig_pub = test_sig_pub;
            ann.sender_aik_pub_bytes = aik2.copy();
            ann.sender_device_id = 2;
            ann.room_jid = "r@x";
            ann.epoch = gs.epoch;
            ann.chain_key = bytes_to_arr(Crypto.random_bytes(32));
            ann.next_index = 0;
            gs.accept_sender_chain(ann);

            // Encrypt a message from m2's perspective using a dummy gs.
            GroupSession m2_gs = GroupSession.new_session("r@x", aik2, 2);
            m2_gs.add_member(make_member(aik1, 1));
            SenderChainAnnouncement ann2 = m2_gs.announce_sender_chain();
            // Now remove m2 from gs.
            gs.remove_member_by_fp(fp2);

            // Attempt to decrypt a message from the removed member — must fail.
            GroupMessageHeader hdr = new GroupMessageHeader();
            hdr.version = 1; hdr.epoch = ann.epoch; hdr.sender_device_id = 2; hdr.chain_index = 0;
            bool got_error = false;
            try {
                gs.decrypt(fp2, hdr, new uint8[32], new uint8[64]);
            } catch (GLib.Error e) {
                got_error = true;
            }
            fail_if_not(got_error, "decrypt from removed member must fail");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_groupsession_serialize_deserialize() {
        try {
            Bytes ed1; Bytes priv1; Crypto.generate_ed25519(out ed1, out priv1);
            Bytes ml1; Bytes mlpriv1; Crypto.generate_mldsa65(out ml1, out mlpriv1);
            uint8[] aik1 = make_aik_bytes(bytes_to_arr(ed1), bytes_to_arr(ml1));
            GroupSession gs = GroupSession.new_session("room@x", aik1, 1);

            Bytes ed2; Bytes priv2; Crypto.generate_ed25519(out ed2, out priv2);
            Bytes ml2; Bytes mlpriv2; Crypto.generate_mldsa65(out ml2, out mlpriv2);
            uint8[] aik2 = make_aik_bytes(bytes_to_arr(ed2), bytes_to_arr(ml2));
            gs.add_member(make_member(aik2, 2));

            string ss = gs.serialize_send_state();
            string ms = gs.serialize_member_state() + gs.serialize_recv_chains();
            GroupSession? gs2 = GroupSession.deserialize("room@x", aik1, 1, ss, ms);
            fail_if(gs2 == null, "deserialize returned null");
            fail_if_not_eq_int((int)((!) gs2).epoch, (int) gs.epoch, "epoch mismatch after deserialize");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    // The announce checkpoint bounds re-shareable history: a member that installs
    // from an ADVANCED checkpoint can decrypt messages at/after it but not before,
    // while a fresh session announces from index 0 (whole epoch available).
    private void test_groupsession_checkpoint_bounds_history() {
        try {
            Bytes aed; Bytes apriv; Crypto.generate_ed25519(out aed, out apriv);
            Bytes aml; Bytes amlpriv; Crypto.generate_mldsa65(out aml, out amlpriv);
            uint8[] alice_aik = make_aik_bytes(bytes_to_arr(aed), bytes_to_arr(aml));
            Bytes bed; Bytes bpriv; Crypto.generate_ed25519(out bed, out bpriv);
            Bytes bml; Bytes bmlpriv; Crypto.generate_mldsa65(out bml, out bmlpriv);
            uint8[] bob_aik = make_aik_bytes(bytes_to_arr(bed), bytes_to_arr(bml));

            string room = "room@conference.example.org";
            GroupSession alice = GroupSession.new_session(room, alice_aik, 1);
            alice.add_member(make_member(bob_aik, 2));

            // Fresh epoch: the checkpoint sits at index 0 → announce exports 0.
            SenderChainAnnouncement a0 = alice.announce_sender_chain();
            fail_if_not_eq_int((int) a0.next_index, 0, "fresh checkpoint must be index 0");

            // Advance the send chain past a few messages.
            for (int i = 0; i < 3; i++) {
                GroupMessageHeader hh; uint8[] cc; uint8[] ss;
                alice.encrypt(string_to_bytes("m"), out hh, out cc, out ss);
            }

            // Stamp the checkpoint start (t=1000), then elapse the 100s window.
            alice.maybe_advance_checkpoint(1000, 100);
            bool moved = alice.maybe_advance_checkpoint(1200, 100);
            fail_if_not(moved, "checkpoint must advance once the window elapses");

            // Announce now exports the advanced position (live index 3), not 0.
            SenderChainAnnouncement a1 = alice.announce_sender_chain();
            fail_if_not_eq_int((int) a1.next_index, 3, "checkpoint must advance to live index 3");

            // A member joining now installs from the advanced checkpoint.
            GroupSession bob = GroupSession.new_session(room, bob_aik, 2);
            bob.add_member(make_member(alice_aik, 1));
            bob.accept_sender_chain(a1);
            string alice_fp = a1.aik_fingerprint();

            // Post-checkpoint message (index 3) decrypts.
            GroupMessageHeader h3; uint8[] ct3; uint8[] sig3;
            alice.encrypt(string_to_bytes("after"), out h3, out ct3, out sig3);
            uint8[] dec = bob.decrypt(alice_fp, h3, ct3, sig3);
            fail_if_not_eq_uint8_arr(string_to_bytes("after"), dec, "post-checkpoint message must decrypt");

            // Pre-checkpoint message (index 1) must NOT be decryptable.
            GroupMessageHeader hpre = new GroupMessageHeader();
            hpre.version = 1; hpre.epoch = a1.epoch; hpre.sender_device_id = 1; hpre.chain_index = 1;
            bool pre_failed = false;
            try {
                bob.decrypt(alice_fp, hpre, new uint8[32], new uint8[64]);
            } catch (GLib.Error e) {
                pre_failed = true;
            }
            fail_if_not(pre_failed, "pre-checkpoint message must not be decryptable");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private static uint8[] bytes_to_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }

    private static uint8[] string_to_bytes(string s) {
        return ((uint8[]) s.data).copy();
    }
}

}
