namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class MembershipJournalTest : Gee.TestCase {

    public MembershipJournalTest() {
        base("MembershipJournal");
        add_test("audit_entry_marshal_roundtrip", test_audit_entry_marshal_roundtrip);
        add_test("journal_genesis_valid", test_journal_genesis_valid);
        add_test("journal_chain_valid", test_journal_chain_valid);
        add_test("journal_bad_sig_rejected", test_journal_bad_sig_rejected);
        add_test("journal_bad_chain_rejected", test_journal_bad_chain_rejected);
        add_test("journal_member_tracking", test_journal_member_tracking);
    }

    private MemberAuditEntry make_entry(
        uint64 seq,
        uint8[] prev_hash,
        uint8 action,
        uint8[] payload,
        int64 timestamp,
        Bytes priv_ed,
        Bytes priv_mldsa
    ) throws GLib.Error {
        MemberAuditEntry e = new MemberAuditEntry();
        e.seq = seq;
        e.prev_hash = prev_hash.copy();
        e.action = action;
        e.payload = payload.copy();
        e.timestamp = timestamp;
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_arr(Crypto.ed25519_sign(priv_ed, new Bytes(sp)));
        e.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(priv_mldsa, new Bytes(sp)));
        return e;
    }

    private void test_audit_entry_marshal_roundtrip() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            uint8[] fp_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] payload = MemberAuditEntry.build_member_payload(fp_raw, 1);
            MemberAuditEntry e = make_entry(0, new uint8[32], (uint8) MemberAuditAction.ADD_MEMBER, payload, 1000, ed_priv, ml_priv);
            uint8[] wire = e.marshal();
            MemberAuditEntry? e2 = MemberAuditEntry.unmarshal(wire);
            fail_if(e2 == null, "unmarshal returned null");
            fail_if_not_eq_int((int)((!) e2).seq, 0, "seq mismatch");
            fail_if_not_eq_int((int)((!) e2).action, (int) MemberAuditAction.ADD_MEMBER, "action mismatch");
            // Verify against the owner's AIK.
            bool ok = ((!) e2).verify(ed_pub, ml_pub);
            fail_if_not(ok, "verify after roundtrip failed");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_journal_genesis_valid() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            uint8[] fp_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] payload = MemberAuditEntry.build_member_payload(fp_raw, 1);
            MemberAuditEntry e0 = make_entry(0, new uint8[32], (uint8) MemberAuditAction.ADD_MEMBER, payload, 1000, ed_priv, ml_priv);

            MembershipJournal journal = new MembershipJournal();
            bool ok = journal.append(e0, ed_pub, ml_pub);
            fail_if_not(ok, "genesis entry should be accepted");
            fail_if_not(journal.has_any_entries(), "journal should have entries");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_journal_chain_valid() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            uint8[] fp_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] fp2_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] payload0 = MemberAuditEntry.build_member_payload(fp_raw, 1);
            uint8[] payload1 = MemberAuditEntry.build_member_payload(fp2_raw, 2);

            MemberAuditEntry e0 = make_entry(0, new uint8[32], (uint8) MemberAuditAction.ADD_MEMBER, payload0, 1000, ed_priv, ml_priv);
            uint8[] h0 = e0.compute_hash();
            MemberAuditEntry e1 = make_entry(1, h0, (uint8) MemberAuditAction.ADD_MEMBER, payload1, 1001, ed_priv, ml_priv);

            MembershipJournal journal = new MembershipJournal();
            bool ok0 = journal.append(e0, ed_pub, ml_pub);
            fail_if_not(ok0, "e0 should be accepted");
            bool ok1 = journal.append(e1, ed_pub, ml_pub);
            fail_if_not(ok1, "e1 should be accepted");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_journal_bad_sig_rejected() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            // Different key pair for signing — wrong signer.
            Bytes bad_ed_pub; Bytes bad_ed_priv; Crypto.generate_ed25519(out bad_ed_pub, out bad_ed_priv);
            Bytes bad_ml_pub; Bytes bad_ml_priv; Crypto.generate_mldsa65(out bad_ml_pub, out bad_ml_priv);

            uint8[] fp_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] payload = MemberAuditEntry.build_member_payload(fp_raw, 1);
            // Sign with bad key.
            MemberAuditEntry e0 = make_entry(0, new uint8[32], (uint8) MemberAuditAction.ADD_MEMBER, payload, 1000, bad_ed_priv, bad_ml_priv);

            MembershipJournal journal = new MembershipJournal();
            bool ok = journal.append(e0, ed_pub, ml_pub);  // verify against correct owner key
            fail_if(ok, "bad-sig entry must be rejected");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_journal_bad_chain_rejected() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            uint8[] fp_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] fp2_raw = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] payload0 = MemberAuditEntry.build_member_payload(fp_raw, 1);
            uint8[] payload1 = MemberAuditEntry.build_member_payload(fp2_raw, 2);

            MemberAuditEntry e0 = make_entry(0, new uint8[32], (uint8) MemberAuditAction.ADD_MEMBER, payload0, 1000, ed_priv, ml_priv);
            // e1 has wrong prev_hash (random instead of hash of e0).
            uint8[] wrong_hash = bytes_to_arr(Crypto.random_bytes(32));
            MemberAuditEntry e1_bad = make_entry(1, wrong_hash, (uint8) MemberAuditAction.ADD_MEMBER, payload1, 1001, ed_priv, ml_priv);

            MembershipJournal journal = new MembershipJournal();
            journal.append(e0, ed_pub, ml_pub);
            bool ok = journal.append(e1_bad, ed_pub, ml_pub);
            fail_if(ok, "bad-chain entry must be rejected");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_journal_member_tracking() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            uint8[] fp1 = bytes_to_arr(Crypto.random_bytes(20));
            uint8[] fp2 = bytes_to_arr(Crypto.random_bytes(20));

            MemberAuditEntry e0 = make_entry(0, new uint8[32], (uint8) MemberAuditAction.ADD_MEMBER,
                MemberAuditEntry.build_member_payload(fp1, 1), 1000, ed_priv, ml_priv);
            MemberAuditEntry e1 = make_entry(1, e0.compute_hash(), (uint8) MemberAuditAction.ADD_MEMBER,
                MemberAuditEntry.build_member_payload(fp2, 2), 1001, ed_priv, ml_priv);
            // Remove fp2.
            MemberAuditEntry e2 = make_entry(2, e1.compute_hash(), (uint8) MemberAuditAction.REMOVE_MEMBER,
                MemberAuditEntry.build_member_payload(fp2, 3), 1002, ed_priv, ml_priv);

            MembershipJournal journal = new MembershipJournal();
            fail_if_not(journal.append(e0, ed_pub, ml_pub), "e0");
            fail_if_not(journal.append(e1, ed_pub, ml_pub), "e1");
            fail_if_not(journal.append(e2, ed_pub, ml_pub), "e2");

            string fp1_hex = hex(fp1);
            string fp2_hex = hex(fp2);
            fail_if_not(journal.get_members().has_key(fp1_hex), "fp1 should be a member");
            fail_if(journal.get_members().has_key(fp2_hex), "fp2 should be removed from members");
            fail_if_not(journal.get_removed_aiks().has_key(fp2_hex), "fp2 should be in removed_aiks");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private static string hex(uint8[] b) {
        StringBuilder sb = new StringBuilder();
        foreach (uint8 byte in b) {
            sb.append_printf("%02x", byte);
        }
        return sb.str;
    }

    private static uint8[] bytes_to_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }
}

}
