namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class AccountAuditTest : Gee.TestCase {

    public AccountAuditTest() {
        base("AccountAudit");
        add_test("entry_marshal_roundtrip", test_entry_marshal_roundtrip);
        add_test("chain_valid_two_entries", test_chain_valid_two_entries);
        add_test("signal_fires_for_each_entry", test_signal_fires_for_each_entry);
        add_test("bad_sig_rejected", test_bad_sig_rejected);
        add_test("bad_chain_rejected", test_bad_chain_rejected);
        add_test("bad_seq_rejected", test_bad_seq_rejected);
        add_test("timestamp_regression_rejected", test_timestamp_regression_rejected);
    }

    private AuditEntry make_entry(
        uint64 seq,
        uint8[] prev_hash,
        uint8 action,
        uint8[] payload,
        int64 timestamp,
        Bytes priv_ed,
        Bytes priv_mldsa
    ) throws GLib.Error {
        AuditEntry e = new AuditEntry();
        e.seq = seq;
        e.prev_hash = prev_hash.copy();
        e.action = action;
        e.payload = payload.copy();
        e.timestamp = timestamp;
        uint8[] sp = e.signed_part();
        Bytes sig = Crypto.ed25519_sign(priv_ed, new Bytes(sp));
        e.signature = arr(sig);
        Bytes ml = Crypto.mldsa65_sign(priv_mldsa, new Bytes(sp));
        e.mldsa_signature = arr(ml);
        return e;
    }

    private void test_entry_marshal_roundtrip() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);

            AuditEntry e = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                { 0x00, 0x00, 0x01, 0x00 }, 1000, ed_priv, ml_priv);
            uint8[] wire = e.marshal();
            AuditEntry? e2 = AuditEntry.unmarshal(wire);
            fail_if(e2 == null, "unmarshal returned null");
            fail_if_not_eq_int((int)((!) e2).seq, 0, "seq");
            fail_if_not_eq_int((int)((!) e2).action, (int) AccountAuditAction.ADD_DEVICE, "action");
            bool ok = ((!) e2).verify(ed_pub, ml_pub);
            fail_if_not(ok, "verify after roundtrip");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_chain_valid_two_entries() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);

            AuditEntry e0 = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                { 0x00, 0x00, 0x01, 0x00 }, 1000, ed_priv, ml_priv);
            uint8[] h0 = e0.compute_hash();
            AuditEntry e1 = make_entry(1, h0, (uint8) AccountAuditAction.REMOVE_DEVICE,
                { 0x00, 0x00, 0x01, 0x00 }, 1001, ed_priv, ml_priv);

            var chain = new Gee.ArrayList<AuditEntry>();
            chain.add(e0);
            chain.add(e1);

            AccountAuditChain verifier = new AccountAuditChain(null);
            verifier.verify_and_apply(1, ed_pub, ml_pub, chain);
            fail_if_not(verifier.has_entries(), "chain should have entries");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_signal_fires_for_each_entry() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);

            AuditEntry e0 = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                { 0x00, 0x00, 0x01, 0x00 }, 1000, ed_priv, ml_priv);
            uint8[] h0 = e0.compute_hash();
            AuditEntry e1 = make_entry(1, h0, (uint8) AccountAuditAction.REMOVE_DEVICE,
                { 0x00, 0x00, 0x01, 0x00 }, 1001, ed_priv, ml_priv);

            var chain = new Gee.ArrayList<AuditEntry>();
            chain.add(e0);
            chain.add(e1);

            AccountAuditChain verifier = new AccountAuditChain(null);
            int fire_count = 0;
            verifier.audit_entry_observed.connect((action, detail) => {
                fire_count++;
            });
            verifier.verify_and_apply(1, ed_pub, ml_pub, chain);
            fail_if_not_eq_int(fire_count, 2, "signal should fire twice for a 2-entry chain");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_bad_sig_rejected() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);
            Bytes bad_ed_pub; Bytes bad_ed_priv; Crypto.generate_ed25519(out bad_ed_pub, out bad_ed_priv);
            Bytes bad_ml_pub; Bytes bad_ml_priv; Crypto.generate_mldsa65(out bad_ml_pub, out bad_ml_priv);

            // Signed with wrong key pair.
            AuditEntry e0 = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                {}, 1000, bad_ed_priv, bad_ml_priv);

            var chain = new Gee.ArrayList<AuditEntry>();
            chain.add(e0);

            bool threw = false;
            try {
                new AccountAuditChain(null).verify_and_apply(1, ed_pub, ml_pub, chain);
            } catch (AccountAuditError ex) {
                threw = true;
            }
            fail_if_not(threw, "bad-sig chain must throw AccountAuditError");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_bad_chain_rejected() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);

            AuditEntry e0 = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                {}, 1000, ed_priv, ml_priv);
            // e1 references wrong prev_hash — random bytes instead of hash(e0).
            uint8[] wrong_hash = arr(Crypto.random_bytes(32));
            AuditEntry e1 = make_entry(1, wrong_hash, (uint8) AccountAuditAction.REMOVE_DEVICE,
                {}, 1001, ed_priv, ml_priv);

            var chain = new Gee.ArrayList<AuditEntry>();
            chain.add(e0);
            chain.add(e1);

            bool threw = false;
            try {
                new AccountAuditChain(null).verify_and_apply(1, ed_pub, ml_pub, chain);
            } catch (AccountAuditError ex) {
                threw = true;
            }
            fail_if_not(threw, "bad-chain must throw AccountAuditError");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_bad_seq_rejected() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);

            // seq jumps from 0 to 2, skipping 1.
            AuditEntry e0 = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                {}, 1000, ed_priv, ml_priv);
            AuditEntry e2 = make_entry(2, e0.compute_hash(), (uint8) AccountAuditAction.REMOVE_DEVICE,
                {}, 1001, ed_priv, ml_priv);

            var chain = new Gee.ArrayList<AuditEntry>();
            chain.add(e0);
            chain.add(e2);

            bool threw = false;
            try {
                new AccountAuditChain(null).verify_and_apply(1, ed_pub, ml_pub, chain);
            } catch (AccountAuditError ex) {
                threw = true;
            }
            fail_if_not(threw, "non-contiguous seq must throw AccountAuditError");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_timestamp_regression_rejected() {
        try {
            Bytes ed_pub; Bytes ed_priv; Crypto.generate_ed25519(out ed_pub, out ed_priv);
            Bytes ml_pub; Bytes ml_priv; Crypto.generate_mldsa65(out ml_pub, out ml_priv);

            AuditEntry e0 = make_entry(0, new uint8[32], (uint8) AccountAuditAction.ADD_DEVICE,
                {}, 1000, ed_priv, ml_priv);
            // e1 timestamp is less than e0 — regression.
            AuditEntry e1 = make_entry(1, e0.compute_hash(), (uint8) AccountAuditAction.REMOVE_DEVICE,
                {}, 999, ed_priv, ml_priv);

            var chain = new Gee.ArrayList<AuditEntry>();
            chain.add(e0);
            chain.add(e1);

            bool threw = false;
            try {
                new AccountAuditChain(null).verify_and_apply(1, ed_pub, ml_pub, chain);
            } catch (AccountAuditError ex) {
                threw = true;
            }
            fail_if_not(threw, "timestamp regression must throw AccountAuditError");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private static uint8[] arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }
}

}
