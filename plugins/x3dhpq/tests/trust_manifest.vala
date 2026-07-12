namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

// Tests for the Trust Manifest (Phase 1 core, trust-manifest-canonical.md).
// The two KAT vectors below MUST match the Java x3dhpq-core TrustEntryTest /
// TrustManifestTest byte-for-byte — that is the cross-language contract. The
// functional tests exercise the delegation fold with REAL generated keys.
class TrustManifestTest : Gee.TestCase {

    // KAT-locked values (computed by this implementation; cross-checked against
    // the Java client for byte-identity).
    // "X3DHPQ-TrustEntry-v1\0" | action(ADD) | device_id | dc_len | DC_SUBJECT.marshal()(101)
    //   | lamport | parent_count | parents[0]=32xBB | author_device_id | author_dc_hash=32xCC | timestamp
    private const string TRUST_ENTRY_SIGNED_PART_HEX =
        "5833444850512d5472757374456e7472792d763100012222222200650001222222220020a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10020a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20000000000006630f0000000080102030405060708000411121314000000000000000500000001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb11111111cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0000000000000000";

    // sha256 of TrustManifest.signed_part for the KAT manifest vector (version=7,
    // prev_hash=32x0, aik=ed(32xD1)+mldsa(1952xD2), 1 entry with dummy sigs).
    private const string TRUST_MANIFEST_SIGNED_PART_SHA256_HEX =
        "6385abed72f376d53951bde1aed581d4f272e7316bbd9b9e07cc0769c69282e7";

    public TrustManifestTest() {
        base("TrustManifest");
        add_test("kat_trust_entry_signed_part", test_kat_trust_entry);
        add_test("kat_trust_manifest_sha256", test_kat_trust_manifest);
        add_test("genesis_and_delegated_add", test_genesis_delegated);
        add_test("untrusted_author_dropped", test_untrusted_author);
        add_test("removal_wins", test_removal_wins);
        add_test("convergence_independent_of_order", test_convergence);
        add_test("marshal_roundtrip", test_roundtrip);
        add_test("head_sign_verify", test_head_sign_verify);
        add_test("migration_roundtrip", test_migration_roundtrip);
        add_test("confirmer_append", test_confirmer_append);
        add_test("revoke_removes_device", test_revoke_removes_device);
        add_test("reset_fresh_genesis_new_aik", test_reset_fresh_genesis_new_aik);
    }

    // ── DC_SUBJECT / KAT object builders ─────────────────────────────────────

    private DeviceCertificate dc_subject() {
        uint8[] ed = new uint8[32]; for (int i = 0; i < 32; i++) ed[i] = 0xA1;
        uint8[] x = new uint8[32]; for (int i = 0; i < 32; i++) x[i] = 0xA2;
        var dc = new DeviceCertificate();
        dc.version = 1;
        dc.device_id = 0x22222222;
        dc.dik_pub_ed25519 = new Bytes(ed);
        dc.dik_pub_x25519 = new Bytes(x);
        dc.dik_pub_mldsa = new Bytes(new uint8[0]);
        dc.created_at = 1714483200;
        dc.flags = 0x00;
        dc.signature = new Bytes(new uint8[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
        dc.mldsa_signature = new Bytes(new uint8[] { 0x11, 0x12, 0x13, 0x14 });
        return dc;
    }

    private TrustEntry kat_trust_entry() {
        uint8[] parent = new uint8[32]; for (int i = 0; i < 32; i++) parent[i] = 0xBB;
        uint8[] author_hash = new uint8[32]; for (int i = 0; i < 32; i++) author_hash[i] = 0xCC;
        var e = new TrustEntry();
        e.action = TrustEntry.ACTION_ADD;
        e.device_id = 0x22222222;
        e.dc = dc_subject();
        e.lamport = 5;
        e.parents = new Gee.ArrayList<Bytes>();
        e.parents.add(new Bytes(parent));
        e.author_device_id = 0x11111111;
        e.author_dc_hash = author_hash;
        e.timestamp = 0;
        // Fixed dummy entry signatures per the canonical spec.
        e.signature = new uint8[] { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26 };
        e.mldsa_signature = new uint8[] { 0x31, 0x32, 0x33 };
        return e;
    }

    private TrustManifest kat_trust_manifest() {
        uint8[] ed = new uint8[32]; for (int i = 0; i < 32; i++) ed[i] = 0xD1;
        uint8[] mldsa = new uint8[1952]; for (int i = 0; i < 1952; i++) mldsa[i] = 0xD2;
        var aik = new AccountIdentityPub();
        aik.pub_ed25519 = ed;
        aik.pub_mldsa = mldsa;

        var m = new TrustManifest();
        m.aik = aik;
        m.version = 7;
        m.prev_hash = new uint8[32];   // 32 zero bytes
        m.entries = new Gee.ArrayList<TrustEntry>();
        m.entries.add(kat_trust_entry());
        return m;
    }

    // ── KAT tests ────────────────────────────────────────────────────────────

    private void test_kat_trust_entry() {
        var e = kat_trust_entry();
        string sp_hex = hex(e.signed_part());
        stderr.printf("\n[KAT] TRUST_ENTRY signed_part = %s\n", sp_hex);
        stderr.printf("[KAT] DC_SUBJECT.marshal() length = %d\n", dc_subject().marshal().length);
        fail_if_not_eq_str(sp_hex, TRUST_ENTRY_SIGNED_PART_HEX,
            "TrustEntry signed_part must match the cross-client vector");

        // marshal -> unmarshal -> marshal round-trip is byte-stable.
        uint8[] w1 = e.marshal();
        fail_if_not(TrustEntry.is_v1(w1), "is_v1 should detect the v1 prefix");
        TrustEntry? e2 = TrustEntry.unmarshal(w1);
        fail_if(e2 == null, "TrustEntry.unmarshal returned null");
        if (e2 != null) {
            fail_if_not_eq_str(hex(((!) e2).marshal()), hex(w1), "TrustEntry marshal round-trip must be byte-stable");
        }
    }

    private void test_kat_trust_manifest() {
        var m = kat_trust_manifest();
        uint8[] sp = m.signed_part();
        string sha_hex = "";
        try {
            sha_hex = hex(bytes_to_arr(Crypto.sha256(new Bytes(sp))));
        } catch (Error err) { fail_if_reached(err.message); return; }
        stderr.printf("\n[KAT] TRUST_MANIFEST sha256(signed_part) = %s\n", sha_hex);
        stderr.printf("[KAT] TRUST_MANIFEST signed_part length = %d\n", sp.length);
        fail_if_not_eq_str(sha_hex, TRUST_MANIFEST_SIGNED_PART_SHA256_HEX,
            "TrustManifest sha256(signed_part) must match the cross-client vector");

        // Round-trip with dummy manifest signatures.
        m.signature = new uint8[] { 0x41, 0x42 };
        m.mldsa_signature = new uint8[] { 0x43 };
        uint8[] w1 = m.marshal();
        fail_if_not(TrustManifest.is_v1(w1), "is_v1 should detect the v1 prefix");
        TrustManifest? m2 = TrustManifest.unmarshal(w1);
        fail_if(m2 == null, "TrustManifest.unmarshal returned null");
        if (m2 != null) {
            fail_if_not_eq_str(hex(((!) m2).marshal()), hex(w1), "TrustManifest marshal round-trip must be byte-stable");
        }
    }

    // ── Functional (real keys) ───────────────────────────────────────────────

    private class Dev {
        public uint32 id;
        public DeviceIdentityKey dik;
        public DeviceCertificate dc;
    }

    // Issue a device certificate under an arbitrary issuer signing keypair
    // (the AIK for the genesis device, or an author device's DIK for delegated
    // devices).
    private Dev make_dev(uint32 id, Bytes issuer_ed_priv, Bytes issuer_ml_priv) throws GLib.Error {
        Dev d = new Dev();
        d.id = id;
        d.dik = DeviceIdentityKey.generate();
        d.dc = DeviceCertificate.issue(
            id,
            new Bytes(d.dik.pub_ed25519),
            new Bytes(d.dik.pub_x25519),
            new Bytes(d.dik.pub_mldsa),
            issuer_ed_priv,
            issuer_ml_priv,
            0);
        return d;
    }

    private uint8[] sha256_arr(uint8[] b) throws GLib.Error {
        return bytes_to_arr(Crypto.sha256(new Bytes(b)));
    }

    // Build and sign a TrustEntry under the given signer private keys.
    private TrustEntry sign_entry(uint8 action, uint32 subject_id, DeviceCertificate subject_dc,
            uint64 lamport, Gee.ArrayList<Bytes> parents, uint32 author_id, uint8[] author_dc_hash,
            int64 ts, Bytes signer_ed_priv, Bytes signer_ml_priv) throws GLib.Error {
        var e = new TrustEntry();
        e.action = action;
        e.device_id = subject_id;
        e.dc = subject_dc;
        e.lamport = lamport;
        e.parents = parents;
        e.author_device_id = author_id;
        e.author_dc_hash = author_dc_hash;
        e.timestamp = ts;
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_arr(Crypto.ed25519_sign(signer_ed_priv, new Bytes(sp)));
        e.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(signer_ml_priv, new Bytes(sp)));
        return e;
    }

    private Gee.ArrayList<Bytes> parents_of(uint8[]? h) {
        var l = new Gee.ArrayList<Bytes>();
        if (h != null) l.add(new Bytes(h));
        return l;
    }

    // Genesis: device D1 authorized under the account AIK; author == subject == D1.
    private TrustEntry genesis(AccountIdentityKey aik, Dev d1) throws GLib.Error {
        return sign_entry(TrustEntry.ACTION_ADD, d1.id, d1.dc, 0, parents_of(null),
            d1.id, sha256_arr(d1.dc.marshal()), 1000,
            new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
    }

    private TrustManifest manifest_of(AccountIdentityPub aik, TrustEntry[] es) {
        var m = new TrustManifest();
        m.aik = aik;
        m.version = 1;
        m.prev_hash = new uint8[32];
        m.entries = new Gee.ArrayList<TrustEntry>();
        foreach (var e in es) m.entries.add(e);
        return m;
    }

    private void test_genesis_delegated() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            // D1 authorizes D2: D2's DC is issued under D1's DIK; entry authored by D1.
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 2, "trusted set should contain exactly D1 and D2");
            fail_if_not(trusted.has_key("1001"), "D1 authorized from genesis");
            fail_if_not(trusted.has_key("1002"), "D2 authorized by delegated add");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_untrusted_author() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            // A rogue device D9 (never trusted) tries to authorize D3.
            DeviceIdentityKey rogue = DeviceIdentityKey.generate();
            DeviceCertificate rogue_dc = DeviceCertificate.issue(9999,
                new Bytes(rogue.pub_ed25519), new Bytes(rogue.pub_x25519), new Bytes(rogue.pub_mldsa),
                new Bytes(rogue.priv_ed25519), new Bytes(rogue.priv_mldsa), 0);  // self-issued garbage
            Dev d3 = make_dev(1003, new Bytes(rogue.priv_ed25519), new Bytes(rogue.priv_mldsa));
            var bad = sign_entry(TrustEntry.ACTION_ADD, d3.id, d3.dc, 2, parents_of(add2.compute_hash()),
                9999, sha256_arr(rogue_dc.marshal()), 1002,
                new Bytes(rogue.priv_ed25519), new Bytes(rogue.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2, bad });
            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 2, "rogue-authored entry must be dropped (not fatal)");
            fail_if_not(trusted.has_key("1001"), "D1 still authorized");
            fail_if_not(trusted.has_key("1002"), "D2 still authorized");
            fail_if(trusted.has_key("1003"), "device authorized by an untrusted author must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_removal_wins() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            uint8[] add2h = add2.compute_hash();

            // Concurrent siblings on add2: D1 removes D2, and D1 re-adds D2 (fresh cert).
            var rem = sign_entry(TrustEntry.ACTION_REMOVE, d2.id, d2.dc, 2, parents_of(add2h),
                d1.id, sha256_arr(d1.dc.marshal()), 1002,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            Dev d2b = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var readd = sign_entry(TrustEntry.ACTION_ADD, d2b.id, d2b.dc, 2, parents_of(add2h),
                d1.id, sha256_arr(d1.dc.marshal()), 1003,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2, rem, readd });
            var trusted = m.fold();
            fail_if(trusted.has_key("1002"), "removal must win over a concurrent (non-descendant) re-add");
            fail_if_not(trusted.has_key("1001"), "D1 still authorized");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_convergence() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            uint8[] add2h = add2.compute_hash();

            // Concurrent: D2 authorizes D3, D1 authorizes D4 (both build on add2).
            Dev d3 = make_dev(1003, new Bytes(d2.dik.priv_ed25519), new Bytes(d2.dik.priv_mldsa));
            var add3 = sign_entry(TrustEntry.ACTION_ADD, d3.id, d3.dc, 2, parents_of(add2h),
                d2.id, sha256_arr(d2.dc.marshal()), 1002,
                new Bytes(d2.dik.priv_ed25519), new Bytes(d2.dik.priv_mldsa));
            Dev d4 = make_dev(1004, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add4 = sign_entry(TrustEntry.ACTION_ADD, d4.id, d4.dc, 2, parents_of(add2h),
                d1.id, sha256_arr(d1.dc.marshal()), 1003,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m1 = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2, add3, add4 });
            var m2 = manifest_of(aik.public_key(), new TrustEntry[]{ add4, add3, add2, g });
            var t1 = m1.fold();
            var t2 = m2.fold();
            fail_if_not(keys_equal(t1, t2), "fold must converge regardless of entry input order");
            fail_if_not(t1.has_key("1001") && t1.has_key("1002") && t1.has_key("1003") && t1.has_key("1004"),
                "all four devices authorized");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_roundtrip() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            // TrustEntry round-trip.
            uint8[] ew = add2.marshal();
            TrustEntry? e2 = TrustEntry.unmarshal(ew);
            fail_if(e2 == null, "TrustEntry.unmarshal null");
            if (e2 != null) fail_if_not_eq_str(hex(((!) e2).marshal()), hex(ew), "TrustEntry round-trip stable");

            // TrustManifest round-trip (sign the head under D1's DIK).
            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            uint8[] msp = m.signed_part();
            m.signature = bytes_to_arr(Crypto.ed25519_sign(new Bytes(d1.dik.priv_ed25519), new Bytes(msp)));
            m.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(new Bytes(d1.dik.priv_mldsa), new Bytes(msp)));
            uint8[] mw = m.marshal();
            TrustManifest? m2 = TrustManifest.unmarshal(mw);
            fail_if(m2 == null, "TrustManifest.unmarshal null");
            if (m2 != null) {
                fail_if_not_eq_str(hex(((!) m2).marshal()), hex(mw), "TrustManifest round-trip stable");
                fail_if_not(((!) m2).fold().size == 2, "unmarshalled manifest still folds to {D1, D2}");
            }
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ── Phase 2: head sign/verify + migration + confirmer-append ─────────────

    private void test_head_sign_verify() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g });

            // Sign the head under D1's DIK; verify_head must be true for D1's DIK...
            m.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            fail_if_not(m.verify_head(new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_mldsa)),
                "verify_head must accept the DIK that signed it");

            // ...and false under an unrelated DIK.
            DeviceIdentityKey other = DeviceIdentityKey.generate();
            fail_if(m.verify_head(new Bytes(other.pub_ed25519), new Bytes(other.pub_mldsa)),
                "verify_head must reject a wrong DIK");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // Mirrors build_and_publish_genesis_manifest: the primary (D1, AIK holder)
    // builds a genesis manifest from a 2-device authorized set — its own self DC
    // (AIK-signed genesis) plus a sibling D2 whose DC is RE-ISSUED under the
    // primary's DIK and appended as a DIK-signed ADD. Fold must yield {D1, D2}.
    private void test_migration_roundtrip() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            // D1 is the primary: its DC is AIK-signed (genesis).
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            // D2 pre-exists in the account with its own DIK (its old cert would be
            // AIK-signed; migration RE-ISSUES it under D1's DIK).
            DeviceIdentityKey d2_dik = DeviceIdentityKey.generate();
            DeviceCertificate d2_reissued = DeviceCertificate.issue(1002,
                new Bytes(d2_dik.pub_ed25519), new Bytes(d2_dik.pub_x25519), new Bytes(d2_dik.pub_mldsa),
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa), 0);

            var g = genesis(aik, d1);
            var m = new TrustManifest();
            m.aik = aik.public_key();
            m.prev_hash = new uint8[32];
            m.entries = new Gee.ArrayList<TrustEntry>();
            m.entries.add(g);
            var add2 = sign_entry(TrustEntry.ACTION_ADD, 1002, d2_reissued, m.next_lamport(),
                clone_heads(m), d1.id, sha256_arr(d1.dc.marshal()), 2000,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            m.entries.add(add2);
            m.version = 2;
            m.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 2, "genesis migration folds to exactly {D1, D2}");
            fail_if_not(trusted.has_key("1001"), "D1 (genesis) present");
            fail_if_not(trusted.has_key("1002"), "D2 (re-issued sibling) present");
            // Head sig is under D1, a folded device.
            fail_if_not(m.verify_head(new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_mldsa)),
                "head signed by a folded device (D1)");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // A trusted non-genesis device (D2) appends a DIK-signed ADD for a newcomer
    // (D3), whose DC is issued under D2's DIK. Fold must then contain D3.
    private void test_confirmer_append() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            var fold0 = m.fold();
            fail_if_not(fold0.has_key("1002"), "D2 trusted before it authors");

            // D2 (confirmer) admits newcomer D3: D3's DC issued under D2's DIK,
            // ADD entry authored + signed by D2.
            Dev d3 = make_dev(1003, new Bytes(d2.dik.priv_ed25519), new Bytes(d2.dik.priv_mldsa));
            var add3 = sign_entry(TrustEntry.ACTION_ADD, d3.id, d3.dc, m.next_lamport(),
                clone_heads(m), d2.id, sha256_arr(d2.dc.marshal()), 3000,
                new Bytes(d2.dik.priv_ed25519), new Bytes(d2.dik.priv_mldsa));
            m.entries.add(add3);
            m.version = m.version + 1;
            m.sign_head(new Bytes(d2.dik.priv_ed25519), new Bytes(d2.dik.priv_mldsa));

            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 3, "fold now contains {D1, D2, D3}");
            fail_if_not(trusted.has_key("1003"), "newcomer D3 appears after confirmer append");
            // The new head signature verifies under the authoring member D2.
            fail_if_not(m.verify_head(new Bytes(d2.dik.pub_ed25519), new Bytes(d2.dik.pub_mldsa)),
                "head signed by folded confirmer D2");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // §D4: a trusted non-genesis device (A = D2) revokes device B (D3) by
    // appending a DIK-signed REMOVE. Fold must drop B. A concurrent sibling ADD
    // re-adding B (NOT a descendant of the removal) loses (removal-wins).
    private void test_revoke_removes_device() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa)); // genesis/primary
            var g = genesis(aik, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa)); // A (trusted)
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            Dev d3 = make_dev(1003, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa)); // B
            var add3 = sign_entry(TrustEntry.ACTION_ADD, d3.id, d3.dc, 2, parents_of(add2.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1002,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            uint8[] add3h = add3.compute_hash();

            // A (D2) revokes B (D3): REMOVE authored + signed by D2's DIK.
            var rem = sign_entry(TrustEntry.ACTION_REMOVE, d3.id, d3.dc, 3, parents_of(add3h),
                d2.id, sha256_arr(d2.dc.marshal()), 2000,
                new Bytes(d2.dik.priv_ed25519), new Bytes(d2.dik.priv_mldsa));
            // Concurrent re-add of B by D1 on add3 (NOT a descendant of the removal).
            Dev d3b = make_dev(1003, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var readd = sign_entry(TrustEntry.ACTION_ADD, d3b.id, d3b.dc, 3, parents_of(add3h),
                d1.id, sha256_arr(d1.dc.marshal()), 2001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2, add3, rem, readd });
            var trusted = m.fold();
            fail_if(trusted.has_key("1003"),
                "B revoked by trusted non-genesis device A; concurrent non-descendant re-add loses (removal-wins)");
            fail_if_not(trusted.has_key("1001"), "D1 (primary) still authorized");
            fail_if_not(trusted.has_key("1002"), "D2 (revoker) still authorized");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // Account reset (task #55): a fresh SELF-ONLY genesis under a NEW AIK
    // (version=1) folds to only this device — every old sibling is dropped — and
    // roots a DIFFERENT AIK lineage than the pre-reset manifest.
    private void test_reset_fresh_genesis_new_aik() {
        try {
            // --- Pre-reset lineage under AIK1: {d1 (primary), d2 (sibling)}. ---
            AccountIdentityKey aik1 = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik1.priv_ed25519), new Bytes(aik1.priv_mldsa));
            var g1 = genesis(aik1, d1);
            Dev d2 = make_dev(1002, new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1, parents_of(g1.compute_hash()),
                d1.id, sha256_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var m_old = manifest_of(aik1.public_key(), new TrustEntry[]{ g1, add2 });
            fail_if_not_eq_int(m_old.fold().size, 2, "pre-reset lineage folds to {d1, d2}");

            // --- Reset: NEW AIK2, KEEP d1's DIK, self-issue a NEW genesis DC under
            //     AIK2, SELF-ONLY genesis at version=1. ---
            AccountIdentityKey aik2 = AccountIdentityKey.generate();
            DeviceCertificate self_dc2 = DeviceCertificate.issue(d1.id,
                new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_x25519), new Bytes(d1.dik.pub_mldsa),
                new Bytes(aik2.priv_ed25519), new Bytes(aik2.priv_mldsa), 1);
            var g2 = sign_entry(TrustEntry.ACTION_ADD, d1.id, self_dc2, 0, parents_of(null),
                d1.id, sha256_arr(self_dc2.marshal()), 9000,
                new Bytes(aik2.priv_ed25519), new Bytes(aik2.priv_mldsa));  // AIK2-signed genesis edge
            var m_new = new TrustManifest();
            m_new.aik = aik2.public_key();
            m_new.version = 1;
            m_new.prev_hash = new uint8[32];
            m_new.entries = new Gee.ArrayList<TrustEntry>();
            m_new.entries.add(g2);
            m_new.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa)); // head under this device's DIK

            var trusted = m_new.fold();
            fail_if_not_eq_int(trusted.size, 1, "fresh reset genesis is SELF-ONLY (old siblings dropped)");
            fail_if_not(trusted.has_key("1001"), "self (d1) present in fresh genesis");
            fail_if(trusted.has_key("1002"), "old sibling d2 must NOT survive the reset");
            fail_if_not_eq_int((int) m_new.version, 1, "fresh reset lineage starts at version=1");

            // Head verifies under this device's DIK; genesis is AIK2-rooted.
            fail_if_not(m_new.verify_head(new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_mldsa)),
                "fresh genesis head signed under this device's DIK");

            // Lineage distinction: the new manifest's AIK differs from the old one —
            // a version=1 genesis under a DIFFERENT AIK is a re-pin, not a rollback.
            fail_if(hex(m_new.aik.pub_ed25519) == hex(aik1.public_key().pub_ed25519),
                "reset roots a DIFFERENT AIK lineage than the pre-reset manifest");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private Gee.ArrayList<Bytes> clone_heads(TrustManifest m) {
        var heads = m.current_heads();
        var l = new Gee.ArrayList<Bytes>();
        l.add_all(heads);
        return l;
    }

    private static bool keys_equal(Gee.HashMap<string, DeviceCertificate> a, Gee.HashMap<string, DeviceCertificate> b) {
        if (a.size != b.size) return false;
        foreach (string k in a.keys) if (!b.has_key(k)) return false;
        return true;
    }

    private static string hex(uint8[] b) {
        StringBuilder sb = new StringBuilder();
        foreach (uint8 x in b) sb.append_printf("%02x", x);
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
