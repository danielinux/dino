namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

// Tests for the Trust Manifest (wire v2 — snapshot model + SHA-512,
// trust-manifest-v2-canonical.md). The two KAT vectors below MUST match the Java
// x3dhpq-core TrustEntryTest / TrustManifestTest byte-for-byte — that is the
// cross-language contract. The functional tests exercise the snapshot fold with
// REAL generated keys.
class TrustManifestTest : Gee.TestCase {

    // KAT-locked values (computed by this implementation; cross-checked against
    // the Java client for byte-identity).
    // v2 TrustEntry.signed_part: "X3DHPQ-TrustEntry-v2\0" | action(ADD) | device_id
    //   | dc_len | DC_SUBJECT.marshal()(101) | author_device_id
    //   | author_dc_hash=64xCC | timestamp
    private const string TRUST_ENTRY_SIGNED_PART_HEX =
        "5833444850512d5472757374456e7472792d763200012222222200650001222222220020a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10020a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20000000000006630f000000008010203040506070800041112131411111111cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0000000000000000";

    // SHA-512 of v2 TrustManifest.signed_part for the KAT manifest vector
    // (version=7, prev_hash=64x0, aik=ed(32xD1)+mldsa(1952xD2), 1 entry with dummy sigs).
    private const string TRUST_MANIFEST_SIGNED_PART_SHA512_HEX =
        "0ee896361a7af58c9524d86f380f382af5b6f0761322e4a9c9d6258c12bef7d7356d8f1d16e722a9db0aa8ad09e3eb747672b73b636aca5aa49549045f9f7c9a";

    public TrustManifestTest() {
        base("TrustManifest");
        add_test("kat_trust_entry_signed_part", test_kat_trust_entry);
        add_test("kat_trust_manifest_sha512", test_kat_trust_manifest);
        add_test("genesis_and_member", test_genesis_member);
        add_test("non_genesis_author_dropped", test_non_genesis_author);
        add_test("marshal_roundtrip", test_roundtrip);
        add_test("head_sign_verify", test_head_sign_verify);
        add_test("migration_roundtrip", test_migration_roundtrip);
        add_test("dik_reissued_dc_rejects_manifest", test_dik_reissued_dc_rejects_manifest);
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
        uint8[] author_hash = new uint8[64]; for (int i = 0; i < 64; i++) author_hash[i] = 0xCC;
        var e = new TrustEntry();
        e.action = TrustEntry.ACTION_ADD;
        e.device_id = 0x22222222;
        e.dc = dc_subject();
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
        m.prev_hash = new uint8[64];   // 64 zero bytes
        m.entries = new Gee.ArrayList<TrustEntry>();
        m.entries.add(kat_trust_entry());
        return m;
    }

    // ── KAT tests ────────────────────────────────────────────────────────────

    private void test_kat_trust_entry() {
        var e = kat_trust_entry();
        string sp_hex = hex(e.signed_part());
        stderr.printf("\n[KAT] TRUST_ENTRY_V2 signed_part = %s\n", sp_hex);
        stderr.printf("[KAT] DC_SUBJECT.marshal() length = %d\n", dc_subject().marshal().length);
        fail_if_not_eq_str(sp_hex, TRUST_ENTRY_SIGNED_PART_HEX,
            "TrustEntry v2 signed_part must match the cross-client vector");

        // marshal -> unmarshal -> marshal round-trip is byte-stable.
        uint8[] w1 = e.marshal();
        fail_if_not(TrustEntry.is_v2(w1), "is_v2 should detect the v2 prefix");
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
            sha_hex = hex(bytes_to_arr(Crypto.sha512(new Bytes(sp))));
        } catch (Error err) { fail_if_reached(err.message); return; }
        stderr.printf("\n[KAT] TRUST_MANIFEST_V2 sha512(signed_part) = %s\n", sha_hex);
        stderr.printf("[KAT] TRUST_MANIFEST_V2 signed_part length = %d\n", sp.length);
        fail_if_not_eq_str(sha_hex, TRUST_MANIFEST_SIGNED_PART_SHA512_HEX,
            "TrustManifest v2 sha512(signed_part) must match the cross-client vector");

        // Round-trip with dummy manifest signatures.
        m.signature = new uint8[] { 0x41, 0x42 };
        m.mldsa_signature = new uint8[] { 0x43 };
        uint8[] w1 = m.marshal();
        fail_if_not(TrustManifest.is_v2(w1), "is_v2 should detect the v2 prefix");
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
    // (the AIK for the genesis device, or the genesis device's DIK for members).
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

    private uint8[] sha512_arr(uint8[] b) throws GLib.Error {
        return bytes_to_arr(Crypto.sha512(new Bytes(b)));
    }

    // Build and hybrid-sign a v2 TrustEntry (no lamport/parents) under the signer keys.
    private TrustEntry sign_entry(uint8 action, uint32 subject_id, DeviceCertificate subject_dc,
            uint32 author_id, uint8[] author_dc_hash, int64 ts,
            Bytes signer_ed_priv, Bytes signer_ml_priv) throws GLib.Error {
        var e = new TrustEntry();
        e.action = action;
        e.device_id = subject_id;
        e.dc = subject_dc;
        e.author_device_id = author_id;
        e.author_dc_hash = author_dc_hash;
        e.timestamp = ts;
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_arr(Crypto.ed25519_sign(signer_ed_priv, new Bytes(sp)));
        e.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(signer_ml_priv, new Bytes(sp)));
        return e;
    }

    // Genesis: device D1 authorized under the account AIK; author == subject == D1.
    private TrustEntry genesis(AccountIdentityKey aik, Dev d1) throws GLib.Error {
        return sign_entry(TrustEntry.ACTION_ADD, d1.id, d1.dc,
            d1.id, sha512_arr(d1.dc.marshal()), 1000,
            new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
    }

    private TrustManifest manifest_of(AccountIdentityPub aik, TrustEntry[] es) {
        var m = new TrustManifest();
        m.aik = aik;
        m.version = 1;
        m.prev_hash = new uint8[64];
        m.entries = new Gee.ArrayList<TrustEntry>();
        foreach (var e in es) m.entries.add(e);
        return m;
    }

    // Genesis D1 (AIK) + member D2 whose DC is issued under the genesis DIK and
    // whose ADD entry is authored + signed by the genesis. Fold = {D1, D2}.
    private void test_genesis_member() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            // D8: the subject's DC is the ordinary AIK-signed one, embedded unmodified.
            Dev d2 = make_dev(1002, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc,
                d1.id, sha512_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 2, "trusted set should contain exactly D1 and D2");
            fail_if_not(trusted.has_key("1001"), "D1 authorized from genesis");
            fail_if_not(trusted.has_key("1002"), "D2 authorized as a member (genesis-authored)");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // A member ADD authored by a NON-genesis device is dropped (snapshot rule:
    // all member entries must be authored by the genesis/publisher).
    private void test_non_genesis_author() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            // D8: the subject's DC is the ordinary AIK-signed one, embedded unmodified.
            Dev d2 = make_dev(1002, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc,
                d1.id, sha512_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            // A rogue device D9 (never the genesis) tries to author D3.
            DeviceIdentityKey rogue = DeviceIdentityKey.generate();
            DeviceCertificate rogue_dc = DeviceCertificate.issue(9999,
                new Bytes(rogue.pub_ed25519), new Bytes(rogue.pub_x25519), new Bytes(rogue.pub_mldsa),
                new Bytes(rogue.priv_ed25519), new Bytes(rogue.priv_mldsa), 0);  // self-issued garbage
            // The DC itself is legitimate (AIK-signed); only the AUTHOR is rogue, so
            // this exercises the per-entry drop, not the D8 whole-manifest rejection.
            Dev d3 = make_dev(1003, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var bad = sign_entry(TrustEntry.ACTION_ADD, d3.id, d3.dc,
                9999, sha512_arr(rogue_dc.marshal()), 1002,
                new Bytes(rogue.priv_ed25519), new Bytes(rogue.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2, bad });
            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 2, "non-genesis-authored entry must be dropped (not fatal)");
            fail_if_not(trusted.has_key("1001"), "D1 still authorized");
            fail_if_not(trusted.has_key("1002"), "D2 still authorized");
            fail_if(trusted.has_key("1003"), "member authored by a non-genesis device must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_roundtrip() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);
            // D8: the subject's DC is the ordinary AIK-signed one, embedded unmodified.
            Dev d2 = make_dev(1002, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc,
                d1.id, sha512_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            // TrustEntry round-trip.
            uint8[] ew = add2.marshal();
            TrustEntry? e2 = TrustEntry.unmarshal(ew);
            fail_if(e2 == null, "TrustEntry.unmarshal null");
            if (e2 != null) fail_if_not_eq_str(hex(((!) e2).marshal()), hex(ew), "TrustEntry round-trip stable");

            // TrustManifest round-trip (sign the head under D1's DIK).
            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            m.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            uint8[] mw = m.marshal();
            TrustManifest? m2 = TrustManifest.unmarshal(mw);
            fail_if(m2 == null, "TrustManifest.unmarshal null");
            if (m2 != null) {
                fail_if_not_eq_str(hex(((!) m2).marshal()), hex(mw), "TrustManifest round-trip stable");
                fail_if_not(((!) m2).fold().size == 2, "unmarshalled manifest still folds to {D1, D2}");
            }
        } catch (Error e) { fail_if_reached(e.message); }
    }

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

    // Mirrors build_snapshot_manifest: the primary (D1, AIK holder) builds a
    // snapshot from a 2-device set — its own self DC (AIK-signed genesis) plus a
    // sibling D2 whose ORDINARY AIK-SIGNED DC is embedded unmodified in a
    // genesis-authored ADD. Fold must yield {D1, D2}.
    //
    // D8: the primary used to RE-ISSUE the sibling's DC under its own DIK first.
    // §7.3.1 defines a DeviceCertificate as AIK-signed by definition, so that
    // produced an object called a DC that verifies only under a DIK — and it was
    // redundant, because the entry is already DIK-signed and already names the
    // subject, so the ENTRY signature is the delegation edge.
    private void test_migration_roundtrip() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            Dev d2 = make_dev(1002, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));

            var g = genesis(aik, d1);
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc,
                d1.id, sha512_arr(d1.dc.marshal()), 2000,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            m.version = 2;
            m.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var trusted = m.fold();
            fail_if_not_eq_int(trusted.size, 2, "snapshot folds to exactly {D1, D2}");
            fail_if_not(trusted.has_key("1001"), "D1 (genesis) present");
            fail_if_not(trusted.has_key("1002"), "D2 (AIK-signed member DC) present");
            fail_if_not(m.verify_head(new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_mldsa)),
                "head signed by a folded device (D1)");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // D8: a manifest embedding a DIK-RE-SIGNED DC is at the PREVIOUS format and must
    // be REJECTED WHOLE — not silently reduced to its genesis. The difference between
    // "the primary republished at the new format" and "the primary quietly dropped
    // every sibling" is the difference between a working account and one that stops
    // delivering to its own devices, so an empty fold (which the caller treats as
    // REJECT and keeps last-good for) is the only safe outcome.
    private void test_dik_reissued_dc_rejects_manifest() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa));
            var g = genesis(aik, d1);

            // Previous format: D2's DC re-issued under the PRIMARY'S DIK.
            DeviceIdentityKey d2_dik = DeviceIdentityKey.generate();
            DeviceCertificate d2_reissued = DeviceCertificate.issue(1002,
                new Bytes(d2_dik.pub_ed25519), new Bytes(d2_dik.pub_x25519), new Bytes(d2_dik.pub_mldsa),
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa), 0);
            var add2 = sign_entry(TrustEntry.ACTION_ADD, 1002, d2_reissued,
                d1.id, sha512_arr(d1.dc.marshal()), 2000,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var m = manifest_of(aik.public_key(), new TrustEntry[]{ g, add2 });
            m.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            fail_if_not_eq_int(m.fold().size, 0,
                "a manifest embedding a DIK-re-signed DC must be rejected outright");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // Account reset: a fresh SELF-ONLY genesis under a NEW AIK (version=1) folds to
    // only this device — every old sibling is dropped — and roots a DIFFERENT AIK
    // lineage than the pre-reset manifest.
    private void test_reset_fresh_genesis_new_aik() {
        try {
            // Pre-reset lineage under AIK1: {d1, d2}.
            AccountIdentityKey aik1 = AccountIdentityKey.generate();
            Dev d1 = make_dev(1001, new Bytes(aik1.priv_ed25519), new Bytes(aik1.priv_mldsa));
            var g1 = genesis(aik1, d1);
            // D8: the subject's DC is the ordinary AIK-signed one, embedded unmodified.
            Dev d2 = make_dev(1002, new Bytes(aik1.priv_ed25519), new Bytes(aik1.priv_mldsa));
            var add2 = sign_entry(TrustEntry.ACTION_ADD, d2.id, d2.dc,
                d1.id, sha512_arr(d1.dc.marshal()), 1001,
                new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));
            var m_old = manifest_of(aik1.public_key(), new TrustEntry[]{ g1, add2 });
            fail_if_not_eq_int(m_old.fold().size, 2, "pre-reset lineage folds to {d1, d2}");

            // Reset: NEW AIK2, KEEP d1's DIK, self-issue a NEW genesis DC under AIK2,
            // SELF-ONLY genesis at version=1.
            AccountIdentityKey aik2 = AccountIdentityKey.generate();
            DeviceCertificate self_dc2 = DeviceCertificate.issue(d1.id,
                new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_x25519), new Bytes(d1.dik.pub_mldsa),
                new Bytes(aik2.priv_ed25519), new Bytes(aik2.priv_mldsa), 1);
            var g2 = sign_entry(TrustEntry.ACTION_ADD, d1.id, self_dc2,
                d1.id, sha512_arr(self_dc2.marshal()), 9000,
                new Bytes(aik2.priv_ed25519), new Bytes(aik2.priv_mldsa));  // AIK2-signed genesis edge
            var m_new = manifest_of(aik2.public_key(), new TrustEntry[]{ g2 });
            m_new.sign_head(new Bytes(d1.dik.priv_ed25519), new Bytes(d1.dik.priv_mldsa));

            var trusted = m_new.fold();
            fail_if_not_eq_int(trusted.size, 1, "fresh reset genesis is SELF-ONLY (old siblings dropped)");
            fail_if_not(trusted.has_key("1001"), "self (d1) present in fresh genesis");
            fail_if(trusted.has_key("1002"), "old sibling d2 must NOT survive the reset");
            fail_if_not_eq_int((int) m_new.version, 1, "fresh reset lineage starts at version=1");
            fail_if_not(m_new.verify_head(new Bytes(d1.dik.pub_ed25519), new Bytes(d1.dik.pub_mldsa)),
                "fresh genesis head signed under this device's DIK");
            fail_if(hex(m_new.aik.pub_ed25519) == hex(aik1.public_key().pub_ed25519),
                "reset roots a DIFFERENT AIK lineage than the pre-reset manifest");
        } catch (Error e) { fail_if_reached(e.message); }
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
