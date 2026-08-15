namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

// Tests for the multi-admin membership DAG (WS2). Convergence and authorization
// are verified without any live transport.
class MembershipDagTest : Gee.TestCase {

    // A signing identity with its AIK fingerprint (raw 20 bytes) as fp_hex.
    /* An ACCOUNT (its AIK) plus one DEVICE of that account: a DIK and the AIK-issued
     * certificate binding it. §13.1a entries are signed by the DIK and carry the DC, so a
     * test author needs both halves. */
    private class Id {
        public Bytes ed_pub; public Bytes ed_priv;
        public Bytes ml_pub; public Bytes ml_priv;
        public uint8[] fp;      // 20 raw bytes
        public string fp_hex;
        public uint32 device_id;
        public Bytes dik_ed_pub; public Bytes dik_ed_priv;
        public Bytes dik_ml_pub; public Bytes dik_ml_priv;
        public uint8[] dc;      // marshalled DeviceCertificate, AIK-signed
    }

    private Gee.HashMap<string, Id> registry = new Gee.HashMap<string, Id>();

    public MembershipDagTest() {
        base("MembershipDag");
        add_test("v2_signed_part_vector", test_signed_part_vector);
        add_test("v2_marshal_roundtrip", test_marshal_roundtrip);
        add_test("genesis_and_linear_add", test_genesis_linear);
        add_test("admin_can_add_after_promotion", test_admin_promotion);
        add_test("non_admin_rejected", test_non_admin_rejected);
        add_test("concurrent_remove_beats_promote", test_remove_beats_promote);
        add_test("remove_member_ban_blocks_readd", test_ban_blocks_readd);
        add_test("mutual_admin_removal_one_survives", test_mutual_removal);
        add_test("convergence_independent_of_order", test_convergence);
        add_test("snapshot_payload_roundtrip", test_snapshot_payload_roundtrip);
        add_test("snapshot_virtual_genesis_import", test_snapshot_genesis);
        add_test("pinned_owner_survives_hostile_root", test_pinned_owner_survives_hostile_root);
        add_test("unverifiable_first_entry_does_not_consume_genesis", test_unverifiable_first_entry);
        add_test("group_heads_kat_vector", test_group_heads_kat);
        add_test("concurrent_late_entry_does_not_renumber_epoch", test_epoch_monotone);
        add_test("revoked_device_cannot_author_entries", test_revoked_device_cannot_author);
        // D4.2
        add_test("device_set_change_rotates_epoch", test_device_set_change_rotates_epoch);
        add_test("device_set_change_replay_does_not_rotate", test_device_set_change_replay);
        add_test("device_set_change_for_another_account_rejected", test_device_set_change_wrong_subject);
        add_test("device_set_change_payload_roundtrip", test_device_set_change_payload);
        // D5.1
        add_test("late_concurrent_entry_changes_epoch_id", test_late_entry_changes_epoch_id);
        // D6
        add_test("forged_dc_for_unseen_device_id_rejected", test_forged_dc_unseen_device_rejected);
        add_test("retired_but_formerly_authorized_device_still_folds", test_retired_device_still_folds);
    }

    // ---------------------------------------------------------------- D4.2 ---

    private void test_device_set_change_payload() {
        try {
            Id a = make_id();
            uint8[] p = JournalEntryV2.build_device_set_change_payload(a.fp, (uint64) 0x0102030405060708);
            fail_if_not_eq_int(p.length, 28, "DeviceSetChange payload is aik_fp(20) | uint64");
            uint8[] fp; uint64 ver;
            fail_if_not(JournalEntryV2.parse_device_set_change_payload(p, out fp, out ver), "parse failed");
            fail_if_not_eq_str(hex(fp), a.fp_hex, "aik_fp round-trip");
            fail_if_not(ver == (uint64) 0x0102030405060708, "manifest_version round-trip");
            fail_if(JournalEntryV2.parse_device_set_change_payload(new uint8[27], out fp, out ver),
                "a short payload must not parse");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* D4.2: revoking a device from an account's Trust Manifest leaves the ACCOUNT a
     * room member, so nothing rotates and the revoked device keeps every member's
     * live sender chain key. A DeviceSetChange entry is what turns that into a room
     * epoch rotation. A plain MEMBER (not an admin) must be able to author one — an
     * account speaks for its own device set — which is the one action with a weaker
     * authorization gate than the rest. */
    private void test_device_set_change_rotates_epoch() {
        try {
            Id owner = make_id(); Id m1 = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var add = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m1.fp), 1001);

            var dag = new MembershipDag();
            dag.ingest(g.marshal());
            dag.ingest(add.marshal());
            uint32 before = dag.recompute(resolver()).epoch;
            fail_if_not_eq_int((int) before, 1, "one rotation from the AddMember");

            // m1 is a plain member, not an admin, and announces its own device set.
            var dsc = sign(m1, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(m1.fp, 5), 1002);
            dag.ingest(dsc.marshal());
            DagState st = dag.recompute(resolver());
            fail_if_not_eq_int((int) st.epoch, (int) before + 1,
                "a DeviceSetChange from a current member must rotate the epoch");
            fail_if_not(st.members.contains(m1.fp_hex), "membership itself is unchanged");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* D4.2 rule 3: a replayed entry is ACCEPTED (it still folds, and still counts
     * towards fold_hash) but is NOT rotation-causing. Letting a replay bump the epoch
     * would burn epoch numbers, and install-once (§13.4a.2) makes every burnt number
     * permanently unusable for a real chain. */
    private void test_device_set_change_replay() {
        try {
            Id owner = make_id(); Id m1 = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var add = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m1.fp), 1001);
            var v5 = sign(m1, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(m1.fp, 5), 1002);
            // A distinct entry (different lamport/timestamp ⇒ different hash) that
            // re-announces the SAME manifest version, and one that goes backwards.
            var v5_again = sign(m1, 3, heads(v5.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(m1.fp, 5), 1003);
            var v4_stale = sign(m1, 4, heads(v5_again.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(m1.fp, 4), 1004);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, add, v5}) dag.ingest(e.marshal());
            uint32 after_first = dag.recompute(resolver()).epoch;

            dag.ingest(v5_again.marshal());
            fail_if_not_eq_int((int) dag.recompute(resolver()).epoch, (int) after_first,
                "re-announcing the same manifest version must not rotate");
            dag.ingest(v4_stale.marshal());
            fail_if_not_eq_int((int) dag.recompute(resolver()).epoch, (int) after_first,
                "announcing an OLDER manifest version must not rotate");

            // A genuinely newer version still rotates.
            var v6 = sign(m1, 5, heads(v4_stale.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(m1.fp, 6), 1005);
            dag.ingest(v6.marshal());
            fail_if_not_eq_int((int) dag.recompute(resolver()).epoch, (int) after_first + 1,
                "a strictly newer manifest version must rotate");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* D4.2 rule 2: payload.aik_fp MUST equal signer_fp. Otherwise one member could
     * force epoch churn in another member's name. */
    private void test_device_set_change_wrong_subject() {
        try {
            Id owner = make_id(); Id m1 = make_id(); Id m2 = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var a1 = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m1.fp), 1001);
            var a2 = sign(owner, 2, heads(a1.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m2.fp), 1002);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, a1, a2}) dag.ingest(e.marshal());
            uint32 before = dag.recompute(resolver()).epoch;

            // m1 claims m2's device set changed.
            var bad = sign(m1, 3, heads(a2.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(m2.fp, 9), 1003);
            dag.ingest(bad.marshal());
            fail_if_not_eq_int((int) dag.recompute(resolver()).epoch, (int) before,
                "an account may only speak for its OWN device set");

            // A non-member cannot author one either.
            Id outsider = make_id();
            var by_outsider = sign(outsider, 4, heads(a2.compute_hash()),
                (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE,
                JournalEntryV2.build_device_set_change_payload(outsider.fp, 1), 1004);
            dag.ingest(by_outsider.marshal());
            fail_if_not_eq_int((int) dag.recompute(resolver()).epoch, (int) before,
                "a non-member's DeviceSetChange must not rotate");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ---------------------------------------------------------------- D5.1 ---

    /* D5: two folds differing only by a late CONCURRENT entry must yield different
     * epoch_ids. That is the whole recovery path for a contradicted epoch: canonical
     * order has unstable prefixes, so a late entry can reverse whether an EARLIER
     * entry was authorized while leaving the numeric epoch untouched — and reusing an
     * epoch number for a new chain is forbidden by install-once, so without a
     * fold-derived discriminator there is no way to retire the contradicted chain. */
    private void test_late_entry_changes_epoch_id() {
        try {
            Id owner = make_id(); Id m1 = make_id(); Id m2 = make_id();
            string room = "room@conference.example.org";
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var a = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m1.fp), 1001);
            var b = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m2.fp), 1002);

            var partial = new MembershipDag();
            partial.ingest(g.marshal());
            partial.ingest(b.marshal());
            DagState s1 = partial.recompute(resolver());
            uint64 id1 = s1.epoch_id(room);

            partial.ingest(a.marshal());
            DagState s2 = partial.recompute(resolver());
            uint64 id2 = s2.epoch_id(room);

            fail_if(id1 == id2, "a late concurrent entry must change epoch_id");
            fail_if(hex(s1.fold_hash) == hex(s2.fold_hash), "fold_hash must change with the accepted set");

            // epoch_id is a function of the fold, not of arrival order.
            var other = new MembershipDag();
            other.ingest(a.marshal());
            other.ingest(g.marshal());
            other.ingest(b.marshal());
            fail_if(other.recompute(resolver()).epoch_id(room) != id2,
                "epoch_id must converge regardless of ingest order");

            // ...and of the room, so the same fold in two rooms cannot collide.
            fail_if(s2.epoch_id("other@conference.example.org") == id2,
                "epoch_id must be bound to the room JID");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------------------ D6 ---

    /* D6 — THE forged-issuer test. §11.8 replicates AIK_priv to every authorized
     * device, so a device revoked as id 7 can mint a fresh DIK, pick a device id
     * NOBODY HAS EVER SEEN, and self-sign a completely valid DC under the stolen
     * account root. The tombstone on 7 does not cover the new id, so "is it
     * revoked?" was never a sufficient issuer check. "Has this id ever appeared in a
     * Trust Manifest fold I accepted?" is, because the new id never did. */
    private void test_forged_dc_unseen_device_rejected() {
        try {
            Id owner = make_id(); Id victim = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);

            // Device 43: never in any manifest, but its DC is signed by the real AIK.
            Bytes f_ed_pub, f_ed_priv, f_ml_pub, f_ml_priv;
            Crypto.generate_ed25519(out f_ed_pub, out f_ed_priv);
            Crypto.generate_mldsa65(out f_ml_pub, out f_ml_priv);
            uint8[] forged_dc = issue_dc(43, f_ed_pub, f_ml_pub, owner.ed_priv, owner.ml_priv);
            var by_forged = sign_as_device(owner, 43, forged_dc, f_ed_priv, f_ml_priv,
                1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            fail_if_not(by_forged.verify(owner.ed_pub, owner.ml_pub),
                "the forged issuer's entry is cryptographically valid on its own terms");

            var dag = new MembershipDag();
            dag.ingest(g.marshal());
            dag.ingest(by_forged.marshal());

            // Ever-authorized set for this account = {1} (the genesis device only).
            DagState st = dag.recompute_authorized(resolver(), null, null, ever_authorized({ 1 }));
            fail_if(st.members.contains(victim.fp_hex),
                "an entry from a device id that never appeared in an accepted manifest must be rejected");
            // The genesis entry itself, authored by device 1, still folds.
            fail_if_not_eq_str(st.owner_fp, owner.fp_hex, "the genesis (device 1) still folds");

            // Tombstoning does not help against an id nobody has ever seen — which is
            // exactly why the ever-authorized set is the check that matters.
            DagState tomb = dag.recompute_checked(resolver(), null,
                (fp_hex, dev) => fp_hex.down() == owner.fp_hex.down() && dev == 7);
            fail_if_not(tomb.members.contains(victim.fp_hex),
                "control: a tombstone on the OLD id does not cover the forged one");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* D6 uses EVER-authorized, not currently-authorized, on purpose: a journal entry
     * is a historical record. Requiring current membership would retroactively erase
     * the room history authored by devices that have since been legitimately retired. */
    private void test_retired_device_still_folds() {
        try {
            Id owner = make_id(); Id newcomer = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);

            // Device 7 was a real device of this account and did appear in a manifest
            // we accepted; it has since been retired (absent from the CURRENT fold).
            Bytes r_ed_pub, r_ed_priv, r_ml_pub, r_ml_priv;
            Crypto.generate_ed25519(out r_ed_pub, out r_ed_priv);
            Crypto.generate_mldsa65(out r_ml_pub, out r_ml_priv);
            uint8[] retired_dc = issue_dc(7, r_ed_pub, r_ml_pub, owner.ed_priv, owner.ml_priv);
            var by_retired = sign_as_device(owner, 7, retired_dc, r_ed_priv, r_ml_priv,
                1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(newcomer.fp), 1001);

            var dag = new MembershipDag();
            dag.ingest(g.marshal());
            dag.ingest(by_retired.marshal());

            DagState st = dag.recompute_authorized(resolver(), null, null, ever_authorized({ 1, 7 }));
            fail_if_not(st.members.contains(newcomer.fp_hex),
                "history authored by a formerly-authorized device must still fold");

            // Quarantine: no manifest held for that account at all ⇒ UNRESOLVED, so
            // the entry is neither folded nor discarded; it stays in the store and is
            // re-evaluated once the manifest arrives.
            DagState unresolved = dag.recompute_authorized(resolver(), null, null,
                (fp_hex, dev) => IssuerAuthStatus.UNRESOLVED);
            fail_if(unresolved.members.contains(newcomer.fp_hex),
                "an unresolvable issuer must not fold (quarantine, not fail-open)");
            fail_if_not_eq_int(dag.size, 2, "quarantined entries stay in the store");
            fail_if_not(dag.recompute_authorized(resolver(), null, null, ever_authorized({ 1, 7 }))
                    .members.contains(newcomer.fp_hex),
                "a quarantined entry folds once authorization becomes resolvable");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // An issuer checker backed by a fixed ever-authorized device-id set.
    private DeviceIssuerChecker ever_authorized(uint32[] ids) {
        var set = new Gee.HashSet<uint32>();
        foreach (uint32 i in ids) set.add(i);
        return (fp_hex, dev) => set.contains(dev)
            ? IssuerAuthStatus.AUTHORIZED : IssuerAuthStatus.REJECTED;
    }

    // §13.1b anti-withholding KAT — the <heads> wire vector. MUST stay
    // byte-for-byte in sync with PQonversations' GroupHeadsTest (same
    // canonical vector, same base64).
    private void test_group_heads_kat() {
        try {
            uint8[] zero = new uint8[32]; // 0x00 * 32
            uint8[] one = new uint8[32];  for (int i = 0; i < 32; i++) one[i] = 1;
            uint8[] ff = new uint8[32];   for (int i = 0; i < 32; i++) ff[i] = 0xFF;
            var heads = new Gee.ArrayList<Bytes>();
            heads.add(new Bytes(ff));
            heads.add(new Bytes(zero));
            heads.add(new Bytes(one));

            uint8[] wire = GroupHeads.encode(heads);
            fail_if_not_eq_int(wire.length, 98, "wire length = 2 + 3*32");
            fail_if_not_eq_int(wire[0], 0x00, "n high byte");
            fail_if_not_eq_int(wire[1], 0x03, "n low byte");
            string b64 = Base64.encode(wire);
            fail_if_not_eq_str(b64,
                "AAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQEBAQEBAQ"
              + "EBAQEBAQEBAQEBAQEBAQEB//////////////////////////////////////////8=",
                "canonical KAT base64 (shared with PQonversations)");

            // Round-trip: decode restores the three heads in sorted order.
            Gee.ArrayList<Bytes> dec = GroupHeads.decode(wire);
            fail_if_not_eq_int(dec.size, 3, "decode count");
            fail_if(hex(bytes_to_arr(dec.get(0))) != hex(zero), "first head sorted first");
            fail_if(hex(bytes_to_arr(dec.get(1))) != hex(one), "second head");
            fail_if(hex(bytes_to_arr(dec.get(2))) != hex(ff), "third head");

            // Deterministic across input orderings.
            var heads2 = new Gee.ArrayList<Bytes>();
            heads2.add(new Bytes(one)); heads2.add(new Bytes(ff)); heads2.add(new Bytes(zero));
            fail_if(hex(GroupHeads.encode(heads2)) != hex(wire), "order-independent encoding");

            // Malformed payloads must be rejected.
            bool rejected = false;
            try { GroupHeads.decode(new uint8[1]); } catch (Error e) { rejected = true; }
            fail_if_not(rejected, "short payload rejected");
            uint8[] bad_len = new uint8[35]; bad_len[1] = 1;
            rejected = false;
            try { GroupHeads.decode(bad_len); } catch (Error e) { rejected = true; }
            fail_if_not(rejected, "length-mismatch payload rejected");
            rejected = false;
            var bad_entry = new Gee.ArrayList<Bytes>();
            bad_entry.add(new Bytes(new uint8[31]));
            try { GroupHeads.encode(bad_entry); } catch (Error e) { rejected = true; }
            fail_if_not(rejected, "non-32-byte head rejected");

            // covers(): a peer subset is not a divergence; an unknown head is.
            fail_if_not(GroupHeads.covers(heads, heads), "covers(self)");
            var unknown = new Gee.ArrayList<Bytes>();
            uint8[] k = new uint8[32]; k[0] = 0x42;
            unknown.add(new Bytes(k));
            fail_if(GroupHeads.covers(unknown, heads), "unknown head → divergence");
            var subset = new Gee.ArrayList<Bytes>();
            subset.add(new Bytes(zero));
            fail_if_not(GroupHeads.covers(subset, heads), "peer behind us is not withholding");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // v1->v2 bridge Snapshot payload marshals/parses byte-for-byte.
    private void test_snapshot_payload_roundtrip() {
        try {
            Id owner = make_id(); Id m1 = make_id(); Id m2 = make_id(); Id b1 = make_id();
            var sp = new SnapshotPayload();
            sp.owner_fp = owner.fp;
            sp.epoch = 7;
            sp.member_fps.add(new Bytes(m1.fp)); sp.member_is_admin.add(true);
            sp.member_fps.add(new Bytes(m2.fp)); sp.member_is_admin.add(false);
            sp.banned_fps.add(new Bytes(b1.fp)); sp.banned_epochs.add(3);
            uint8[] payload = JournalEntryV2.build_snapshot_payload(sp);
            SnapshotPayload? p2 = JournalEntryV2.parse_snapshot_payload(payload);
            fail_if(p2 == null, "snapshot payload parse null");
            fail_if_not_eq_str(hex(((!) p2).owner_fp), owner.fp_hex, "owner fp");
            fail_if_not_eq_int((int) ((!) p2).epoch, 7, "epoch");
            fail_if_not_eq_int(((!) p2).member_fps.size, 2, "member count");
            fail_if_not(((!) p2).member_is_admin.get(0), "m1 is admin");
            fail_if(((!) p2).member_is_admin.get(1), "m2 not admin");
            fail_if_not_eq_int(((!) p2).banned_fps.size, 1, "banned count");
            fail_if_not_eq_int((int) ((!) p2).banned_epochs.get(0), 3, "banned epoch");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // A Snapshot as the first canonical entry is a virtual genesis: it imports
    // the asserted member/admin set, TOFU-pins the owner, and later admin-signed
    // entries fold on top of it.
    private void test_snapshot_genesis() {
        try {
            Id owner = make_id(); Id m1 = make_id(); Id m2 = make_id(); Id newbie = make_id();
            var sp = new SnapshotPayload();
            sp.owner_fp = owner.fp;
            sp.epoch = 0;
            sp.member_fps.add(new Bytes(m1.fp)); sp.member_is_admin.add(false);
            sp.member_fps.add(new Bytes(m2.fp)); sp.member_is_admin.add(false);
            uint8[] snap_payload = JournalEntryV2.build_snapshot_payload(sp);
            var snap = sign(owner, 1, heads(null), (uint8) MemberAuditActionV2.SNAPSHOT, snap_payload, 1000);
            // owner promotes m1 to admin, then m1 adds newbie.
            var prom = sign(owner, 2, heads(snap.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(m1.fp), 1001);
            var add = sign(m1, 3, heads(prom.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(newbie.fp), 1002);
            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{snap, prom, add}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if_not_eq_str(st.owner_fp, owner.fp_hex, "owner TOFU-pinned from snapshot");
            fail_if_not(st.members.contains(owner.fp_hex), "owner imported as member");
            fail_if_not(st.admins.contains(owner.fp_hex), "owner imported as admin");
            fail_if_not(st.members.contains(m1.fp_hex), "m1 imported as member");
            fail_if_not(st.members.contains(m2.fp_hex), "m2 imported as member");
            fail_if_not(st.admins.contains(m1.fp_hex), "m1 promoted to admin");
            fail_if_not(st.members.contains(newbie.fp_hex), "newbie added by promoted admin");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private Id make_id() throws GLib.Error {
        Id id = new Id();
        Crypto.generate_ed25519(out id.ed_pub, out id.ed_priv);
        Crypto.generate_mldsa65(out id.ml_pub, out id.ml_priv);
        id.fp = bytes_to_arr(Crypto.random_bytes(20));
        id.fp_hex = hex(id.fp);
        id.device_id = 1;
        Crypto.generate_ed25519(out id.dik_ed_pub, out id.dik_ed_priv);
        Crypto.generate_mldsa65(out id.dik_ml_pub, out id.dik_ml_priv);
        id.dc = issue_dc(id.device_id, id.dik_ed_pub, id.dik_ml_pub, id.ed_priv, id.ml_priv);
        registry.set(id.fp_hex, id);
        return id;
    }

    /* Mint a DC for the given DIK, signed by the account AIK private halves (§7.3.1). */
    private uint8[] issue_dc(uint32 device_id, Bytes dik_ed_pub, Bytes dik_ml_pub,
                             Bytes aik_ed_priv, Bytes aik_ml_priv) throws GLib.Error {
        Bytes dik_x_pub; Bytes dik_x_priv;
        Crypto.generate_x25519(out dik_x_pub, out dik_x_priv);
        var cert = DeviceCertificate.issue(
            device_id, dik_ed_pub, dik_x_pub, dik_ml_pub, aik_ed_priv, aik_ml_priv, 0);
        return cert.marshal();
    }

    private AikResolver resolver() {
        return (fp_hex, out ed, out ml) => {
            Id? id = registry.get(fp_hex);
            if (id == null) { ed = new Bytes(new uint8[0]); ml = new Bytes(new uint8[0]); return false; }
            ed = id.ed_pub; ml = id.ml_pub; return true;
        };
    }

    private JournalEntryV2 sign(Id signer, uint64 lamport, Gee.ArrayList<Bytes> parents,
            uint8 action, uint8[] payload, int64 ts) throws GLib.Error {
        return sign_as_device(signer, signer.device_id, signer.dc,
            signer.dik_ed_priv, signer.dik_ml_priv, lamport, parents, action, payload, ts);
    }

    /* Author an entry as a specific device of the account (§13.1a). */
    private JournalEntryV2 sign_as_device(Id account, uint32 device_id, uint8[] dc,
            Bytes dik_ed_priv, Bytes dik_ml_priv, uint64 lamport,
            Gee.ArrayList<Bytes> parents, uint8 action, uint8[] payload, int64 ts) throws GLib.Error {
        JournalEntryV2 e = new JournalEntryV2();
        e.lamport = lamport;
        e.signer_fp = account.fp;
        e.issuer_device_id = device_id;
        e.issuer_dc = dc;
        e.parents = parents;
        e.action = action;
        e.payload = payload;
        e.timestamp = ts;
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_arr(Crypto.ed25519_sign(dik_ed_priv, new Bytes(sp)));
        e.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(dik_ml_priv, new Bytes(sp)));
        return e;
    }

    // §13.1a.1: the AIK resolver is seeded from the whole local key cache, so ANY known
    // contact can author a well-formed root entry and — by choosing its own lamport,
    // signer_fp and hash — sort it ahead of the real genesis. Unpinned, that stranger
    // becomes owner (permanent admin, irremovable). The durable owner pin is what
    // closes it.
    private void test_pinned_owner_survives_hostile_root() {
        try {
            Id owner = make_id(); Id stranger = make_id(); Id victim = make_id();
            JournalEntryV2 g = sign(owner, 5, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            JournalEntryV2 add = sign(owner, 6, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);
            // Sorts first: lower lamport, no parents.
            JournalEntryV2 hostile = sign(stranger, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(stranger.fp), 999);

            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(add.marshal()); dag.ingest(hostile.marshal());

            // Unpinned (first ever fold) the hostile root wins — the TOFU window.
            DagState unpinned = dag.recompute(resolver());
            fail_if_not_eq_str((!) unpinned.owner_fp, stranger.fp_hex, "unpinned fold: hostile root takes ownership");

            // Pinned to the real owner, the hostile root is skipped.
            DagState pinned = dag.recompute_pinned(resolver(), owner.fp_hex);
            fail_if_not_eq_str((!) pinned.owner_fp, owner.fp_hex, "pinned owner must survive a hostile root");
            fail_if(pinned.admins.contains(stranger.fp_hex), "stranger must not become admin");
            fail_if(pinned.members.contains(stranger.fp_hex), "stranger must not become member");
            fail_if_not(pinned.members.contains(victim.fp_hex), "genuine members survive");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // §13.1a.1: an entry that sorts first but cannot be verified (unresolvable signer)
    // must be skipped, leaving the genesis slot open. Binding genesis to canonical index
    // 0 instead let one such entry — free for anyone to produce — leave the room
    // permanently ownerless, so every later entry folded as unauthorized.
    private void test_unverifiable_first_entry() {
        try {
            Id owner = make_id(); Id member = make_id();
            // Deliberately NOT registered with the resolver.
            Id unknown = new Id();
            Crypto.generate_ed25519(out unknown.ed_pub, out unknown.ed_priv);
            Crypto.generate_mldsa65(out unknown.ml_pub, out unknown.ml_priv);
            unknown.fp = bytes_to_arr(Crypto.random_bytes(20));
            unknown.fp_hex = hex(unknown.fp);
            unknown.device_id = 1;
            Crypto.generate_ed25519(out unknown.dik_ed_pub, out unknown.dik_ed_priv);
            Crypto.generate_mldsa65(out unknown.dik_ml_pub, out unknown.dik_ml_priv);
            unknown.dc = issue_dc(unknown.device_id, unknown.dik_ed_pub, unknown.dik_ml_pub,
                unknown.ed_priv, unknown.ml_priv);

            JournalEntryV2 g = sign(owner, 5, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            JournalEntryV2 add = sign(owner, 6, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(member.fp), 1001);
            JournalEntryV2 noise = sign(unknown, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(unknown.fp), 999);

            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(add.marshal()); dag.ingest(noise.marshal());

            DagState st = dag.recompute(resolver());
            fail_if(st.owner_fp == null, "an unverifiable entry sorting first must not block the real genesis");
            fail_if_not_eq_str((!) st.owner_fp, owner.fp_hex, "owner must be the real genesis signer");
            fail_if_not(st.members.contains(member.fp_hex), "later entries must still fold");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private Gee.ArrayList<Bytes> heads(uint8[]? h) {
        var l = new Gee.ArrayList<Bytes>();
        if (h != null) l.add(new Bytes(h));
        return l;
    }

    private uint8[] mp(uint8[] fp) {
        return JournalEntryV2.build_member_payload(fp, 0);
    }

    // Fixed, deterministic v2 signed_part vector — identical to the Java engine's
    // MembershipDagTest.V2_SIGNEDPART_VECTOR, so the two clients are byte-compatible.
    private const string V2_SIGNEDPART_VECTOR =
        "5833444850512d41756469742d763300" +   // "X3DHPQ-Audit-v3\0"
        "0000000000000001" +                   // lamport
        "abababababababababababababababababababab" + // signer_fp (account AIK)
        "11223344" +                           // issuer_device_id
        "0004" +                               // issuer_dc_len
        "dcdcdcdc" +                           // issuer_dc
        "0000" +                               // parent_count
        "05" +                                 // action = AddMember
        "00000018" +                           // payload_len = 24
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000000" + // payload
        "0000000000000000";                    // timestamp

    private void test_signed_part_vector() {
        uint8[] fp = new uint8[20]; for (int i = 0; i < 20; i++) fp[i] = 0xAB;
        uint8[] subj = new uint8[20]; for (int i = 0; i < 20; i++) subj[i] = 0xCD;
        var e = new JournalEntryV2();
        e.lamport = 1;
        e.signer_fp = fp;
        /* A fixed 4-byte stand-in for the issuer DC: this vector pins the FRAMING of the v3
         * signed_part (field order, lengths, endianness), not certificate contents. */
        e.issuer_device_id = 0x11223344;
        e.issuer_dc = new uint8[] { 0xDC, 0xDC, 0xDC, 0xDC };
        e.parents = new Gee.ArrayList<Bytes>();
        e.action = (uint8) MemberAuditActionV2.ADD_MEMBER;
        e.payload = JournalEntryV2.build_member_payload(subj, 0);
        e.timestamp = 0;
        fail_if_not_eq_str(hex(e.signed_part()), V2_SIGNEDPART_VECTOR, "v2 signed_part must match the cross-client vector");
    }

    private void test_marshal_roundtrip() {
        try {
            Id owner = make_id();
            var e = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            uint8[] wire = e.marshal();
            fail_if_not(JournalEntryV2.is_v2(wire), "is_v2 should detect v2 prefix");
            JournalEntryV2? e2 = JournalEntryV2.unmarshal(wire);
            fail_if(e2 == null, "unmarshal null");
            fail_if_not(((!) e2).verify(owner.ed_pub, owner.ml_pub), "verify roundtrip");
            fail_if_not_eq_str(hex(((!) e2).signer_fp), owner.fp_hex, "signer fp mismatch");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_genesis_linear() {
        try {
            Id owner = make_id(); Id m1 = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var a1 = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m1.fp), 1001);
            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(a1.marshal());
            DagState st = dag.recompute(resolver());
            fail_if_not_eq_str(st.owner_fp, owner.fp_hex, "owner should be genesis signer");
            fail_if_not(st.members.contains(owner.fp_hex), "owner is member");
            fail_if_not(st.members.contains(m1.fp_hex), "m1 is member");
            fail_if_not(st.admins.contains(owner.fp_hex), "owner is admin");
            fail_if(st.admins.contains(m1.fp_hex), "m1 is not admin");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_admin_promotion() {
        try {
            Id owner = make_id(); Id a = make_id(); Id m = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var prom = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a.fp), 1001);
            // admin `a` (promoted) adds member `m`
            var add = sign(a, 2, heads(prom.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m.fp), 1002);
            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(prom.marshal()); dag.ingest(add.marshal());
            DagState st = dag.recompute(resolver());
            fail_if_not(st.admins.contains(a.fp_hex), "a should be admin");
            fail_if_not(st.members.contains(m.fp_hex), "m added by promoted admin should be a member");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_non_admin_rejected() {
        try {
            Id owner = make_id(); Id notadmin = make_id(); Id m = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            // notadmin (never promoted) tries to add m
            var add = sign(notadmin, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m.fp), 1001);
            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(add.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.members.contains(m.fp_hex), "add by non-admin must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_remove_beats_promote() {
        try {
            Id owner = make_id(); Id a1 = make_id(); Id a2 = make_id(); Id x = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            uint8[] gh = g.compute_hash();
            var pa1 = sign(owner, 1, heads(gh), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a1.fp), 1001);
            var pa2 = sign(owner, 2, heads(pa1.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a2.fp), 1002);
            var addx = sign(owner, 3, heads(pa2.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(x.fp), 1003);
            uint8[] addxh = addx.compute_hash();
            // Concurrent: a1 removes x, a2 promotes x — both build on addx (siblings).
            var rem = sign(a1, 4, heads(addxh), (uint8) MemberAuditActionV2.REMOVE_MEMBER, mp(x.fp), 1004);
            var promx = sign(a2, 4, heads(addxh), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(x.fp), 1005);
            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, pa1, pa2, addx, rem, promx}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            // Removal wins: x neither member nor admin (promote didn't observe the removal).
            fail_if(st.members.contains(x.fp_hex), "removal must win over concurrent promote (member)");
            fail_if(st.admins.contains(x.fp_hex), "removal must win over concurrent promote (admin)");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_ban_blocks_readd() {
        try {
            Id owner = make_id(); Id m = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var add = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m.fp), 1001);
            var ban = sign(owner, 2, heads(add.compute_hash()), (uint8) MemberAuditActionV2.REMOVE_MEMBER,
                JournalEntryV2.build_remove_payload(m.fp, 0, true), 1002);
            var readd = sign(owner, 3, heads(ban.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m.fp), 1003);
            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, add, ban, readd}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.members.contains(m.fp_hex), "banned member must not be re-added");
            fail_if(st.admins.contains(m.fp_hex), "banned member must not be admin");
            fail_if_not(st.banned.contains(m.fp_hex), "ban flag must be folded into banned set");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_mutual_removal() {
        try {
            Id owner = make_id(); Id a1 = make_id(); Id a2 = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var pa1 = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a1.fp), 1001);
            var pa2 = sign(owner, 2, heads(pa1.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a2.fp), 1002);
            uint8[] pa2h = pa2.compute_hash();
            // a1 removes a2 and a2 removes a1, concurrently (both build on pa2).
            var r12 = sign(a1, 3, heads(pa2h), (uint8) MemberAuditActionV2.REMOVE_ADMIN, mp(a2.fp), 1003);
            var r21 = sign(a2, 3, heads(pa2h), (uint8) MemberAuditActionV2.REMOVE_ADMIN, mp(a1.fp), 1004);
            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, pa1, pa2, r12, r21}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            // Exactly one of a1/a2 survives as admin (the one ordered first strips
            // the other's authority; the loser's removal is then unauthorized).
            int survivors = (st.admins.contains(a1.fp_hex) ? 1 : 0) + (st.admins.contains(a2.fp_hex) ? 1 : 0);
            fail_if_not_eq_int(survivors, 1, "exactly one admin must survive mutual removal");
            fail_if_not(st.admins.contains(owner.fp_hex), "owner always admin");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* §13.5: a concurrent entry arriving LATE must not renumber the epoch of work already
     * done. Under the old "epoch = index in canonical order" rule, a client holding only B
     * folded it at index 1, and when concurrent A (which sorts ahead of B) arrived, B's
     * epoch silently became 2 — so a sender could be asked to rotate to a number it had
     * already used for a different chain, and install-once-per-epoch would then discard the
     * new chain, making those messages permanently undecryptable. Mirrors
     * PQonversations' MembershipDagTest.concurrentLateEntryDoesNotRenumberEpoch. */
    private void test_epoch_monotone() {
        try {
            Id owner = make_id(); Id m1 = make_id(); Id m2 = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            /* A and B are CONCURRENT: both name genesis as their only parent, same lamport. */
            var a = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m1.fp), 1001);
            var b = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(m2.fp), 1002);

            /* Carol sees only genesis + B. */
            var partial = new MembershipDag();
            partial.ingest(g.marshal());
            partial.ingest(b.marshal());
            uint64 epoch_b_only = partial.recompute(resolver()).epoch;
            fail_if_not_eq_int((int) epoch_b_only, 1, "one accepted rotation so far");

            /* The concurrent sibling finally arrives. */
            partial.ingest(a.marshal());
            uint64 epoch_both = partial.recompute(resolver()).epoch;
            fail_if_not_eq_int((int) epoch_both, 2, "two accepted rotations now");
            fail_if(epoch_both <= epoch_b_only, "epoch must be monotone as the DAG grows");

            /* A client that received both in the other order converges on the same value,
             * so the epoch is still a function of the entry SET, not of delivery order. */
            var other = new MembershipDag();
            other.ingest(g.marshal());
            other.ingest(a.marshal());
            other.ingest(b.marshal());
            fail_if_not_eq_int((int) other.recompute(resolver()).epoch, (int) epoch_both,
                "epoch must converge regardless of arrival order");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* §13.1a — THE revocation test. Mirrors PQonversations'
     * MembershipDagTest.revokedDeviceCannotAuthorJournalEntries.
     *
     * Under v2, entries were signed by the account AIK and named no device. Combined with
     * §11.8 (which replicates AIK_priv to every authorized device), a phone revoked from
     * the account manifest still held the account root and could keep administering every
     * room its account administered, forever. v3 names a device actor, so revoking the
     * device revokes the authority. */
    private void test_revoked_device_cannot_author() {
        try {
            Id owner = make_id(); Id victim = make_id();

            /* The owner account has a second device, 7, with a legitimate AIK-signed
             * certificate — nothing here is forged. */
            Bytes c_ed_pub, c_ed_priv, c_ml_pub, c_ml_priv;
            Crypto.generate_ed25519(out c_ed_pub, out c_ed_priv);
            Crypto.generate_mldsa65(out c_ml_pub, out c_ml_priv);
            uint8[] compromised_dc = issue_dc(7, c_ed_pub, c_ml_pub, owner.ed_priv, owner.ml_priv);

            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var by_revoked = sign_as_device(owner, 7, compromised_dc, c_ed_priv, c_ml_priv,
                1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            /* Its certificate chain is perfectly valid — that is exactly the problem. */
            fail_if_not(by_revoked.verify(owner.ed_pub, owner.ml_pub),
                "the revoked device's entry is cryptographically valid on its own terms");

            var dag = new MembershipDag();
            dag.ingest(g.marshal());
            dag.ingest(by_revoked.marshal());

            /* With no revocation knowledge the entry folds (pre-fix behaviour). */
            fail_if_not(dag.recompute(resolver()).members.contains(victim.fp_hex),
                "without revocation state the entry is accepted");

            /* Once the receiver knows device 7 is revoked, the entry is skipped. */
            DagState st = dag.recompute_checked(resolver(), null,
                (fp_hex, dev) => fp_hex.down() == owner.fp_hex.down() && dev == 7);
            fail_if(st.members.contains(victim.fp_hex),
                "an entry authored by a revoked device must not fold");

            /* A surviving device of the SAME account is unaffected — revocation is
             * per-device, so revoking one must not silence the whole admin. */
            var by_survivor = sign(owner, 2, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1002);
            dag.ingest(by_survivor.marshal());
            DagState st2 = dag.recompute_checked(resolver(), null,
                (fp_hex, dev) => fp_hex.down() == owner.fp_hex.down() && dev == 7);
            fail_if_not(st2.members.contains(victim.fp_hex),
                "a surviving device of the same account must still be able to administer");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_convergence() {
        try {
            Id owner = make_id(); Id a1 = make_id(); Id a2 = make_id(); Id x = make_id(); Id y = make_id();
            var g = sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
            var pa1 = sign(owner, 1, heads(g.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a1.fp), 1001);
            var pa2 = sign(owner, 2, heads(pa1.compute_hash()), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(a2.fp), 1002);
            uint8[] pa2h = pa2.compute_hash();
            var ax = sign(a1, 3, heads(pa2h), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(x.fp), 1003);
            var ay = sign(a2, 3, heads(pa2h), (uint8) MemberAuditActionV2.ADD_MEMBER, mp(y.fp), 1004);
            var all = new JournalEntryV2[]{g, pa1, pa2, ax, ay};

            // Ingest in forward order.
            var d1 = new MembershipDag();
            foreach (var e in all) d1.ingest(e.marshal());
            DagState s1 = d1.recompute(resolver());
            // Ingest in reverse order.
            var d2 = new MembershipDag();
            for (int i = all.length - 1; i >= 0; i--) d2.ingest(all[i].marshal());
            DagState s2 = d2.recompute(resolver());

            fail_if_not(state_equal(s1, s2), "state must converge regardless of ingest order");
            fail_if_not(s1.members.contains(x.fp_hex) && s1.members.contains(y.fp_hex), "both x and y are members");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private bool state_equal(DagState a, DagState b) {
        if (a.owner_fp != b.owner_fp) return false;
        if (a.members.size != b.members.size) return false;
        foreach (string m in a.members) if (!b.members.contains(m)) return false;
        if (a.admins.size != b.admins.size) return false;
        foreach (string m in a.admins) if (!b.admins.contains(m)) return false;
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
