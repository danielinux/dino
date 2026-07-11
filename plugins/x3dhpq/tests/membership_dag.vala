namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

// Tests for the multi-admin membership DAG (WS2). Convergence and authorization
// are verified without any live transport.
class MembershipDagTest : Gee.TestCase {

    // A signing identity with its AIK fingerprint (raw 20 bytes) as fp_hex.
    private class Id {
        public Bytes ed_pub; public Bytes ed_priv;
        public Bytes ml_pub; public Bytes ml_priv;
        public uint8[] fp;      // 20 raw bytes
        public string fp_hex;
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
        add_test("mutual_admin_removal_one_survives", test_mutual_removal);
        add_test("convergence_independent_of_order", test_convergence);
        add_test("snapshot_payload_roundtrip", test_snapshot_payload_roundtrip);
        add_test("snapshot_virtual_genesis_import", test_snapshot_genesis);
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
        registry.set(id.fp_hex, id);
        return id;
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
        JournalEntryV2 e = new JournalEntryV2();
        e.lamport = lamport;
        e.signer_fp = signer.fp;
        e.parents = parents;
        e.action = action;
        e.payload = payload;
        e.timestamp = ts;
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_arr(Crypto.ed25519_sign(signer.ed_priv, new Bytes(sp)));
        e.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(signer.ml_priv, new Bytes(sp)));
        return e;
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
        "5833444850512d41756469742d763200" +
        "0000000000000001" +
        "abababababababababababababababababababab" +
        "0000" +
        "05" +
        "00000018" +
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000000" +
        "0000000000000000";

    private void test_signed_part_vector() {
        uint8[] fp = new uint8[20]; for (int i = 0; i < 20; i++) fp[i] = 0xAB;
        uint8[] subj = new uint8[20]; for (int i = 0; i < 20; i++) subj[i] = 0xCD;
        var e = new JournalEntryV2();
        e.lamport = 1;
        e.signer_fp = fp;
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
