namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

// Tests for the multi-writer device-audit DAG (x3dhpq-xep-draft.md §11.7).
// Convergence and single-AIK authorization are verified without any live
// transport. The shared byte-vectors below MUST match the Java engine's
// DeviceDagTest byte-for-byte — that is the cross-language contract.
class DeviceDagTest : Gee.TestCase {

    // A signing identity: one account AIK keypair + its raw 20-byte fingerprint
    // (the REAL BLAKE2b-160 of the AIK's wire encoding — RotateAIK re-derives the
    // pin from the payload's embedded key material, so this must match production).
    private class Id {
        public Bytes ed_pub; public Bytes ed_priv;
        public Bytes ml_pub; public Bytes ml_priv;
        public uint8[] fp;      // 20 raw bytes
        public string fp_hex;
    }

    private Gee.HashMap<string, Id> registry = new Gee.HashMap<string, Id>();

    public DeviceDagTest() {
        base("DeviceDag");
        add_test("v2_signed_part_vector", test_signed_part_vector);
        add_test("v2_snapshot_vector", test_snapshot_vector);
        add_test("v2_marshal_roundtrip", test_marshal_roundtrip);
        add_test("genesis_add_device", test_genesis_add_device);
        add_test("unknown_signer_rejected", test_unknown_signer_rejected);
        add_test("convergence_independent_of_order", test_convergence);
        add_test("removal_wins_over_concurrent_readd", test_removal_wins);
        add_test("rotate_aik_resets_pin", test_rotate_aik);
        add_test("snapshot_virtual_genesis_import", test_snapshot_genesis);
    }

    // The account AIK fp is the REAL BLAKE2b-160 of its wire encoding (not an
    // arbitrary test tag): RotateAIK re-derives the pin from the payload's
    // embedded key material, so this must match what DeviceDag itself computes.
    private Id make_id() throws GLib.Error {
        Id id = new Id();
        Crypto.generate_ed25519(out id.ed_pub, out id.ed_priv);
        Crypto.generate_mldsa65(out id.ml_pub, out id.ml_priv);
        uint8[] marshalled = DeviceAuditEntryV2.aik_pub_marshal(bytes_to_arr(id.ed_pub), bytes_to_arr(id.ml_pub));
        id.fp = bytes_to_arr(Crypto.blake2b160(new Bytes(marshalled)));
        id.fp_hex = hex(id.fp);
        registry.set(id.fp_hex, id);
        return id;
    }

    private DeviceAikResolver resolver() {
        return (fp_hex, out ed, out ml) => {
            Id? id = registry.get(fp_hex);
            if (id == null) { ed = new Bytes(new uint8[0]); ml = new Bytes(new uint8[0]); return false; }
            ed = id.ed_pub; ml = id.ml_pub; return true;
        };
    }

    private DeviceAuditEntryV2 sign(Id signer, uint64 lamport, uint32 author_device_id,
            Gee.ArrayList<Bytes> parents, uint8 action, uint8[] payload, int64 ts) throws GLib.Error {
        DeviceAuditEntryV2 e = new DeviceAuditEntryV2();
        e.lamport = lamport;
        e.signer_fp = signer.fp;
        e.author_device_id = author_device_id;
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

    // A structurally-valid (but not cryptographically meaningful) DeviceCertificate,
    // sufficient for DeviceDag folding: the DAG never verifies the cert's own
    // signature, only the entry's hybrid signature under the pinned account AIK.
    private uint8[] make_cert_bytes(uint32 device_id) {
        uint8[] ed = new uint8[32]; for (int i = 0; i < ed.length; i++) ed[i] = 0x11;
        uint8[] x = new uint8[32]; for (int i = 0; i < x.length; i++) x[i] = 0x22;
        uint8[] mldsa = new uint8[1952]; for (int i = 0; i < mldsa.length; i++) mldsa[i] = 0x33;
        uint8[] sig_ed = new uint8[64]; for (int i = 0; i < sig_ed.length; i++) sig_ed[i] = 0x44;
        uint8[] sig_ml = new uint8[3309]; for (int i = 0; i < sig_ml.length; i++) sig_ml[i] = 0x55;
        var dc = new DeviceCertificate();
        dc.version = 1;
        dc.device_id = device_id;
        dc.dik_pub_ed25519 = new Bytes(ed);
        dc.dik_pub_x25519 = new Bytes(x);
        dc.dik_pub_mldsa = new Bytes(mldsa);
        dc.created_at = 1000;
        dc.flags = 0;
        dc.signature = new Bytes(sig_ed);
        dc.mldsa_signature = new Bytes(sig_ml);
        return dc.marshal();
    }

    // -------------------------------------------------------------------------
    // Shared cross-language byte-vectors (§11.7). MUST match the Java engine's
    // DeviceDagTest.DEVICE_AUDIT_V2_VECTOR / DEVICE_AUDIT_SNAPSHOT_VECTOR exactly.
    // -------------------------------------------------------------------------

    // lamport=1, signer_fp=20xAB, author_device_id=7, no parents,
    // action=RemoveDevice(2), payload=build_remove_device_payload(0xCDCDCDCD), timestamp=0.
    private const string DEVICE_AUDIT_V2_VECTOR =
        "5833444850512d44657641756469742d763200" +
        "0000000000000001" +
        "abababababababababababababababababababab" +
        "00000007" +
        "00000000" +
        "02" +
        "00000004" +
        "cdcdcdcd" +
        "0000000000000000";

    // lamport=2, signer_fp=20xAB, author_device_id=7, no parents, action=Snapshot(10),
    // payload=build_snapshot_payload(owner_aik_fp=20xEF, epoch=5,
    //         devices=[{device_id=42, cert=8xEE}]), timestamp=0.
    private const string DEVICE_AUDIT_SNAPSHOT_VECTOR =
        "5833444850512d44657641756469742d763200" +
        "0000000000000002" +
        "abababababababababababababababababababab" +
        "00000007" +
        "00000000" +
        "0a" +
        "00000030" +
        "efefefefefefefefefefefefefefefefefefefef" +
        "0000000000000005" +
        "00000001" +
        "0000002a" +
        "00000008" +
        "eeeeeeeeeeeeeeee" +
        "0000000000000000";

    private void test_signed_part_vector() {
        uint8[] fp = new uint8[20]; for (int i = 0; i < 20; i++) fp[i] = 0xAB;
        var e = new DeviceAuditEntryV2();
        e.lamport = 1;
        e.signer_fp = fp;
        e.author_device_id = 7;
        e.parents = new Gee.ArrayList<Bytes>();
        e.action = (uint8) DeviceAuditActionV2.REMOVE_DEVICE;
        e.payload = DeviceAuditEntryV2.build_remove_device_payload((uint32) 0xCDCDCDCD);
        e.timestamp = 0;
        fail_if_not_eq_str(hex(e.signed_part()), DEVICE_AUDIT_V2_VECTOR,
            "device v2 signed_part must match the cross-client vector");
    }

    private void test_snapshot_vector() {
        uint8[] fp = new uint8[20]; for (int i = 0; i < 20; i++) fp[i] = 0xAB;
        uint8[] owner_fp = new uint8[20]; for (int i = 0; i < 20; i++) owner_fp[i] = 0xEF;
        uint8[] cert = new uint8[8]; for (int i = 0; i < 8; i++) cert[i] = 0xEE;

        var sp = new DeviceSnapshotPayload();
        sp.owner_aik_fp = owner_fp;
        sp.epoch = 5;
        var dev = new DeviceSnapshotDevice();
        dev.device_id = 42;
        dev.cert_bytes = cert;
        sp.devices.add(dev);
        uint8[] payload = DeviceAuditEntryV2.build_snapshot_payload(sp);

        var e = new DeviceAuditEntryV2();
        e.lamport = 2;
        e.signer_fp = fp;
        e.author_device_id = 7;
        e.parents = new Gee.ArrayList<Bytes>();
        e.action = (uint8) DeviceAuditActionV2.SNAPSHOT;
        e.payload = payload;
        e.timestamp = 0;
        fail_if_not_eq_str(hex(e.signed_part()), DEVICE_AUDIT_SNAPSHOT_VECTOR,
            "device snapshot signed_part must match the cross-client vector");

        DeviceSnapshotPayload? parsed = DeviceAuditEntryV2.parse_snapshot_payload(payload);
        fail_if(parsed == null, "snapshot payload parse null");
        fail_if_not_eq_str(hex(((!) parsed).owner_aik_fp), hex(owner_fp), "owner_aik_fp roundtrip");
        fail_if_not_eq_int((int) ((!) parsed).epoch, 5, "epoch roundtrip");
        fail_if_not_eq_int(((!) parsed).devices.size, 1, "device count roundtrip");
        fail_if_not_eq_int((int) ((!) parsed).devices.get(0).device_id, 42, "device_id roundtrip");
        fail_if_not_eq_str(hex(((!) parsed).devices.get(0).cert_bytes), hex(cert), "cert_bytes roundtrip");
    }

    private void test_marshal_roundtrip() {
        try {
            Id owner = make_id();
            uint8[] payload = DeviceAuditEntryV2.build_add_device_payload(1, make_cert_bytes(1));
            var e = sign(owner, 0, 1, heads(null), (uint8) DeviceAuditActionV2.ADD_DEVICE, payload, 1000);
            uint8[] wire = e.marshal();
            fail_if_not(DeviceAuditEntryV2.is_v2(wire), "is_v2 should detect v2 prefix");
            DeviceAuditEntryV2? e2 = DeviceAuditEntryV2.unmarshal(wire);
            fail_if(e2 == null, "unmarshal null");
            fail_if_not(((!) e2).verify(owner.ed_pub, owner.ml_pub), "verify roundtrip");
            fail_if_not_eq_str(hex(((!) e2).signer_fp), owner.fp_hex, "signer fp mismatch");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_genesis_add_device() {
        try {
            Id owner = make_id();
            var g = sign(owner, 0, 1, heads(null), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(1, make_cert_bytes(1)), 1000);
            var dag = new DeviceDag();
            dag.ingest(g.marshal());
            DeviceState st = dag.recompute(resolver());
            fail_if_not_eq_str(st.current_aik_fp_hex, owner.fp_hex, "owner should be genesis signer");
            fail_if_not(st.authorized.has_key("1"), "device 1 authorized from genesis");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_unknown_signer_rejected() {
        try {
            Id owner = make_id();
            Id intruder = make_id();
            var g = sign(owner, 0, 1, heads(null), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(1, make_cert_bytes(1)), 1000);
            var bad = sign(intruder, 1, 99, heads(g.compute_hash()), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(99, make_cert_bytes(99)), 1001);
            var dag = new DeviceDag();
            dag.ingest(g.marshal()); dag.ingest(bad.marshal());
            DeviceState st = dag.recompute(resolver());
            fail_if_not(st.authorized.has_key("1"), "device 1 authorized");
            fail_if(st.authorized.has_key("99"), "entry from a non-pinned AIK must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_convergence() {
        try {
            Id owner = make_id();
            var g = sign(owner, 0, 1, heads(null), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(1, make_cert_bytes(1)), 1000);
            uint8[] gh = g.compute_hash();
            // Two authorized devices concurrently AddDevice different device_ids.
            var a2 = sign(owner, 1, 2, heads(gh), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(2, make_cert_bytes(2)), 1001);
            var a3 = sign(owner, 1, 3, heads(gh), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(3, make_cert_bytes(3)), 1002);
            var all = new DeviceAuditEntryV2[]{g, a2, a3};

            var d1 = new DeviceDag();
            foreach (var e in all) d1.ingest(e.marshal());
            DeviceState s1 = d1.recompute(resolver());

            var d2 = new DeviceDag();
            for (int i = all.length - 1; i >= 0; i--) d2.ingest(all[i].marshal());
            DeviceState s2 = d2.recompute(resolver());

            fail_if_not(state_authorized_equal(s1, s2), "authorized set must converge regardless of ingest order");
            fail_if_not(s1.authorized.has_key("1") && s1.authorized.has_key("2") && s1.authorized.has_key("3"),
                "all three devices authorized");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_removal_wins() {
        try {
            Id owner = make_id();
            var g = sign(owner, 0, 1, heads(null), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(1, make_cert_bytes(1)), 1000);
            var add2 = sign(owner, 1, 1, heads(g.compute_hash()), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(2, make_cert_bytes(2)), 1001);
            uint8[] add2h = add2.compute_hash();
            // Concurrent: remove device 2 vs re-add device 2 with a fresh cert — both build on add2 (siblings).
            var rem = sign(owner, 2, 1, heads(add2h), (uint8) DeviceAuditActionV2.REMOVE_DEVICE,
                DeviceAuditEntryV2.build_remove_device_payload(2), 1002);
            var readd = sign(owner, 2, 1, heads(add2h), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(2, make_cert_bytes(2)), 1003);
            var dag = new DeviceDag();
            foreach (var e in new DeviceAuditEntryV2[]{g, add2, rem, readd}) dag.ingest(e.marshal());
            DeviceState st = dag.recompute(resolver());
            fail_if(st.authorized.has_key("2"), "removal must win over a concurrent (non-descendant) re-add");
            fail_if_not(st.removed.contains("2"), "device 2 recorded as removed");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_rotate_aik() {
        try {
            Id owner = make_id();
            Id new_owner = make_id();
            var g = sign(owner, 0, 1, heads(null), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(1, make_cert_bytes(1)), 1000);
            uint8[] new_aik_marshalled = DeviceAuditEntryV2.aik_pub_marshal(
                bytes_to_arr(new_owner.ed_pub), bytes_to_arr(new_owner.ml_pub));
            var rot = sign(owner, 1, 1, heads(g.compute_hash()), (uint8) DeviceAuditActionV2.ROTATE_AIK,
                DeviceAuditEntryV2.build_rotate_aik_payload(new_aik_marshalled), 1001);
            var add2 = sign(new_owner, 2, 1, heads(rot.compute_hash()), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(2, make_cert_bytes(2)), 1002);
            // An entry still signed by the OLD AIK after rotation must be rejected.
            var stale = sign(owner, 3, 1, heads(add2.compute_hash()), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(3, make_cert_bytes(3)), 1003);
            var dag = new DeviceDag();
            foreach (var e in new DeviceAuditEntryV2[]{g, rot, add2, stale}) dag.ingest(e.marshal());
            DeviceState st = dag.recompute(resolver());
            fail_if_not_eq_str(st.current_aik_fp_hex, new_owner.fp_hex, "fold must be re-pinned to the new AIK after RotateAIK");
            fail_if_not(st.authorized.has_key("1"), "device 1 still authorized");
            fail_if_not(st.authorized.has_key("2"), "device added under the new AIK is authorized");
            fail_if(st.authorized.has_key("3"), "device added under the stale (pre-rotation) AIK must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private void test_snapshot_genesis() {
        try {
            Id owner = make_id();
            uint8[] c1 = make_cert_bytes(10);
            uint8[] c2 = make_cert_bytes(11);
            var sp = new DeviceSnapshotPayload();
            sp.owner_aik_fp = owner.fp;
            sp.epoch = 7;
            var d1 = new DeviceSnapshotDevice(); d1.device_id = 10; d1.cert_bytes = c1;
            var d2 = new DeviceSnapshotDevice(); d2.device_id = 11; d2.cert_bytes = c2;
            sp.devices.add(d1); sp.devices.add(d2);
            uint8[] payload = DeviceAuditEntryV2.build_snapshot_payload(sp);
            var snap = sign(owner, 1, 1, heads(null), (uint8) DeviceAuditActionV2.SNAPSHOT, payload, 1000);

            // Snapshot alone: epoch is the asserted snapshot epoch.
            var snap_only_dag = new DeviceDag();
            snap_only_dag.ingest(snap.marshal());
            DeviceState snap_only_st = snap_only_dag.recompute(resolver());
            fail_if_not_eq_str(snap_only_st.current_aik_fp_hex, owner.fp_hex, "owner TOFU-pinned from the genesis snapshot's signer");
            fail_if_not(snap_only_st.authorized.has_key("10"), "device 10 imported from snapshot");
            fail_if_not(snap_only_st.authorized.has_key("11"), "device 11 imported from snapshot");
            fail_if_not_eq_int((int) snap_only_st.epoch, 7, "epoch imported from snapshot");

            // A device added by the pinned AIK on top of the bridging snapshot.
            var add = sign(owner, 2, 1, heads(snap.compute_hash()), (uint8) DeviceAuditActionV2.ADD_DEVICE,
                DeviceAuditEntryV2.build_add_device_payload(12, make_cert_bytes(12)), 1001);
            var dag = new DeviceDag();
            dag.ingest(snap.marshal()); dag.ingest(add.marshal());
            DeviceState st = dag.recompute(resolver());
            fail_if_not(st.authorized.has_key("10"), "device 10 imported from snapshot");
            fail_if_not(st.authorized.has_key("11"), "device 11 imported from snapshot");
            fail_if_not(st.authorized.has_key("12"), "device 12 added on top of the bridging snapshot");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    private bool state_authorized_equal(DeviceState a, DeviceState b) {
        if (a.authorized.size != b.authorized.size) return false;
        foreach (string k in a.authorized.keys) if (!b.authorized.has_key(k)) return false;
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
