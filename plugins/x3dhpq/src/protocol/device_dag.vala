// x3dhpq-xep-draft.md §11.7: multi-writer device-audit DAG (v2).
//
// The account's authorised device set is the fold of an AIK-rooted, append-only
// hash-DAG with an enforced Lamport clock — the audit chain (§11) generalised to
// multiple writers (§10.6.6). Any authorized device (any holder of AIK_priv) may
// append concurrently; all authorized devices converge on the same set. This
// mirrors the group membership journal (membership_dag.vala): same canonical
// order discipline (Kahn topo-sort, ties by (lamport, signer_fp, entry_hash)).
//
// Authorization DIFFERS from the group journal — it is simpler: all authorized
// devices of one account share the SAME account AIK, so an entry is authorized
// iff BOTH hybrid signatures verify under the CURRENT account AIK (TOFU-pinned
// at genesis / first Snapshot). There is no signer∈admins set: a disabled device
// holds no AIK_priv and cannot produce a valid signature. `author_device_id`
// records which device authored the change for the §11.6 "was this you?" UX only.
//
// v2 signed_part layout (all integers big-endian), domain separator
// "X3DHPQ-DevAudit-v2\0" (distinct from the group journal's "X3DHPQ-Audit-v2\0"
// to prevent cross-context replay):
//   "X3DHPQ-DevAudit-v2\0" (19)
//   lamport            uint64
//   signer_fp          20 bytes          (raw BLAKE2b-160 of the account AIK)
//   author_device_id   uint32            (attribution only, never an authz input)
//   parent_count       uint32
//   parents[N]         32 bytes each     (SHA-256(marshal(parent)))
//   action             uint8
//   payload_len        uint32
//   payload            payload_len bytes
//   timestamp          int64 (as uint64)
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl
// entry_hash = SHA-256(marshal)
//
// Actions: AddDevice=1, RemoveDevice=2, RotateAIK=3 (§11.4, unchanged), plus
// Snapshot=10 (asserts the folded device set + current AIK at a DAG cut, for
// v1->v2 migration and prune-proof catch-up).

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public enum DeviceAuditActionV2 {
    ADD_DEVICE = 1,
    REMOVE_DEVICE = 2,
    ROTATE_AIK = 3,
    SNAPSHOT = 10,
}

// Resolve a signer's AIK public keys from its raw-hex fingerprint. Returns false
// if the AIK is not (yet) known, in which case the entry is skipped in the fold.
public delegate bool DeviceAikResolver(string signer_fp_hex, out Bytes ed, out Bytes mldsa);

public class DeviceAuditEntryV2 : Object {
    public uint64 lamport { get; set; }
    public uint8[] signer_fp { get; set; }             // 20 bytes; account AIK fp
    public uint32 author_device_id { get; set; }        // attribution only
    public Gee.ArrayList<Bytes> parents { get; set; default = new Gee.ArrayList<Bytes>(); } // each 32 bytes
    public uint8 action { get; set; }
    public uint8[] payload { get; set; }
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }
    public uint8[] mldsa_signature { get; set; }

    private static uint8[] v2_prefix() {
        return { 'X','3','D','H','P','Q','-','D','e','v','A','u','d','i','t','-','v','2', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v2_prefix();
        int size = PREFIX.length + 8 + 20 + 4 + 4 + parents.size * 32 + 1 + 4 + payload.length + 8;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, lamport);
        Memory.copy((uint8*) buf + off, signer_fp, 20);
        off += 20;
        put_u32(buf, ref off, author_device_id);
        put_u32(buf, ref off, (uint32) parents.size);
        foreach (Bytes p in parents) {
            Memory.copy((uint8*) buf + off, p.get_data(), 32);
            off += 32;
        }
        buf[off++] = action;
        put_u32(buf, ref off, (uint32) payload.length);
        if (payload.length > 0) {
            Memory.copy((uint8*) buf + off, payload, payload.length);
            off += payload.length;
        }
        put_u64(buf, ref off, (uint64) timestamp);
        return buf;
    }

    public uint8[] marshal() {
        uint8[] sp = signed_part();
        int size = sp.length + 2 + signature.length + 2 + mldsa_signature.length;
        uint8[] buf = new uint8[size];
        Memory.copy(buf, sp, sp.length);
        int off = sp.length;
        put_u16(buf, ref off, (uint16) signature.length);
        Memory.copy((uint8*) buf + off, signature, signature.length);
        off += signature.length;
        put_u16(buf, ref off, (uint16) mldsa_signature.length);
        Memory.copy((uint8*) buf + off, mldsa_signature, mldsa_signature.length);
        return buf;
    }

    public uint8[] compute_hash() {
        try {
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha256(new Bytes(marshal())));
        } catch (GLib.Error e) {
            return new uint8[32];
        }
    }

    public string hash_hex() {
        return hex_of(compute_hash());
    }

    public bool verify(Bytes aik_ed, Bytes aik_mldsa) throws GLib.Error {
        if (signature.length == 0 || mldsa_signature.length == 0) return false;
        uint8[] sp = signed_part();
        if (!global::X3dhpq.Crypto.ed25519_verify(aik_ed, new Bytes(sp), new Bytes(signature))) return false;
        return global::X3dhpq.Crypto.mldsa65_verify(aik_mldsa, new Bytes(sp), new Bytes(mldsa_signature));
    }

    public static bool is_v2(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static DeviceAuditEntryV2? unmarshal(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        int min = PREFIX.length + 8 + 20 + 4 + 4 + 1 + 4 + 8 + 2 + 2;
        if (b.length < min) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) if (b[off + i] != PREFIX[i]) return null;
        off += PREFIX.length;

        DeviceAuditEntryV2 e = new DeviceAuditEntryV2();
        e.lamport = get_u64(b, ref off);
        e.signer_fp = new uint8[20];
        Memory.copy(e.signer_fp, (uint8*) b + off, 20);
        off += 20;
        e.author_device_id = get_u32(b, ref off);
        int64 pc64 = (int64) get_u32(b, ref off);
        if (pc64 < 0 || pc64 > 4096) return null;
        int pc = (int) pc64;
        if ((int64) off + (int64) pc * 32 + 1 + 4 + 8 + 2 + 2 > (int64) b.length) return null;
        e.parents = new Gee.ArrayList<Bytes>();
        for (int i = 0; i < pc; i++) {
            uint8[] p = new uint8[32];
            Memory.copy(p, (uint8*) b + off, 32);
            off += 32;
            e.parents.add(new Bytes(p));
        }
        e.action = b[off++];
        uint32 pl = get_u32(b, ref off);
        if ((int64) off + (int64) pl + 8 + 2 + 2 > (int64) b.length) return null;
        e.payload = new uint8[(int) pl];
        if (pl > 0) Memory.copy(e.payload, (uint8*) b + off, (int) pl);
        off += (int) pl;
        e.timestamp = (int64) get_u64(b, ref off);

        if (off + 2 > b.length) return null;
        int sl = (int) get_u16(b, ref off);
        if (off + sl + 2 > b.length) return null;
        e.signature = new uint8[sl];
        if (sl > 0) Memory.copy(e.signature, (uint8*) b + off, sl);
        off += sl;
        int ml = (int) get_u16(b, ref off);
        if (off + ml > b.length) return null;
        e.mldsa_signature = new uint8[ml];
        if (ml > 0) Memory.copy(e.mldsa_signature, (uint8*) b + off, ml);
        if (sl == 0 || ml == 0) return null;
        return e;
    }

    // -------------------------------------------------------------------------
    // §11.4 device action payload codecs (unchanged from v1, reused verbatim).
    // -------------------------------------------------------------------------

    // AddDevice(1): uint32(device_id) | uint32(cert_len) | DeviceCertificate.marshal().
    public static uint8[] build_add_device_payload(uint32 device_id, uint8[] cert_bytes) {
        uint8[] buf = new uint8[4 + 4 + cert_bytes.length];
        int off = 0;
        put_u32(buf, ref off, device_id);
        put_u32(buf, ref off, (uint32) cert_bytes.length);
        if (cert_bytes.length > 0) Memory.copy((uint8*) buf + off, cert_bytes, cert_bytes.length);
        return buf;
    }

    public static bool parse_add_device_payload(uint8[] payload, out uint32 device_id, out uint8[] cert_bytes) {
        device_id = 0;
        cert_bytes = new uint8[0];
        if (payload.length < 8) return false;
        int off = 0;
        device_id = get_u32(payload, ref off);
        uint32 cert_len = get_u32(payload, ref off);
        if ((int64) off + (int64) cert_len > (int64) payload.length) return false;
        cert_bytes = new uint8[cert_len];
        if (cert_len > 0) Memory.copy(cert_bytes, (uint8*) payload + off, (int) cert_len);
        return true;
    }

    // RemoveDevice(2): uint32(device_id).
    public static uint8[] build_remove_device_payload(uint32 device_id) {
        uint8[] buf = new uint8[4];
        int off = 0;
        put_u32(buf, ref off, device_id);
        return buf;
    }

    public static bool parse_remove_device_payload(uint8[] payload, out uint32 device_id) {
        device_id = 0;
        if (payload.length < 4) return false;
        int off = 0;
        device_id = get_u32(payload, ref off);
        return true;
    }

    // RotateAIK(3): uint16(new_aik_len) | AccountIdentityPub.marshal().
    public static uint8[] build_rotate_aik_payload(uint8[] new_aik_marshalled) {
        uint8[] buf = new uint8[2 + new_aik_marshalled.length];
        int off = 0;
        put_u16(buf, ref off, (uint16) new_aik_marshalled.length);
        if (new_aik_marshalled.length > 0) Memory.copy((uint8*) buf + off, new_aik_marshalled, new_aik_marshalled.length);
        return buf;
    }

    public static bool parse_rotate_aik_payload(uint8[] payload, out uint8[] new_aik_bytes) {
        new_aik_bytes = new uint8[0];
        if (payload.length < 2) return false;
        int off = 0;
        int len = (int) get_u16(payload, ref off);
        if (off + len > payload.length) return false;
        new_aik_bytes = new uint8[len];
        if (len > 0) Memory.copy(new_aik_bytes, (uint8*) payload + off, len);
        return true;
    }

    // AccountIdentityPub wire encoding, byte-compatible with the Java engine's
    // AccountIdentityPub.marshal(): uint16(version=1) | uint8(hasMLDSA=1) | ed25519 pub(32) | mldsa65 pub(1952).
    public static uint8[] aik_pub_marshal(uint8[] ed_pub, uint8[] mldsa_pub) {
        uint8[] buf = new uint8[2 + 1 + ed_pub.length + mldsa_pub.length];
        int off = 0;
        put_u16(buf, ref off, 1);
        buf[off++] = 1;
        if (ed_pub.length > 0) Memory.copy((uint8*) buf + off, ed_pub, ed_pub.length);
        off += ed_pub.length;
        if (mldsa_pub.length > 0) Memory.copy((uint8*) buf + off, mldsa_pub, mldsa_pub.length);
        return buf;
    }

    public static bool aik_pub_unmarshal(uint8[] data, out uint8[] ed_pub, out uint8[] mldsa_pub) {
        ed_pub = new uint8[0];
        mldsa_pub = new uint8[0];
        if (data.length < 3 + 32 + 1952) return false;
        int off = 0;
        uint16 ver = get_u16(data, ref off);
        if (ver != 1) return false;
        uint8 has_mldsa = data[off++];
        if (has_mldsa != 1) return false;
        ed_pub = new uint8[32];
        Memory.copy(ed_pub, (uint8*) data + off, 32);
        off += 32;
        mldsa_pub = new uint8[1952];
        Memory.copy(mldsa_pub, (uint8*) data + off, 1952);
        return true;
    }

    // ---- Snapshot (action=10) payload codec (§11.7) ----
    // Layout (big-endian):
    //   owner_aik_fp(20) | epoch(uint64) | count(uint32)
    //   | { device_id(uint32) | cert_len(uint32) | DC.marshal() }*
    public static uint8[] build_snapshot_payload(DeviceSnapshotPayload sp) {
        int count = sp.devices.size;
        int size = 20 + 8 + 4;
        foreach (var d in sp.devices) size += 4 + 4 + d.cert_bytes.length;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy((uint8*) buf + off, sp.owner_aik_fp, 20); off += 20;
        put_u64(buf, ref off, sp.epoch);
        put_u32(buf, ref off, (uint32) count);
        foreach (var d in sp.devices) {
            put_u32(buf, ref off, d.device_id);
            put_u32(buf, ref off, (uint32) d.cert_bytes.length);
            if (d.cert_bytes.length > 0) {
                Memory.copy((uint8*) buf + off, d.cert_bytes, d.cert_bytes.length);
                off += d.cert_bytes.length;
            }
        }
        return buf;
    }

    public static DeviceSnapshotPayload? parse_snapshot_payload(uint8[] p) {
        if (p.length < 20 + 8 + 4) return null;
        int off = 0;
        var sp = new DeviceSnapshotPayload();
        sp.owner_aik_fp = new uint8[20];
        Memory.copy(sp.owner_aik_fp, p, 20); off += 20;
        sp.epoch = get_u64(p, ref off);
        int64 count64 = (int64) get_u32(p, ref off);
        if (count64 < 0 || count64 > 1000000) return null;
        int count = (int) count64;
        for (int i = 0; i < count; i++) {
            if ((int64) off + 8 > (int64) p.length) return null;
            uint32 device_id = get_u32(p, ref off);
            uint32 cert_len = get_u32(p, ref off);
            if ((int64) off + (int64) cert_len > (int64) p.length) return null;
            uint8[] cert = new uint8[cert_len];
            if (cert_len > 0) Memory.copy(cert, (uint8*) p + off, (int) cert_len);
            off += (int) cert_len;
            var dev = new DeviceSnapshotDevice();
            dev.device_id = device_id;
            dev.cert_bytes = cert;
            sp.devices.add(dev);
        }
        return sp;
    }

    private static void put_u16(uint8[] b, ref int off, uint16 v) {
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static void put_u32(uint8[] b, ref int off, uint32 v) {
        b[off++] = (uint8)(v >> 24); b[off++] = (uint8)(v >> 16);
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static void put_u64(uint8[] b, ref int off, uint64 v) {
        for (int i = 7; i >= 0; i--) b[off++] = (uint8)(v >> (i * 8));
    }
    private static uint16 get_u16(uint8[] b, ref int off) {
        uint16 v = (uint16)((b[off] << 8) | b[off + 1]); off += 2; return v;
    }
    private static uint32 get_u32(uint8[] b, ref int off) {
        uint32 v = ((uint32) b[off] << 24) | ((uint32) b[off+1] << 16) | ((uint32) b[off+2] << 8) | (uint32) b[off+3];
        off += 4; return v;
    }
    private static uint64 get_u64(uint8[] b, ref int off) {
        uint64 v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | b[off + i];
        off += 8; return v;
    }
}

// Decoded genesis-Snapshot payload. Not identical to the group journal's
// SnapshotPayload: there is no admin/banned distinction here, just the asserted
// authorized device set at a DAG cut.
public class DeviceSnapshotDevice : Object {
    public uint32 device_id = 0;
    public uint8[] cert_bytes = new uint8[0];
}

public class DeviceSnapshotPayload : Object {
    public uint8[] owner_aik_fp = new uint8[20];  // sanity-checked against the entry's own signer_fp
    public uint64 epoch = 0;
    public Gee.ArrayList<DeviceSnapshotDevice> devices = new Gee.ArrayList<DeviceSnapshotDevice>();
}

// The folded device state. `authorized`/`removed` are keyed by the device_id's
// base-10 string form (Vala's Gee generics are happiest with reference/string
// keys; the numeric device_id is recoverable via uint32.parse()).
public class DeviceState : Object {
    public Gee.HashMap<string, DeviceCertificate> authorized = new Gee.HashMap<string, DeviceCertificate>();
    public Gee.HashSet<string> removed = new Gee.HashSet<string>();
    public Bytes? current_aik_ed = null;
    public Bytes? current_aik_mldsa = null;
    public string? current_aik_fp_hex = null;
    public uint32 epoch = 0;
}

public class DeviceDag : Object {
    // entry_hash_hex -> entry
    private Gee.HashMap<string, DeviceAuditEntryV2> store = new Gee.HashMap<string, DeviceAuditEntryV2>();

    public int size { get { return store.size; } }

    public bool ingest(uint8[] bytes) {
        DeviceAuditEntryV2? e = DeviceAuditEntryV2.unmarshal(bytes);
        if (e == null) return false;
        string h = e.hash_hex();
        if (store.has_key(h)) return false;
        store.set(h, e);
        return true;
    }

    public bool has_entry(uint8[] bytes) {
        DeviceAuditEntryV2? e = DeviceAuditEntryV2.unmarshal(bytes);
        if (e == null) return false;
        return store.has_key(e.hash_hex());
    }

    // Every stored entry, marshaled — for catch-up bundling.
    public Gee.ArrayList<Bytes> all_marshaled() {
        var l = new Gee.ArrayList<Bytes>();
        foreach (var en in store.entries) l.add(new Bytes(en.value.marshal()));
        return l;
    }

    private Gee.ArrayList<DeviceAuditEntryV2> canonical_order() {
        var includable = new Gee.HashSet<string>();
        bool changed = true;
        while (changed) {
            changed = false;
            foreach (var en in store.entries) {
                if (includable.contains(en.key)) continue;
                bool all = true;
                foreach (Bytes p in en.value.parents) {
                    string ph = hex_of(p.get_data());
                    if (!store.has_key(ph) || !includable.contains(ph)) { all = false; break; }
                }
                if (all) { includable.add(en.key); changed = true; }
            }
        }
        var indeg = new Gee.HashMap<string, int>();
        var children = new Gee.HashMap<string, Gee.ArrayList<string>>();
        foreach (string h in includable) indeg.set(h, 0);
        foreach (string h in includable) {
            DeviceAuditEntryV2 e = store.get(h);
            int d = 0;
            foreach (Bytes p in e.parents) {
                string ph = hex_of(p.get_data());
                if (includable.contains(ph)) {
                    d++;
                    if (!children.has_key(ph)) children.set(ph, new Gee.ArrayList<string>());
                    children.get(ph).add(h);
                }
            }
            indeg.set(h, d);
        }
        var ready = new Gee.ArrayList<string>();
        foreach (string h in includable) if (indeg.get(h) == 0) ready.add(h);
        var order = new Gee.ArrayList<DeviceAuditEntryV2>();
        while (ready.size > 0) {
            ready.sort((a, b) => cmp_key(store.get(a), store.get(b)));
            string h = ready.remove_at(0);
            order.add(store.get(h));
            if (children.has_key(h)) {
                foreach (string c in children.get(h)) {
                    indeg.set(c, indeg.get(c) - 1);
                    if (indeg.get(c) == 0) ready.add(c);
                }
            }
        }
        return order;
    }

    private static int cmp_key(DeviceAuditEntryV2 a, DeviceAuditEntryV2 b) {
        if (a.lamport != b.lamport) return a.lamport < b.lamport ? -1 : 1;
        int s = strcmp(hex_of(a.signer_fp), hex_of(b.signer_fp));
        if (s != 0) return s;
        return strcmp(a.hash_hex(), b.hash_hex());
    }

    public DeviceState recompute(DeviceAikResolver resolver) {
        var st = new DeviceState();
        var order = canonical_order();
        var removal_node = new Gee.HashMap<string, string>(); // device_id_str -> removal entry hash
        string? pinned_fp_hex = null;
        Bytes? pinned_ed = null;
        Bytes? pinned_mldsa = null;

        for (int i = 0; i < order.size; i++) {
            DeviceAuditEntryV2 e = order.get(i);
            string signer_hex = hex_of(e.signer_fp);

            if (i == 0) {
                Bytes ed, ml;
                if (!resolver(signer_hex, out ed, out ml)) continue;
                bool ok;
                try {
                    ok = e.verify(ed, ml);
                } catch (GLib.Error err) { continue; }
                if (!ok) continue;
                pinned_fp_hex = signer_hex;
                pinned_ed = ed;
                pinned_mldsa = ml;
                st.current_aik_fp_hex = signer_hex;
                st.current_aik_ed = ed;
                st.current_aik_mldsa = ml;
                st.epoch = 0;
            } else {
                if (signer_hex != pinned_fp_hex) continue; // must be signed by the currently pinned AIK
                if (pinned_ed == null || pinned_mldsa == null) continue;
                bool ok;
                try {
                    ok = e.verify(pinned_ed, pinned_mldsa);
                } catch (GLib.Error err) { continue; }
                if (!ok) continue;
                st.epoch = (uint32) i;
            }

            switch (e.action) {
                case (uint8) DeviceAuditActionV2.ADD_DEVICE: {
                    uint32 device_id; uint8[] cert_bytes;
                    if (!DeviceAuditEntryV2.parse_add_device_payload(e.payload, out device_id, out cert_bytes)) break;
                    string idk = device_id.to_string();
                    if (!can_readd(st, removal_node, idk, e)) break;
                    DeviceCertificate? dc = DeviceCertificate.unmarshal(new Bytes(cert_bytes));
                    if (dc == null) break; // malformed cert: reject the AddDevice
                    st.authorized.set(idk, dc);
                    st.removed.remove(idk);
                    break;
                }
                case (uint8) DeviceAuditActionV2.REMOVE_DEVICE: {
                    uint32 device_id;
                    if (!DeviceAuditEntryV2.parse_remove_device_payload(e.payload, out device_id)) break;
                    string idk = device_id.to_string();
                    st.authorized.unset(idk);
                    st.removed.add(idk);
                    removal_node.set(idk, e.hash_hex());
                    break;
                }
                case (uint8) DeviceAuditActionV2.ROTATE_AIK: {
                    uint8[] new_aik_bytes;
                    if (!DeviceAuditEntryV2.parse_rotate_aik_payload(e.payload, out new_aik_bytes)) break;
                    uint8[] new_ed, new_mldsa;
                    if (!DeviceAuditEntryV2.aik_pub_unmarshal(new_aik_bytes, out new_ed, out new_mldsa)) break;
                    try {
                        Bytes fp = global::X3dhpq.Crypto.blake2b160(new Bytes(DeviceAuditEntryV2.aik_pub_marshal(new_ed, new_mldsa)));
                        pinned_fp_hex = hex_of(fp.get_data());
                    } catch (GLib.Error err) { break; }
                    pinned_ed = new Bytes(new_ed);
                    pinned_mldsa = new Bytes(new_mldsa);
                    st.current_aik_ed = pinned_ed;
                    st.current_aik_mldsa = pinned_mldsa;
                    st.current_aik_fp_hex = pinned_fp_hex;
                    break;
                }
                case (uint8) DeviceAuditActionV2.SNAPSHOT: {
                    if (i == 0) apply_genesis_snapshot(st, e);
                    // A mid-DAG Snapshot is a passive checkpoint only.
                    break;
                }
            }
        }
        return st;
    }

    // Import a genesis Snapshot's asserted device set (v1->v2 bridge / prune-proof catch-up).
    private void apply_genesis_snapshot(DeviceState st, DeviceAuditEntryV2 e) {
        DeviceSnapshotPayload? sp = DeviceAuditEntryV2.parse_snapshot_payload(e.payload);
        if (sp == null) return;
        foreach (var d in sp.devices) {
            DeviceCertificate? dc = DeviceCertificate.unmarshal(new Bytes(d.cert_bytes));
            if (dc == null) continue; // skip malformed device entries only
            st.authorized.set(d.device_id.to_string(), dc);
        }
        st.epoch = (uint32) sp.epoch;
    }

    private bool can_readd(DeviceState st, Gee.HashMap<string, string> removal_node, string idk, DeviceAuditEntryV2 add_entry) {
        if (!st.removed.contains(idk)) return true;
        string? rn = removal_node.get(idk);
        if (rn == null) return true;
        return is_ancestor(rn, add_entry);
    }

    private bool is_ancestor(string ancestor_hex, DeviceAuditEntryV2 descendant) {
        var seen = new Gee.HashSet<string>();
        var stack = new Gee.ArrayList<string>();
        foreach (Bytes p in descendant.parents) stack.add(hex_of(p.get_data()));
        while (stack.size > 0) {
            string h = stack.remove_at(stack.size - 1);
            if (h == ancestor_hex) return true;
            if (seen.contains(h)) continue;
            seen.add(h);
            DeviceAuditEntryV2? pe = store.get(h);
            if (pe != null) foreach (Bytes pp in pe.parents) stack.add(hex_of(pp.get_data()));
        }
        return false;
    }

    public Gee.ArrayList<Bytes> current_heads() {
        var has_child = new Gee.HashSet<string>();
        foreach (var en in store.entries) {
            foreach (Bytes p in en.value.parents) has_child.add(hex_of(p.get_data()));
        }
        var heads = new Gee.ArrayList<Bytes>();
        foreach (var en in store.entries) {
            if (!has_child.contains(en.key)) heads.add(new Bytes(en.value.compute_hash()));
        }
        return heads;
    }

    public uint64 next_lamport() {
        uint64 m = 0;
        foreach (var en in store.entries) if (en.value.lamport > m) m = en.value.lamport;
        return m + 1;
    }
}

}
