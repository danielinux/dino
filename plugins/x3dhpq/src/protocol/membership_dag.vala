// WS2: multi-admin membership journal (v2).
//
// The v1 journal (membership_journal.vala) is a single-writer, owner-signed,
// strictly linear seq+prev_hash chain. Multi-admin management (owner + admins
// who may invite/kick/ban and promote/demote other admins) needs multiple
// concurrent writers over the shared MUC channel, so the linear chain is
// replaced by a hash-DAG with an enforced Lamport clock, folded in a
// deterministic topological order. The canonical order is fully content-derived
// (NOT the server/MAM delivery order), so a malicious relay cannot change the
// derived member/admin set by reordering.
//
// v2 signed_part layout (all integers big-endian):
//   "X3DHPQ-Audit-v2\0" (16)
//   lamport        uint64            (> max(parent.lamport), enforced)
//   signer_fp      20 bytes          (raw BLAKE2b-160 of the signing AIK)
//   parent_count   uint16
//   parents[N]     32 bytes each     (SHA-256(marshal(parent)))
//   action         uint8
//   payload_len    uint32
//   payload        payload_len bytes
//   timestamp      int64 (as uint64)
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl
// entry_hash = SHA-256(marshal)
//
// Actions: AddMember=5, RemoveMember=6 (+optional ban flag byte), AddAdmin=7,
// RemoveAdmin=8, Snapshot=10. Payload for 5/7/8 reuses the v1 24-byte
// subject_fp(20)|epoch_after(4); RemoveMember is 24 or 25 bytes (trailing
// flags byte, bit0 = ban). Parents/heads are carried as GLib.Bytes because Vala
// forbids uint8[] as a generic type argument.

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public enum MemberAuditActionV2 {
    ADD_MEMBER = 5,
    REMOVE_MEMBER = 6,
    ADD_ADMIN = 7,
    REMOVE_ADMIN = 8,
    SNAPSHOT = 10,
}

// Resolve a signer's AIK public keys from its raw-hex fingerprint. Returns false
// if the AIK is not (yet) known, in which case the entry is skipped in the fold.
public delegate bool AikResolver(string signer_fp_hex, out Bytes ed, out Bytes mldsa);

public static string hex_of(uint8[] b) {
    StringBuilder sb = new StringBuilder();
    foreach (uint8 x in b) sb.append_printf("%02x", x);
    return sb.str;
}

public class JournalEntryV2 : Object {
    public uint64 lamport { get; set; }
    public uint8[] signer_fp { get; set; }            // 20 bytes
    public Gee.ArrayList<Bytes> parents { get; set; default = new Gee.ArrayList<Bytes>(); } // each 32 bytes
    public uint8 action { get; set; }
    public uint8[] payload { get; set; }
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }
    public uint8[] mldsa_signature { get; set; }

    private static uint8[] v2_prefix() {
        return { 'X','3','D','H','P','Q','-','A','u','d','i','t','-','v','2', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v2_prefix();
        int size = PREFIX.length + 8 + 20 + 2 + parents.size * 32 + 1 + 4 + payload.length + 8;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, lamport);
        Memory.copy((uint8*) buf + off, signer_fp, 20);
        off += 20;
        put_u16(buf, ref off, (uint16) parents.size);
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

    public bool verify(Bytes signer_ed, Bytes signer_mldsa) throws GLib.Error {
        if (signature.length == 0 || mldsa_signature.length == 0) return false;
        uint8[] sp = signed_part();
        if (!global::X3dhpq.Crypto.ed25519_verify(signer_ed, new Bytes(sp), new Bytes(signature))) return false;
        return global::X3dhpq.Crypto.mldsa65_verify(signer_mldsa, new Bytes(sp), new Bytes(mldsa_signature));
    }

    public static bool is_v2(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static JournalEntryV2? unmarshal(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        int min = PREFIX.length + 8 + 20 + 2 + 1 + 4 + 8 + 2 + 2;
        if (b.length < min) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) if (b[off + i] != PREFIX[i]) return null;
        off += PREFIX.length;

        JournalEntryV2 e = new JournalEntryV2();
        e.lamport = get_u64(b, ref off);
        e.signer_fp = new uint8[20];
        Memory.copy(e.signer_fp, (uint8*) b + off, 20);
        off += 20;
        int pc = (int) get_u16(b, ref off);
        if (pc < 0 || pc > 4096) return null;
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

    public static uint8[] build_member_payload(uint8[] fp20, uint32 epoch_after) {
        return MemberAuditEntry.build_member_payload(fp20, epoch_after);
    }

    public static uint8[] build_remove_payload(uint8[] fp20, uint32 epoch_after, bool ban) {
        uint8[] basep = MemberAuditEntry.build_member_payload(fp20, epoch_after);
        uint8[] buf = new uint8[25];
        Memory.copy(buf, basep, 24);
        buf[24] = ban ? 0x01 : 0x00;
        return buf;
    }

    public static bool parse_subject_fp(uint8[] payload, out uint8[] fp20) {
        fp20 = new uint8[20];
        if (payload.length < 20) return false;
        Memory.copy(fp20, payload, 20);
        return true;
    }

    public static bool payload_is_ban(uint8[] payload) {
        return payload.length >= 25 && (payload[24] & 0x01) != 0;
    }

    // v1->v2 bridge Snapshot payload (cross-client contract, big-endian):
    //   owner_fp(20) | epoch(8) | member_count(4) |
    //   member[ fp(20) | is_admin(1) ]* |
    //   banned_count(4) | banned[ fp(20) | removal_epoch(4) ]*
    // Pubkeys are NOT embedded — resolved via the AIK/devicelist layer.
    public static uint8[] build_snapshot_payload(SnapshotPayload sp) {
        int mc = sp.member_fps.size;
        int bc = sp.banned_fps.size;
        int size = 20 + 8 + 4 + mc * 21 + 4 + bc * 24;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy((uint8*) buf + off, sp.owner_fp, 20); off += 20;
        put_u64(buf, ref off, sp.epoch);
        put_u32(buf, ref off, (uint32) mc);
        for (int i = 0; i < mc; i++) {
            Memory.copy((uint8*) buf + off, sp.member_fps.get(i).get_data(), 20); off += 20;
            buf[off++] = sp.member_is_admin.get(i) ? 0x01 : 0x00;
        }
        put_u32(buf, ref off, (uint32) bc);
        for (int i = 0; i < bc; i++) {
            Memory.copy((uint8*) buf + off, sp.banned_fps.get(i).get_data(), 20); off += 20;
            put_u32(buf, ref off, sp.banned_epochs.get(i));
        }
        return buf;
    }

    public static SnapshotPayload? parse_snapshot_payload(uint8[] p) {
        if (p.length < 20 + 8 + 4) return null;
        int off = 0;
        var sp = new SnapshotPayload();
        sp.owner_fp = new uint8[20];
        Memory.copy(sp.owner_fp, p, 20); off += 20;
        sp.epoch = get_u64(p, ref off);
        int mc = (int) get_u32(p, ref off);
        if (mc < 0 || mc > 100000) return null;
        if ((int64) off + (int64) mc * 21 + 4 > (int64) p.length) return null;
        for (int i = 0; i < mc; i++) {
            uint8[] fp = new uint8[20];
            Memory.copy(fp, (uint8*) p + off, 20); off += 20;
            bool adm = p[off++] != 0x00;
            sp.member_fps.add(new Bytes(fp));
            sp.member_is_admin.add(adm);
        }
        int bc = (int) get_u32(p, ref off);
        if (bc < 0 || bc > 100000) return null;
        if ((int64) off + (int64) bc * 24 > (int64) p.length) return null;
        for (int i = 0; i < bc; i++) {
            uint8[] fp = new uint8[20];
            Memory.copy(fp, (uint8*) p + off, 20); off += 20;
            uint32 rep = get_u32(p, ref off);
            sp.banned_fps.add(new Bytes(fp));
            sp.banned_epochs.add(rep);
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

// Decoded v1->v2 bridge Snapshot payload. member_fps[i] pairs with
// member_is_admin[i]; banned_fps[i] pairs with banned_epochs[i].
public class SnapshotPayload : Object {
    public uint8[] owner_fp;                                             // 20 bytes
    public uint64 epoch = 0;
    public Gee.ArrayList<Bytes> member_fps = new Gee.ArrayList<Bytes>(); // 20 bytes each
    public Gee.ArrayList<bool> member_is_admin = new Gee.ArrayList<bool>();
    public Gee.ArrayList<Bytes> banned_fps = new Gee.ArrayList<Bytes>(); // 20 bytes each
    public Gee.ArrayList<uint32> banned_epochs = new Gee.ArrayList<uint32>();
}

public class DagState : Object {
    public Gee.HashSet<string> members = new Gee.HashSet<string>();     // fp_hex
    public Gee.HashSet<string> admins = new Gee.HashSet<string>();      // fp_hex
    public Gee.HashMap<string, uint32> removed = new Gee.HashMap<string, uint32>(); // fp_hex -> removal epoch
    public Gee.HashSet<string> banned = new Gee.HashSet<string>();      // fp_hex
    public string? owner_fp = null;                                     // fp_hex
    public uint32 epoch = 0;
}

public class MembershipDag : Object {
    // entry_hash_hex -> entry
    private Gee.HashMap<string, JournalEntryV2> store = new Gee.HashMap<string, JournalEntryV2>();

    public int size { get { return store.size; } }

    public bool ingest(uint8[] bytes) {
        JournalEntryV2? e = JournalEntryV2.unmarshal(bytes);
        if (e == null) return false;
        string h = e.hash_hex();
        if (store.has_key(h)) return false;
        store.set(h, e);
        return true;
    }

    public bool has_entry(uint8[] bytes) {
        JournalEntryV2? e = JournalEntryV2.unmarshal(bytes);
        if (e == null) return false;
        return store.has_key(e.hash_hex());
    }

    // Every stored entry, marshaled — for re-broadcast in the group-sync bundle.
    public Gee.ArrayList<Bytes> all_marshaled() {
        var l = new Gee.ArrayList<Bytes>();
        foreach (var en in store.entries) l.add(new Bytes(en.value.marshal()));
        return l;
    }

    private Gee.ArrayList<JournalEntryV2> canonical_order() {
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
            JournalEntryV2 e = store.get(h);
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
        var order = new Gee.ArrayList<JournalEntryV2>();
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

    private static int cmp_key(JournalEntryV2 a, JournalEntryV2 b) {
        if (a.lamport != b.lamport) return a.lamport < b.lamport ? -1 : 1;
        int s = strcmp(hex_of(a.signer_fp), hex_of(b.signer_fp));
        if (s != 0) return s;
        return strcmp(a.hash_hex(), b.hash_hex());
    }

    public DagState recompute(AikResolver resolver) {
        return recompute_pinned(resolver, null);
    }

    // Fold the DAG into a member/admin state (§13.1a).
    //
    // `pinned_owner_fp`, when non-null, is the raw-hex fingerprint this room has
    // already been pinned to; only an entry signed by it (or, for a Snapshot genesis,
    // one asserting it as owner) may act as the genesis. Callers MUST persist the owner
    // the first time a room folds to one and pass it back on every later fold — see
    // §13.1a.1. Without the pin the genesis is trust-on-first-FOLD rather than
    // trust-on-first-use, and the window re-opens on every recompute.
    public DagState recompute_pinned(AikResolver resolver, string? pinned_owner_fp) {
        var st = new DagState();
        var order = canonical_order();
        var removal_node = new Gee.HashMap<string, string>();
        // The genesis is the first entry that actually AUTHENTICATES (and matches the
        // pin), NOT whatever sorts first. Keying it off the raw index made the genesis
        // slot consumable: one entry that sorts first and fails to verify — which costs
        // an attacker nothing to produce, since an unresolvable signer suffices — left
        // the room permanently ownerless, after which every later entry (including the
        // real genesis) folded as unauthorized against an empty admin set. That is a
        // durable, remotely triggerable denial of service on the group.
        bool genesis_established = false;
        for (int i = 0; i < order.size; i++) {
            JournalEntryV2 e = order.get(i);
            string signer_hex = hex_of(e.signer_fp);
            Bytes ed, ml;
            if (!resolver(signer_hex, out ed, out ml)) continue;
            try {
                if (!e.verify(ed, ml)) continue;
            } catch (GLib.Error err) { continue; }

            if (!genesis_established) {
                // A genesis must be a root: an entry descending from another entry
                // cannot be the start of the room's history.
                if (e.parents.size != 0) continue;
                // A first-in-canonical-order Snapshot is a virtual genesis
                // (v1->v2 bridge / MAM-prune-proof catch-up): TOFU-pin owner_fp
                // and import its asserted member/admin/banned sets. The snapshot
                // signer MUST be an asserted admin of the set it declares.
                if (e.action == (uint8) MemberAuditActionV2.SNAPSHOT) {
                    SnapshotPayload? sp = JournalEntryV2.parse_snapshot_payload(e.payload);
                    if (sp == null) continue;
                    string owner_hex = hex_of(sp.owner_fp);
                    // The asserted owner is payload data the signer chose, so it is
                    // exactly as attacker-controlled as the signer field. Only the pin
                    // constrains it.
                    if (pinned_owner_fp != null && pinned_owner_fp.down() != owner_hex.down()) continue;
                    var imp_members = new Gee.HashSet<string>();
                    var imp_admins = new Gee.HashSet<string>();
                    for (int mi = 0; mi < sp.member_fps.size; mi++) {
                        string mh = hex_of(sp.member_fps.get(mi).get_data());
                        imp_members.add(mh);
                        if (sp.member_is_admin.get(mi)) imp_admins.add(mh);
                    }
                    imp_members.add(owner_hex);
                    imp_admins.add(owner_hex);
                    // Reject a snapshot whose signer is not an admin it declares.
                    if (!imp_admins.contains(signer_hex)) continue;
                    st.owner_fp = owner_hex;
                    foreach (string mh in imp_members) st.members.add(mh);
                    foreach (string ah in imp_admins) st.admins.add(ah);
                    for (int bi = 0; bi < sp.banned_fps.size; bi++) {
                        string bh = hex_of(sp.banned_fps.get(bi).get_data());
                        st.banned.add(bh);
                        st.removed.set(bh, sp.banned_epochs.get(bi));
                    }
                    st.epoch = (uint32) sp.epoch;
                    genesis_established = true;
                    continue;
                }
                // A plain genesis: the signer becomes owner. The AIK resolver is seeded
                // from the whole local key cache — every contact whose bundle we ever
                // fetched, not just room members — so without the pin ANY known contact
                // could author a root entry, have any member relay it (§13.1a permits
                // relay by anyone), and sort it ahead of the real genesis by choosing
                // its own lamport/signer_fp/hash. On the next fold that stranger is
                // owner: permanent admin, irremovable, undemotable.
                if (pinned_owner_fp != null && pinned_owner_fp.down() != signer_hex.down()) continue;
                st.owner_fp = signer_hex;
                st.admins.add(signer_hex);
                st.members.add(signer_hex);
                st.epoch = 0;
                genesis_established = true;
                continue;
            }
            if (!st.admins.contains(signer_hex)) continue;

            /* §13.5: the epoch is a MONOTONE COUNT of accepted rotation-causing entries —
             * never the entry's index in the canonical order.
             *
             * Canonical order breaks ties among concurrent entries on
             * (lamport, signer_fp, entry_hash), so indices are not prefix-stable: a client
             * holding only B (parent G) folds it at index 1, and when a concurrent A that
             * sorts ahead of B arrives, B's index silently becomes 2. Deriving a live
             * encryption epoch from a rank a later-arriving sibling can renumber means a
             * sender can be asked to rotate to an epoch number it already used for a
             * different chain, which install-once-per-epoch (§13.4a.2) then discards —
             * making those messages permanently undecryptable. Counting accepted rotations
             * only ever moves forward as the DAG grows.
             *
             * The count advances for every AUTHORIZED rotation-causing entry, including one
             * whose effect the fail-closed re-admission rules suppress, so that the epoch
             * never depends on subtle re-admission outcomes. Unauthorized entries are
             * skipped above and never count. */
            uint8[] subject;
            JournalEntryV2.parse_subject_fp(e.payload, out subject);
            string subj_hex = (e.payload.length >= 20) ? hex_of(subject) : "";

            if (is_rotation_causing(e.action)) {
                st.epoch = st.epoch + 1;
            }

            switch (e.action) {
                case (uint8) MemberAuditActionV2.ADD_MEMBER:
                    if (subj_hex == st.owner_fp) break;
                    if (can_readd(st, removal_node, subj_hex, e)) {
                        st.members.add(subj_hex);
                        st.removed.unset(subj_hex);
                    }
                    break;
                case (uint8) MemberAuditActionV2.ADD_ADMIN:
                    if (can_readd(st, removal_node, subj_hex, e)) {
                        st.members.add(subj_hex);
                        st.admins.add(subj_hex);
                        st.removed.unset(subj_hex);
                    }
                    break;
                case (uint8) MemberAuditActionV2.REMOVE_MEMBER:
                    if (subj_hex == st.owner_fp) break;
                    st.members.remove(subj_hex);
                    st.admins.remove(subj_hex);
                    st.removed.set(subj_hex, st.epoch);
                    removal_node.set(subj_hex, e.hash_hex());
                    if (JournalEntryV2.payload_is_ban(e.payload)) st.banned.add(subj_hex);
                    break;
                case (uint8) MemberAuditActionV2.REMOVE_ADMIN:
                    if (subj_hex == st.owner_fp) break;
                    st.admins.remove(subj_hex);
                    break;
                case (uint8) MemberAuditActionV2.SNAPSHOT:
                    break;
            }
        }
        return st;
    }
    /* §13.5 rotation triggers. Genesis establishes epoch 0 and does not rotate; a Snapshot
     * is a passive checkpoint and does not rotate on its own. */
    private static bool is_rotation_causing(uint8 action) {
        return action == (uint8) MemberAuditActionV2.ADD_MEMBER
            || action == (uint8) MemberAuditActionV2.REMOVE_MEMBER
            || action == (uint8) MemberAuditActionV2.ADD_ADMIN
            || action == (uint8) MemberAuditActionV2.REMOVE_ADMIN;
    }


    private bool can_readd(DagState st, Gee.HashMap<string, string> removal_node, string fp_hex, JournalEntryV2 add_entry) {
        if (st.banned.contains(fp_hex)) return false;
        if (!st.removed.has_key(fp_hex)) return true;
        string? rn = removal_node.get(fp_hex);
        if (rn == null) return true;
        return is_ancestor(rn, add_entry);
    }

    private bool is_ancestor(string ancestor_hex, JournalEntryV2 descendant) {
        var seen = new Gee.HashSet<string>();
        var stack = new Gee.ArrayList<string>();
        foreach (Bytes p in descendant.parents) stack.add(hex_of(p.get_data()));
        while (stack.size > 0) {
            string h = stack.remove_at(stack.size - 1);
            if (h == ancestor_hex) return true;
            if (seen.contains(h)) continue;
            seen.add(h);
            JournalEntryV2? pe = store.get(h);
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
