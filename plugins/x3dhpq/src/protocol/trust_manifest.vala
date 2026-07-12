// x3dhpq Trust Manifest (Phase 1 core).
//
// The Trust Manifest is the account's authorized-device set expressed as an
// AIK-rooted, append-only hash-DAG of delegation entries, published as a single
// signed blob (the manifest head) that embeds all of its entries. Unlike the
// device-audit DAG (device_dag.vala) — where every writer shares the account AIK
// and each entry is authorized directly under that AIK — the Trust Manifest is a
// DELEGATION graph: the genesis device is authorized under the AIK, and every
// later entry is authorized under the DIK of an already-trusted AUTHOR device
// (author_device_id + author_dc_hash bind the authoring device's certificate).
//
// This file is byte-identical to the Java x3dhpq-core TrustEntry/TrustManifest.
// It follows the DeviceAuditEntryV2 conventions exactly: big-endian everywhere,
// domain prefixes are raw byte arrays that INCLUDE a trailing 0x00, hybrid sigs
// are appended as (uint16 len | sig) with Ed25519 first then ML-DSA-65, and
// entry_hash = SHA-256(marshal). See trust-manifest-canonical.md.
//
// TrustEntry.signed_part layout (big-endian):
//   "X3DHPQ-TrustEntry-v1\0" (21)
//   action             uint8            1 = ADD, 2 = REMOVE
//   device_id          uint32           the SUBJECT device id
//   dc_len             uint16
//   dc_bytes           dc_len bytes     DeviceCertificate.marshal() of the subject
//   lamport            uint64
//   parent_count       uint32
//   parents[N]         32 bytes each    SHA-256(parent TrustEntry.marshal()), raw
//   author_device_id   uint32           the EDITOR device id (== device_id for genesis)
//   author_dc_hash     32 bytes         SHA-256(author's DeviceCertificate.marshal())
//   timestamp          uint64           unix seconds (int64 cast to uint64)
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl
//
// TrustManifest.signed_part layout (big-endian):
//   "X3DHPQ-TrustManifest-v1\0" (24)
//   version            uint64
//   prev_hash_len      uint32           ALWAYS 32
//   prev_hash          32 bytes         SHA-256(previous manifest.marshal()); zeros at genesis
//   aik_len            uint16
//   aik_bytes          aik_len bytes    AccountIdentityPub.marshal() (1987)
//   entry_count        uint32
//   entries            { uint32 entry_len | TrustEntry.marshal() } * entry_count
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public class TrustEntry : Object {
    public const uint8 ACTION_ADD = 1;
    public const uint8 ACTION_REMOVE = 2;

    public uint8 action { get; set; }
    public uint32 device_id { get; set; }                 // subject
    public DeviceCertificate dc { get; set; }             // subject certificate
    public uint64 lamport { get; set; }
    public Gee.ArrayList<Bytes> parents { get; set; default = new Gee.ArrayList<Bytes>(); } // each 32 bytes
    public uint32 author_device_id { get; set; }          // editor
    public uint8[] author_dc_hash { get; set; }           // 32 bytes
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }
    public uint8[] mldsa_signature { get; set; }

    // "X3DHPQ-TrustEntry-v1\0" — 21 bytes, trailing NUL INCLUDED. Built as a raw
    // byte literal (NOT from a Vala string, which would drop the trailing 0x00).
    private static uint8[] v1_prefix() {
        return { 'X','3','D','H','P','Q','-','T','r','u','s','t','E','n','t','r','y','-','v','1', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v1_prefix();
        uint8[] dc_bytes = dc.marshal();
        int size = PREFIX.length + 1 + 4 + 2 + dc_bytes.length + 8 + 4 + parents.size * 32 + 4 + 32 + 8;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        buf[off++] = action;
        put_u32(buf, ref off, device_id);
        put_u16(buf, ref off, (uint16) dc_bytes.length);
        if (dc_bytes.length > 0) {
            Memory.copy((uint8*) buf + off, dc_bytes, dc_bytes.length);
            off += dc_bytes.length;
        }
        put_u64(buf, ref off, lamport);
        put_u32(buf, ref off, (uint32) parents.size);
        foreach (Bytes p in parents) {
            Memory.copy((uint8*) buf + off, p.get_data(), 32);
            off += 32;
        }
        put_u32(buf, ref off, author_device_id);
        Memory.copy((uint8*) buf + off, author_dc_hash, 32);
        off += 32;
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

    public static bool is_v1(uint8[] b) {
        uint8[] PREFIX = v1_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static TrustEntry? unmarshal(uint8[] b) {
        uint8[] PREFIX = v1_prefix();
        int min = PREFIX.length + 1 + 4 + 2 + 8 + 4 + 4 + 32 + 8 + 2 + 2;
        if (b.length < min) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) if (b[off + i] != PREFIX[i]) return null;
        off += PREFIX.length;

        TrustEntry e = new TrustEntry();
        e.action = b[off++];
        e.device_id = get_u32(b, ref off);

        if (off + 2 > b.length) return null;
        int dc_len = (int) get_u16(b, ref off);
        if ((int64) off + (int64) dc_len > (int64) b.length) return null;
        uint8[] dc_bytes = new uint8[dc_len];
        if (dc_len > 0) Memory.copy(dc_bytes, (uint8*) b + off, dc_len);
        off += dc_len;
        DeviceCertificate? dc = DeviceCertificate.unmarshal(new Bytes(dc_bytes));
        if (dc == null) return null;
        e.dc = dc;

        if (off + 8 + 4 > b.length) return null;
        e.lamport = get_u64(b, ref off);
        int64 pc64 = (int64) get_u32(b, ref off);
        if (pc64 < 0 || pc64 > 4096) return null;
        int pc = (int) pc64;
        if ((int64) off + (int64) pc * 32 + 4 + 32 + 8 + 2 + 2 > (int64) b.length) return null;
        e.parents = new Gee.ArrayList<Bytes>();
        for (int i = 0; i < pc; i++) {
            uint8[] p = new uint8[32];
            Memory.copy(p, (uint8*) b + off, 32);
            off += 32;
            e.parents.add(new Bytes(p));
        }
        e.author_device_id = get_u32(b, ref off);
        e.author_dc_hash = new uint8[32];
        Memory.copy(e.author_dc_hash, (uint8*) b + off, 32);
        off += 32;
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
        return e;
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

public class TrustManifest : Object {
    public AccountIdentityPub aik { get; set; }
    public Gee.ArrayList<TrustEntry> entries { get; set; default = new Gee.ArrayList<TrustEntry>(); }
    public uint64 version { get; set; }
    public uint8[] prev_hash { get; set; default = new uint8[32]; }  // 32 bytes, zeros at genesis
    public uint8[] signature { get; set; default = new uint8[0]; }
    public uint8[] mldsa_signature { get; set; default = new uint8[0]; }

    // "X3DHPQ-TrustManifest-v1\0" — 24 bytes, trailing NUL INCLUDED.
    private static uint8[] v1_prefix() {
        return { 'X','3','D','H','P','Q','-','T','r','u','s','t','M','a','n','i','f','e','s','t','-','v','1', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v1_prefix();
        uint8[] aik_bytes = aik.marshal();
        int ph_len = prev_hash.length;

        // Pre-marshal each entry once (entry_len + bytes).
        var entry_blobs = new Gee.ArrayList<Bytes>();
        int entries_total = 0;
        for (int i = 0; i < entries.size; i++) {
            Bytes eb = new Bytes(entries.get(i).marshal());
            entry_blobs.add(eb);
            entries_total += 4 + eb.length;
        }

        int size = PREFIX.length + 8 + 4 + ph_len + 2 + aik_bytes.length + 4 + entries_total;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, version);
        put_u32(buf, ref off, (uint32) ph_len);
        if (ph_len > 0) {
            Memory.copy((uint8*) buf + off, prev_hash, ph_len);
            off += ph_len;
        }
        put_u16(buf, ref off, (uint16) aik_bytes.length);
        if (aik_bytes.length > 0) {
            Memory.copy((uint8*) buf + off, aik_bytes, aik_bytes.length);
            off += aik_bytes.length;
        }
        put_u32(buf, ref off, (uint32) entries.size);
        for (int i = 0; i < entry_blobs.size; i++) {
            Bytes eb = entry_blobs.get(i);
            int el = (int) eb.length;
            put_u32(buf, ref off, (uint32) el);
            if (el > 0) {
                Memory.copy((uint8*) buf + off, eb.get_data(), el);
                off += el;
            }
        }
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

    // §B: sign the manifest HEAD (signed_part) with the PUBLISHING device's DIK.
    // Both hybrid halves are set; the signer must be a device present in the fold
    // (verified separately by verify_head at the receiver). The signed input is
    // the Phase-1 KAT-locked signed_part, so this is interop-stable.
    public void sign_head(Bytes dik_priv_ed, Bytes dik_priv_mldsa) throws GLib.Error {
        uint8[] sp = signed_part();
        signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(dik_priv_ed, new Bytes(sp)));
        mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(dik_priv_mldsa, new Bytes(sp)));
    }

    // §B: verify the head signature under a candidate device's DIK public halves.
    // BOTH Ed25519 and ML-DSA-65 must verify over signed_part(). Never throws.
    public bool verify_head(Bytes dik_pub_ed, Bytes dik_pub_mldsa) {
        if (signature.length == 0 || mldsa_signature.length == 0) return false;
        try {
            uint8[] sp = signed_part();
            if (!global::X3dhpq.Crypto.ed25519_verify(dik_pub_ed, new Bytes(sp), new Bytes(signature))) return false;
            return global::X3dhpq.Crypto.mldsa65_verify(dik_pub_mldsa, new Bytes(sp), new Bytes(mldsa_signature));
        } catch (GLib.Error e) {
            return false;
        }
    }

    public static bool is_v1(uint8[] b) {
        uint8[] PREFIX = v1_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static TrustManifest? unmarshal(uint8[] b) {
        uint8[] PREFIX = v1_prefix();
        int min = PREFIX.length + 8 + 4 + 2 + 4 + 2 + 2;
        if (b.length < min) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) if (b[off + i] != PREFIX[i]) return null;
        off += PREFIX.length;

        TrustManifest m = new TrustManifest();
        m.version = get_u64(b, ref off);
        int64 ph64 = (int64) get_u32(b, ref off);
        if (ph64 < 0 || ph64 > 4096) return null;
        int ph_len = (int) ph64;
        if ((int64) off + (int64) ph_len + 2 > (int64) b.length) return null;
        m.prev_hash = new uint8[ph_len];
        if (ph_len > 0) Memory.copy(m.prev_hash, (uint8*) b + off, ph_len);
        off += ph_len;

        int aik_len = (int) get_u16(b, ref off);
        if ((int64) off + (int64) aik_len + 4 > (int64) b.length) return null;
        uint8[] aik_bytes = new uint8[aik_len];
        if (aik_len > 0) Memory.copy(aik_bytes, (uint8*) b + off, aik_len);
        off += aik_len;
        AccountIdentityPub? aik = AccountIdentityPub.unmarshal(aik_bytes);
        if (aik == null) return null;
        m.aik = aik;

        int64 ec64 = (int64) get_u32(b, ref off);
        if (ec64 < 0 || ec64 > 1000000) return null;
        int ec = (int) ec64;
        m.entries = new Gee.ArrayList<TrustEntry>();
        for (int i = 0; i < ec; i++) {
            if (off + 4 > b.length) return null;
            int64 el64 = (int64) get_u32(b, ref off);
            if (el64 < 0 || (int64) off + el64 > (int64) b.length) return null;
            int el = (int) el64;
            uint8[] eb = new uint8[el];
            if (el > 0) Memory.copy(eb, (uint8*) b + off, el);
            off += el;
            TrustEntry? te = TrustEntry.unmarshal(eb);
            if (te == null) return null;
            m.entries.add(te);
        }

        if (off + 2 > b.length) return null;
        int sl = (int) get_u16(b, ref off);
        if (off + sl + 2 > b.length) return null;
        m.signature = new uint8[sl];
        if (sl > 0) Memory.copy(m.signature, (uint8*) b + off, sl);
        off += sl;
        int ml = (int) get_u16(b, ref off);
        if (off + ml > b.length) return null;
        m.mldsa_signature = new uint8[ml];
        if (ml > 0) Memory.copy(m.mldsa_signature, (uint8*) b + off, ml);
        return m;
    }

    // -------------------------------------------------------------------------
    // Fold / walk: derive trusted \ removed = { device_id -> DeviceCertificate }.
    // Mirrors DeviceDag.canonical_order + fold, with the DELEGATION authorization
    // rule (author must be already trusted; entry verifies under the author's DIK).
    // Keyed by device_id's base-10 string form (Gee generics prefer string keys).
    // -------------------------------------------------------------------------

    public Gee.HashMap<string, DeviceCertificate> fold() {
        var trusted = new Gee.HashMap<string, DeviceCertificate>();
        var removed = new Gee.HashSet<string>();
        var removal_node = new Gee.HashMap<string, string>();   // device_id_str -> removal entry hash

        // Build store: entry_hash_hex -> entry.
        var store = new Gee.HashMap<string, TrustEntry>();
        foreach (TrustEntry e in entries) {
            store.set(e.hash_hex(), e);
        }

        var order = canonical_order(store);
        if (order.size == 0) return trusted;

        for (int i = 0; i < order.size; i++) {
            TrustEntry e = order.get(i);
            string subject_key = e.device_id.to_string();
            string author_key = e.author_device_id.to_string();

            if (i == 0) {
                // Genesis: ADD, no parents, author==subject, sig+dc verify under AIK.
                if (e.action != TrustEntry.ACTION_ADD) return trusted;
                if (e.parents.size != 0) return trusted;
                if (e.author_device_id != e.device_id) return trusted;
                if (e.dc.device_id != e.device_id) return trusted;
                if (!verify_entry_sig(e, new Bytes(aik.pub_ed25519), new Bytes(aik.pub_mldsa))) return trusted;
                bool dc_ok;
                try {
                    dc_ok = e.dc.verify(new Bytes(aik.pub_ed25519), new Bytes(aik.pub_mldsa));
                } catch (GLib.Error err) { return trusted; }
                if (!dc_ok) return trusted;
                trusted.set(subject_key, e.dc);
                continue;
            }

            // Later entry: authorized under the author device's (trusted) DIK.
            if (!trusted.has_key(author_key) || removed.contains(author_key)) continue;
            DeviceCertificate author_dc = trusted.get(author_key);

            uint8[] expected_author_hash;
            try {
                expected_author_hash = bytes_to_uint8_array(
                    global::X3dhpq.Crypto.sha256(new Bytes(author_dc.marshal())));
            } catch (GLib.Error err) { continue; }
            if (!byte_eq(e.author_dc_hash, expected_author_hash)) continue;

            if (!verify_entry_sig(e, author_dc.dik_pub_ed25519, author_dc.dik_pub_mldsa)) continue;
            if (e.dc.device_id != e.device_id) continue;

            switch (e.action) {
                case TrustEntry.ACTION_ADD:
                    if (!can_readd(removed, removal_node, store, subject_key, e)) break;
                    trusted.set(subject_key, e.dc);
                    removed.remove(subject_key);
                    break;
                case TrustEntry.ACTION_REMOVE:
                    trusted.unset(subject_key);
                    removed.add(subject_key);
                    removal_node.set(subject_key, e.hash_hex());
                    break;
            }
        }

        // Result already excludes removed device_ids (unset on REMOVE / not re-added).
        return trusted;
    }

    private bool verify_entry_sig(TrustEntry e, Bytes ed_pub, Bytes ml_pub) {
        if (e.signature.length == 0 || e.mldsa_signature.length == 0) return false;
        try {
            uint8[] sp = e.signed_part();
            if (!global::X3dhpq.Crypto.ed25519_verify(ed_pub, new Bytes(sp), new Bytes(e.signature))) return false;
            return global::X3dhpq.Crypto.mldsa65_verify(ml_pub, new Bytes(sp), new Bytes(e.mldsa_signature));
        } catch (GLib.Error err) {
            return false;
        }
    }

    private Gee.ArrayList<TrustEntry> canonical_order(Gee.HashMap<string, TrustEntry> store) {
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
            TrustEntry e = store.get(h);
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
        var order = new Gee.ArrayList<TrustEntry>();
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

    // cmp_key: (1) lamport ascending unsigned; (2) author_device_id ascending
    // unsigned 32-bit; (3) lowercase-hex(entry_hash) strcmp.
    private static int cmp_key(TrustEntry a, TrustEntry b) {
        if (a.lamport != b.lamport) return a.lamport < b.lamport ? -1 : 1;
        if (a.author_device_id != b.author_device_id) return a.author_device_id < b.author_device_id ? -1 : 1;
        return strcmp(a.hash_hex(), b.hash_hex());
    }

    private bool can_readd(Gee.HashSet<string> removed, Gee.HashMap<string, string> removal_node,
                           Gee.HashMap<string, TrustEntry> store, string idk, TrustEntry add_entry) {
        if (!removed.contains(idk)) return true;
        string? rn = removal_node.get(idk);
        if (rn == null) return true;
        return is_ancestor(store, rn, add_entry);
    }

    private bool is_ancestor(Gee.HashMap<string, TrustEntry> store, string ancestor_hex, TrustEntry descendant) {
        var seen = new Gee.HashSet<string>();
        var stack = new Gee.ArrayList<string>();
        foreach (Bytes p in descendant.parents) stack.add(hex_of(p.get_data()));
        while (stack.size > 0) {
            string h = stack.remove_at(stack.size - 1);
            if (h == ancestor_hex) return true;
            if (seen.contains(h)) continue;
            seen.add(h);
            TrustEntry? pe = store.get(h);
            if (pe != null) foreach (Bytes pp in pe.parents) stack.add(hex_of(pp.get_data()));
        }
        return false;
    }

    // Heads of the current DAG (entries with no present child) — the parents for
    // the next authored entry. Returns raw 32-byte SHA-256(marshal) hashes.
    public Gee.ArrayList<Bytes> current_heads() {
        var has_child = new Gee.HashSet<string>();
        var by_hash = new Gee.HashMap<string, TrustEntry>();
        foreach (TrustEntry e in entries) by_hash.set(e.hash_hex(), e);
        foreach (TrustEntry e in entries) {
            foreach (Bytes p in e.parents) has_child.add(hex_of(p.get_data()));
        }
        var heads = new Gee.ArrayList<Bytes>();
        foreach (var en in by_hash.entries) {
            if (!has_child.contains(en.key)) heads.add(new Bytes(en.value.compute_hash()));
        }
        return heads;
    }

    public uint64 next_lamport() {
        uint64 m = 0;
        foreach (TrustEntry e in entries) if (e.lamport > m) m = e.lamport;
        return entries.size == 0 ? 0 : m + 1;
    }

    private static bool byte_eq(uint8[] a, uint8[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
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

}
