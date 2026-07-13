// x3dhpq Trust Manifest (wire v2 — compact snapshot model, SHA-512).
//
// The Trust Manifest is the account's authorized-device set expressed as a
// COMPACT SNAPSHOT of current members, published as a single signed blob (the
// manifest head) that embeds all of its entries. The genesis device is
// authorized under the account AIK; every other member entry is authored (and
// signed) by the genesis/publisher device's DIK (author_device_id +
// author_dc_hash bind the authoring device's certificate).
//
// This file is byte-identical to the Java x3dhpq-core TrustEntry/TrustManifest.
// Conventions: big-endian everywhere, domain prefixes are raw byte arrays that
// INCLUDE a trailing 0x00, hybrid sigs are appended as (uint16 len | sig) with
// Ed25519 first then ML-DSA-65. ALL hashes are SHA-512 (author_dc_hash,
// prev_hash, entry_hash, manifest_hash). See trust-manifest-v2-canonical.md.
//
// v2 changes from v1: domain prefixes bump to v2; SHA-256 → SHA-512 (all 64-byte
// hashes); the DAG fields (lamport u64, parent_count u32, parents[32]*) are
// DROPPED from TrustEntry; fold is a simple snapshot walk (genesis first, then
// ADD entries by ascending device_id), no topo-sort, no REMOVE/removal-wins.
//
// TrustEntry.signed_part layout (big-endian):
//   "X3DHPQ-TrustEntry-v2\0" (21)
//   action             uint8            1 = ADD (REMOVE unused in the snapshot model)
//   device_id          uint32           the SUBJECT device id
//   dc_len             uint16
//   dc_bytes           dc_len bytes     DeviceCertificate.marshal() of the subject
//   author_device_id   uint32           the AUTHOR device id (== device_id for genesis)
//   author_dc_hash     64 bytes         SHA-512(author's DeviceCertificate.marshal())
//   timestamp          uint64           unix seconds (int64 cast to uint64)
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl
//
// TrustManifest.signed_part layout (big-endian):
//   "X3DHPQ-TrustManifest-v2\0" (24)
//   version            uint64
//   prev_hash_len      uint32           ALWAYS 64
//   prev_hash          64 bytes         SHA-512(previous manifest.marshal()); zeros at genesis
//   aik_len            uint16
//   aik_bytes          aik_len bytes    AccountIdentityPub.marshal() (1987)
//   entry_count        uint32
//   entries            { uint32 entry_len | TrustEntry.marshal() } * entry_count
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public class TrustEntry : Object {
    public const uint8 ACTION_ADD = 1;
    public const uint8 ACTION_REMOVE = 2;   // reserved / unused in the snapshot model

    public uint8 action { get; set; }
    public uint32 device_id { get; set; }                 // subject
    public DeviceCertificate dc { get; set; }             // subject certificate
    public uint32 author_device_id { get; set; }          // author (== device_id for genesis)
    public uint8[] author_dc_hash { get; set; }           // 64 bytes (SHA-512)
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }
    public uint8[] mldsa_signature { get; set; }

    // "X3DHPQ-TrustEntry-v2\0" — 21 bytes, trailing NUL INCLUDED. Built as a raw
    // byte literal (NOT from a Vala string, which would drop the trailing 0x00).
    private static uint8[] v2_prefix() {
        return { 'X','3','D','H','P','Q','-','T','r','u','s','t','E','n','t','r','y','-','v','2', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v2_prefix();
        uint8[] dc_bytes = dc.marshal();
        int size = PREFIX.length + 1 + 4 + 2 + dc_bytes.length + 4 + 64 + 8;
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
        put_u32(buf, ref off, author_device_id);
        Memory.copy((uint8*) buf + off, author_dc_hash, 64);
        off += 64;
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
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha512(new Bytes(marshal())));
        } catch (GLib.Error e) {
            return new uint8[64];
        }
    }

    public string hash_hex() {
        return hex_of(compute_hash());
    }

    public static bool is_v2(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static TrustEntry? unmarshal(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        int min = PREFIX.length + 1 + 4 + 2 + 4 + 64 + 8 + 2 + 2;
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

        if ((int64) off + 4 + 64 + 8 + 2 + 2 > (int64) b.length) return null;
        e.author_device_id = get_u32(b, ref off);
        e.author_dc_hash = new uint8[64];
        Memory.copy(e.author_dc_hash, (uint8*) b + off, 64);
        off += 64;
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
    public uint8[] prev_hash { get; set; default = new uint8[64]; }  // 64 bytes (SHA-512), zeros at genesis
    public uint8[] signature { get; set; default = new uint8[0]; }
    public uint8[] mldsa_signature { get; set; default = new uint8[0]; }

    // "X3DHPQ-TrustManifest-v2\0" — 24 bytes, trailing NUL INCLUDED.
    private static uint8[] v2_prefix() {
        return { 'X','3','D','H','P','Q','-','T','r','u','s','t','M','a','n','i','f','e','s','t','-','v','2', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v2_prefix();
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
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha512(new Bytes(marshal())));
        } catch (GLib.Error e) {
            return new uint8[64];
        }
    }

    public string hash_hex() {
        return hex_of(compute_hash());
    }

    // Sign the manifest HEAD (signed_part) with the PUBLISHING device's DIK. Both
    // hybrid halves are set; the signer must be a device present in the fold
    // (verified separately by verify_head at the receiver).
    public void sign_head(Bytes dik_priv_ed, Bytes dik_priv_mldsa) throws GLib.Error {
        uint8[] sp = signed_part();
        signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(dik_priv_ed, new Bytes(sp)));
        mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(dik_priv_mldsa, new Bytes(sp)));
    }

    // Verify the head signature under a candidate device's DIK public halves.
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

    public static bool is_v2(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static TrustManifest? unmarshal(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
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
    // Fold (v2, snapshot): derive trusted = { device_id -> DeviceCertificate }.
    //  1. Identify the GENESIS entry (self-authored ADD whose entry sig AND
    //     embedded DC both verify under the account AIK). Exactly one expected;
    //     none valid ⇒ empty fold (reject).
    //  2. Accept remaining ADD entries, ordered by ascending device_id, whose
    //     author is the genesis device, author_dc_hash == SHA-512(genesis DC),
    //     the entry sig verifies under the genesis DC's DIK, and dc.device_id ==
    //     device_id. A bad entry is dropped (that one), never fatal.
    // No lamport/parents/topo-sort, no REMOVE/removal-wins: a revoked device is
    // simply absent from the snapshot.
    // Keyed by device_id's base-10 string form (Gee generics prefer string keys).
    // -------------------------------------------------------------------------

    public Gee.HashMap<string, DeviceCertificate> fold() {
        var trusted = new Gee.HashMap<string, DeviceCertificate>();
        if (aik == null) return trusted;

        // 1. Identify the genesis entry (first valid one in list order).
        TrustEntry? genesis = null;
        foreach (TrustEntry e in entries) {
            if (e.action != TrustEntry.ACTION_ADD) continue;
            if (e.author_device_id != e.device_id) continue;
            if (e.dc.device_id != e.device_id) continue;
            if (!verify_entry_sig(e, new Bytes(aik.pub_ed25519), new Bytes(aik.pub_mldsa))) continue;
            bool dc_ok;
            try {
                dc_ok = e.dc.verify(new Bytes(aik.pub_ed25519), new Bytes(aik.pub_mldsa));
            } catch (GLib.Error err) { continue; }
            if (!dc_ok) continue;
            genesis = e;
            break;
        }
        if (genesis == null) return trusted;
        TrustEntry g = (!) genesis;
        uint32 genesis_id = g.device_id;
        trusted.set(genesis_id.to_string(), g.dc);

        uint8[] genesis_dc_hash;
        try {
            genesis_dc_hash = bytes_to_uint8_array(global::X3dhpq.Crypto.sha512(new Bytes(g.dc.marshal())));
        } catch (GLib.Error err) { return trusted; }

        // 2. Remaining entries ordered by ascending (unsigned) device_id.
        var rest = new Gee.ArrayList<TrustEntry>();
        foreach (TrustEntry e in entries) {
            if (e == g) continue;
            rest.add(e);
        }
        rest.sort((a, b) => (a.device_id < b.device_id) ? -1 : (a.device_id > b.device_id ? 1 : 0));
        foreach (TrustEntry e in rest) {
            if (e.action != TrustEntry.ACTION_ADD) continue;
            if (e.author_device_id != genesis_id) continue;
            if (e.dc.device_id != e.device_id) continue;
            if (!byte_eq(e.author_dc_hash, genesis_dc_hash)) continue;
            if (!verify_entry_sig(e, g.dc.dik_pub_ed25519, g.dc.dik_pub_mldsa)) continue;
            trusted.set(e.device_id.to_string(), e.dc);
        }
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
