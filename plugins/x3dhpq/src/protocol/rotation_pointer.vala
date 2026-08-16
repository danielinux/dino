// SPDX-License-Identifier: AGPL-3.0-or-later
//
// §12.3 AIK retirement pointer: a statement, signed by the OLD AIK, that it has been
// retired in favour of a new one.
//
// NOT a continuity mechanism. §12.2 refuses cryptographic continuity as a basis for
// GRANTING trust and that is unchanged here: a valid pointer retires `old_aik` and
// never authorises `new_aik`, which is adopted only by out-of-band re-verification.
// The asymmetry is what makes honouring it automatically safe — an attacker holding
// the stolen old private key can only retire a key they already control, which is not
// an escalation because they can already do everything that key permits.
//
// Wire layout (big-endian, byte-identical to PQonversations' RotationPointer.java and
// to Go's aik_rotation.go):
//
//   "X3DHPQ-Rotation-v1\x00" (19)
//   uint16 version
//   uint16 old_aik_len | old_aik      (AccountIdentityPub.marshal(), §7.2)
//   uint16 new_aik_len | new_aik      (AccountIdentityPub.marshal(), §7.2)
//   int64  rotated_at                 (unix seconds)
//   uint16 reason_len  | reason       (UTF-8, MAX 512 bytes)
//                                     ── end of signed_part ──
//   uint16 sig_ed_len    | sig_ed25519    (over signed_part, by the OLD AIK)
//   uint16 sig_mldsa_len | sig_mldsa65    (over signed_part, by the OLD AIK)

namespace Dino.Plugins.X3dhpq.Protocol {

public class RotationPointer : Object {
    public const int MAX_REASON_BYTES = 512;

    public uint16 version { get; set; default = 1; }
    // Canonical AccountIdentityPub.marshal() bytes — NOT the bare Ed25519 half.
    public uint8[] old_aik { get; set; default = new uint8[0]; }
    public uint8[] new_aik { get; set; default = new uint8[0]; }
    public int64 rotated_at { get; set; default = 0; }
    public string reason { get; set; default = ""; }
    public uint8[] sig_ed25519 { get; set; default = new uint8[0]; }
    public uint8[] sig_mldsa { get; set; default = new uint8[0]; }

    private static uint8[] rotation_prefix() {
        return { 'X','3','D','H','P','Q','-','R','o','t','a','t','i','o','n','-','v','1', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = rotation_prefix();
        uint8[] reason_bytes = reason.data;
        int size = PREFIX.length + 2 + 2 + old_aik.length + 2 + new_aik.length + 8 + 2 + reason_bytes.length;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u16(buf, ref off, version);
        put_field(buf, ref off, old_aik);
        put_field(buf, ref off, new_aik);
        put_u64(buf, ref off, (uint64) rotated_at);
        put_field(buf, ref off, reason_bytes);
        return buf;
    }

    public uint8[] marshal() {
        uint8[] sp = signed_part();
        int size = sp.length + 2 + sig_ed25519.length + 2 + sig_mldsa.length;
        uint8[] buf = new uint8[size];
        Memory.copy(buf, sp, sp.length);
        int off = sp.length;
        put_field(buf, ref off, sig_ed25519);
        put_field(buf, ref off, sig_mldsa);
        return buf;
    }

    /* Strict parser: returns null on any malformation, including a declared length that
     * runs past the buffer. Callers treat null as "the evidence does not parse", which
     * for a §13.5c RetireMember makes the entry unauthorized. */
    public static RotationPointer? unmarshal(uint8[] b) {
        uint8[] PREFIX = rotation_prefix();
        if (b.length < PREFIX.length + 2) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) if (b[off + i] != PREFIX[i]) return null;
        off += PREFIX.length;

        RotationPointer p = new RotationPointer();
        p.version = get_u16(b, ref off);

        uint8[] old_bytes;
        if (!read_field(b, ref off, out old_bytes)) return null;
        uint8[] new_bytes;
        if (!read_field(b, ref off, out new_bytes)) return null;
        if (off + 8 > b.length) return null;
        p.old_aik = old_bytes;
        p.new_aik = new_bytes;
        p.rotated_at = (int64) get_u64(b, ref off);

        uint8[] reason_bytes;
        if (!read_field(b, ref off, out reason_bytes)) return null;
        if (reason_bytes.length > MAX_REASON_BYTES) return null;
        var sb = new StringBuilder();
        foreach (uint8 c in reason_bytes) sb.append_c((char) c);
        p.reason = sb.str;

        uint8[] sig_ed;
        if (!read_field(b, ref off, out sig_ed)) return null;
        uint8[] sig_ml;
        if (!read_field(b, ref off, out sig_ml)) return null;
        p.sig_ed25519 = sig_ed;
        p.sig_mldsa = sig_ml;
        return p;
    }

    /* §12.3 step 1 — verify BOTH signatures over signed_part against the supplied AIK
     * halves.
     *
     * The AIK is passed in rather than read out of `old_aik` because §13.5c wants the
     * pointer checked against the AIK the ROOM already holds for the member being
     * retired: a pointer that verifies only against a key it carries itself proves
     * nothing about who is being retired. The caller pairs this with the
     * fingerprint(old_aik) == retired_aik_fp check, and the two together are what bind
     * the evidence to that member.
     *
     * wolfSSL raises SIG_VERIFY_E rather than returning false on a bad signature, so a
     * forgery arrives as an exception; both shapes normalise to one plain rejection. */
    public bool verify_with(Bytes aik_ed_pub, Bytes aik_mldsa_pub) {
        if (sig_ed25519.length == 0 || sig_mldsa.length == 0) return false;
        uint8[] sp = signed_part();
        try {
            if (!global::X3dhpq.Crypto.ed25519_verify(aik_ed_pub, new Bytes(sp), new Bytes(sig_ed25519))) {
                return false;
            }
            return global::X3dhpq.Crypto.mldsa65_verify(aik_mldsa_pub, new Bytes(sp), new Bytes(sig_mldsa));
        } catch (GLib.Error e) {
            return false;
        }
    }

    /* Self-contained §12.3 verification: check the signatures against the AIK the
     * pointer itself names as retired. Sound only because the statement is negative —
     * see the class comment. §12.3 step 2 (the pointer's old_aik MUST be the AIK the
     * receiver currently has pinned for that owner) is the caller's job. */
    public bool verify() {
        AccountIdentityPub? old_pub = AccountIdentityPub.unmarshal(old_aik);
        if (old_pub == null) return false;
        return verify_with(new Bytes(((!) old_pub).pub_ed25519), new Bytes(((!) old_pub).pub_mldsa));
    }

    /* Raw BLAKE2b-160 of the canonical old_aik encoding (§5.4) — the same 20-byte form
     * the membership journal keys members by. Empty on failure. */
    public uint8[] old_aik_fp_raw() {
        return fp_of(old_aik);
    }

    public uint8[] new_aik_fp_raw() {
        return fp_of(new_aik);
    }

    private static uint8[] fp_of(uint8[] aik_marshaled) {
        if (aik_marshaled.length == 0) return new uint8[0];
        try {
            return bytes_to_uint8_array(global::X3dhpq.Crypto.blake2b160(new Bytes(aik_marshaled)));
        } catch (GLib.Error e) {
            return new uint8[0];
        }
    }

    private static void put_u16(uint8[] b, ref int off, uint16 v) {
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static void put_u64(uint8[] b, ref int off, uint64 v) {
        for (int i = 7; i >= 0; i--) b[off++] = (uint8)(v >> (i * 8));
    }
    private static void put_field(uint8[] b, ref int off, uint8[] v) {
        put_u16(b, ref off, (uint16) v.length);
        if (v.length > 0) {
            Memory.copy((uint8*) b + off, v, v.length);
            off += v.length;
        }
    }
    private static uint16 get_u16(uint8[] b, ref int off) {
        uint16 v = (uint16)((b[off] << 8) | b[off + 1]); off += 2; return v;
    }
    private static uint64 get_u64(uint8[] b, ref int off) {
        uint64 v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | b[off + i];
        off += 8; return v;
    }
    /* Read one uint16-length-prefixed field. Returns false — and leaves `v` empty — if
     * the declared length runs past the buffer.
     *
     * Success is signalled by the RETURN VALUE, not by a nullable array, and that is not
     * a style choice. A length-prefixed field here may legitimately be EMPTY: `reason` is
     * optional and both other clients leave it empty by default. Vala compiles
     * `new uint8[0]` to `g_malloc0(0)`, which glib returns as NULL, so an out-parameter
     * of type `uint8[]?` cannot distinguish "well-formed empty field" from "malformed".
     *
     * With the earlier nullable signature every RotationPointer carrying no reason string
     * was rejected as unparseable. That is not a cosmetic parse bug: §13.5c makes a
     * kind-1 RetireMember whose evidence does not parse UNAUTHORIZED, and authorized
     * versus unauthorized changes `fold_hash` (§13.5a) — so the peer that could parse the
     * pointer retired the identity, moved its epoch and rotated, while this client folded
     * a different member set at a different epoch_id and never converged again. Caught by
     * conformance/v2/journal-fold.json (`retire-member-kind1` and its three siblings),
     * whose committed pointers carry an empty reason. */
    private static bool read_field(uint8[] b, ref int off, out uint8[] v) {
        v = new uint8[0];
        if (off + 2 > b.length) return false;
        int len = (int) get_u16(b, ref off);
        if ((int64) off + (int64) len > (int64) b.length) return false;
        uint8[] r = new uint8[len];
        if (len > 0) Memory.copy(r, (uint8*) b + off, len);
        off += len;
        v = r;
        return true;
    }
}

}
