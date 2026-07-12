// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Dino.Plugins.X3dhpq.Protocol {

public errordomain CPaceError {
    BAD_MESSAGE,
    LOW_ORDER_POINT,
    INTERNAL
}

public enum CPaceRole {
    INITIATOR,
    RESPONDER
}

public struct CPaceContext {
    public string bare_jid;
    public string initiator_full_jid;
    public string responder_full_jid;
    public string server_domain;
    public uint8[] initiator_aik_pub;
    public uint8[] responder_aik_pub;
    public string purpose;
}

/* Low-order points for Curve25519, per RFC 7748 §7.
 * Stored flat: 7 points × 32 bytes = 224 bytes, concatenated. */
public class CPaceLowOrder : GLib.Object {

    /* 7 low-order points, concatenated, 32 bytes each */
    private const uint8[] LOW_ORDER_POINTS_FLAT = {
        /* point 0: all-zeros */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* point 1: one */
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* point 2 */
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
        0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
        0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
        /* point 3 */
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
        0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
        0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
        0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
        /* point 4 */
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        /* point 5 */
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        /* point 6 */
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };

    private const int NUM_LOW_ORDER_POINTS = 7;


    public static bool is_low_order(uint8[] pt) {
        if (pt.length != 32) {
            return false;
        }
        for (int i = 0; i < NUM_LOW_ORDER_POINTS; i++) {
            int off = i * 32;
            bool match = true;
            for (int j = 0; j < 32; j++) {
                if (pt[j] != LOW_ORDER_POINTS_FLAT[off + j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }
}

public class CPaceState : GLib.Object {

    private const string CPACE_DST = "X3DHPQ-CPace-v1";

    public CPaceRole role { get; private set; }
    public uint8[] sid { get; private set; }
    public uint8[] transcript { get; private set; }
    private uint8[] y_scalar;
    private uint8[] g;
    private uint8[] my_msg;

    private CPaceState() {}

    /* pack_field: uint16-BE length prefix followed by the field bytes */
    private static void pack_field(ref uint8[] buf, uint8[] field) {
        uint16 len = (uint16) field.length;
        int old_len = buf.length;
        buf.resize(old_len + 2 + field.length);
        buf[old_len]     = (uint8)(len >> 8);
        buf[old_len + 1] = (uint8)(len & 0xff);
        Memory.copy((uint8*) buf + old_len + 2, field, field.length);
    }

    private static uint8[] build_transcript(uint8[] password, uint8[] sid_bytes, CPaceContext ctx) {
        /* "X3DHPQ-CPace-Transcript-v1\x00" — the domain separator MUST include the
         * trailing NUL. Vala's `"...\x00".data` drops it (treats \x00 as the C
         * string terminator), so we append it explicitly to stay byte-identical
         * with the Go reference / Java (which pin a 27-byte prefix). */
        uint8[] hdr = "X3DHPQ-CPace-Transcript-v1".data;
        uint8[] t = new uint8[hdr.length + 1];
        Memory.copy(t, hdr, hdr.length);
        t[hdr.length] = 0x00;

        pack_field(ref t, ctx.bare_jid.data);
        pack_field(ref t, ctx.initiator_full_jid.data);
        pack_field(ref t, ctx.responder_full_jid.data);
        pack_field(ref t, ctx.server_domain.data);
        pack_field(ref t, ctx.initiator_aik_pub);
        pack_field(ref t, ctx.responder_aik_pub);
        /* 0x49 = 'I' initiator marker, 0x52 = 'R' responder marker */
        int pos = t.length;
        t.resize(pos + 2);
        t[pos]     = 0x49;
        t[pos + 1] = 0x52;
        pack_field(ref t, ctx.purpose.data);
        return t;
    }

    private static uint8[] build_h2c_input(uint8[] prs, uint8[] sid_bytes, uint8[] transcript_bytes) {
        uint8[] msg = new uint8[0];
        pack_field(ref msg, prs);
        pack_field(ref msg, sid_bytes);
        pack_field(ref msg, transcript_bytes);
        return msg;
    }

    public static CPaceState create(CPaceRole role, uint8[] password, uint8[] sid, CPaceContext ctx) throws GLib.Error {
        uint8[] t = build_transcript(password, sid, ctx);
        uint8[] h2c_input = build_h2c_input(password, sid, t);

        Bytes g_bytes = global::X3dhpq.Crypto.hash_to_curve_x25519(
            new Bytes(h2c_input),
            new Bytes(CPACE_DST.data)
        );

        var state = new CPaceState();
        state.role = role;
        state.sid = sid;
        state.transcript = t;
        state.g = g_bytes.get_data();
        return state;
    }

    /* message1: generate ephemeral scalar y, clamp per RFC 7748, compute Y = X25519(y, g) */
    public uint8[] message1() throws GLib.Error {
        Bytes rand = global::X3dhpq.Crypto.random_bytes(32);
        uint8[] y = rand.get_data();

        /* RFC 7748 clamping */
        y[0]  &= 248;
        y[31] &= 127;
        y[31] |= 64;

        /* Y = X25519(y, g) — x25519_shared_secret performs scalar multiplication */
        Bytes Y_bytes = global::X3dhpq.Crypto.x25519_shared_secret(
            new Bytes(y),
            new Bytes(g)
        );

        y_scalar = y;
        my_msg   = Y_bytes.get_data();
        return my_msg;
    }

    /* process: receive peer's Y point, derive session key */
    public uint8[] process(uint8[] peer_msg) throws CPaceError, GLib.Error {
        if (peer_msg.length != 32) {
            throw new CPaceError.BAD_MESSAGE("cpace: peer message must be 32 bytes");
        }
        if (CPaceLowOrder.is_low_order(peer_msg)) {
            throw new CPaceError.BAD_MESSAGE("cpace: peer sent a low-order point");
        }

        /* K = X25519(y_scalar, peer_msg) */
        Bytes K_bytes = global::X3dhpq.Crypto.x25519_shared_secret(
            new Bytes(y_scalar),
            new Bytes(peer_msg)
        );
        uint8[] K = K_bytes.get_data();

        /* ma = lexicographic minimum, mb = maximum */
        uint8[] ma = my_msg;
        uint8[] mb = peer_msg;
        if (compare_bytes(ma, mb) > 0) {
            uint8[] tmp = ma;
            ma = mb;
            mb = tmp;
        }

        /* thInput = "X3DHPQ-CPace-SessionTranscript-v1\x00" || pack(sid) || pack(transcript) || pack(ma) || pack(mb)
         * As in build_transcript, append the trailing NUL that Vala's string.data drops. */
        uint8[] th_hdr = "X3DHPQ-CPace-SessionTranscript-v1".data;
        uint8[] th_input = new uint8[th_hdr.length + 1];
        Memory.copy(th_input, th_hdr, th_hdr.length);
        th_input[th_hdr.length] = 0x00;
        pack_field(ref th_input, sid);
        pack_field(ref th_input, transcript);
        pack_field(ref th_input, ma);
        pack_field(ref th_input, mb);

        Bytes transcript_hash = global::X3dhpq.Crypto.sha512(new Bytes(th_input));
        uint8[] th = transcript_hash.get_data();

        /* ikm = K || transcript_hash */
        uint8[] ikm = new uint8[K.length + th.length];
        Memory.copy(ikm, K, K.length);
        Memory.copy((uint8*) ikm + K.length, th, th.length);

        Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(new Bytes(sid), new Bytes(ikm));
        Bytes session_key = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes("CPace-SessionKey-v1".data), 32);
        return session_key.get_data();
    }

    /* confirm: derive a 16-byte confirmation tag for this role */
    public uint8[] confirm(uint8[] session_key) throws GLib.Error {
        Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(new Bytes(sid), new Bytes(session_key));
        uint8[] label_bytes;
        if (role == CPaceRole.INITIATOR) {
            label_bytes = "CPace-ConfirmA-v1".data;
        } else {
            label_bytes = "CPace-ConfirmB-v1".data;
        }
        /* info = label || sid */
        uint8[] info = new uint8[label_bytes.length + sid.length];
        Memory.copy(info, label_bytes, label_bytes.length);
        Memory.copy((uint8*) info + label_bytes.length, sid, sid.length);
        Bytes tag = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes(info), 16);
        return tag.get_data();
    }

    /* verify_confirm: verify the peer's confirmation tag (opposite role label) */
    public bool verify_confirm(uint8[] session_key, uint8[] peer_tag) throws GLib.Error {
        if (peer_tag.length != 16) {
            return false;
        }
        Bytes prk = global::X3dhpq.Crypto.hkdf_extract_sha512(new Bytes(sid), new Bytes(session_key));
        uint8[] label_bytes;
        /* use the OPPOSITE role's label */
        if (role == CPaceRole.INITIATOR) {
            label_bytes = "CPace-ConfirmB-v1".data;
        } else {
            label_bytes = "CPace-ConfirmA-v1".data;
        }
        uint8[] info = new uint8[label_bytes.length + sid.length];
        Memory.copy(info, label_bytes, label_bytes.length);
        Memory.copy((uint8*) info + label_bytes.length, sid, sid.length);
        Bytes expected_bytes = global::X3dhpq.Crypto.hkdf_expand_sha512(prk, new Bytes(info), 16);
        uint8[] expected = expected_bytes.get_data();

        /* constant-time comparison via XOR accumulator */
        uint8 diff = 0;
        for (int i = 0; i < 16; i++) {
            diff |= (expected[i] ^ peer_tag[i]);
        }
        return diff == 0;
    }

    /* Lexicographic comparison of two equal-length byte arrays.
     * Returns negative, zero, or positive. */
    private static int compare_bytes(uint8[] a, uint8[] b) {
        int len = int.min(a.length, b.length);
        for (int i = 0; i < len; i++) {
            if (a[i] != b[i]) {
                return (int) a[i] - (int) b[i];
            }
        }
        return a.length - b.length;
    }
}

}
