// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Dino.Plugins.X3dhpq.Protocol {

// ── Identity types ─────────────────────────────────────────────────────────
//
// Vala counterparts of Go's AccountIdentityKey, AccountIdentityPub,
// and DeviceIdentityKey in internal/x3dhpqcrypto/{account,identity}.go.

/**
 * Account Identity Public key: Ed25519 pub + ML-DSA-65 pub.
 *
 * Wire encoding (mirrors AccountIdentityPub.Marshal in account.go):
 *   uint16-BE(1) || 0x01 || ed25519_pub(32) || mldsa65_pub(1952)
 */
public class AccountIdentityPub : GLib.Object {
    public uint8[] pub_ed25519 { get; set; }
    public uint8[] pub_mldsa   { get; set; }

    public AccountIdentityPub() {
        pub_ed25519 = new uint8[0];
        pub_mldsa   = new uint8[0];
    }

    /** Serialize to the canonical wire format used in issuance payloads. */
    public uint8[] marshal() {
        // uint16-BE version=1 || uint8 hasMLDSA=1 || ed25519_pub || mldsa_pub
        int total = 3 + pub_ed25519.length + pub_mldsa.length;
        uint8[] buf = new uint8[total];
        buf[0] = 0x00;
        buf[1] = 0x01;    // version = 1
        buf[2] = 0x01;    // hasMLDSA flag
        for (int i = 0; i < pub_ed25519.length; i++) {
            buf[3 + i] = pub_ed25519[i];
        }
        for (int i = 0; i < pub_mldsa.length; i++) {
            buf[3 + pub_ed25519.length + i] = pub_mldsa[i];
        }
        return buf;
    }

    /**
     * Deserialize from the canonical wire format.
     * Returns null on malformed input.
     */
    public static AccountIdentityPub? unmarshal(uint8[] b) {
        if (b.length < 3) return null;
        uint16 ver = uint16_from_bytes(b, 0);
        if (ver != 1) return null;
        uint8 has_mldsa = b[2];
        if (has_mldsa != 1) return null;
        int pos = 3;
        // Ed25519 public key is always 32 bytes
        if (pos + 32 > b.length) return null;
        uint8[] ed = new uint8[32];
        for (int i = 0; i < 32; i++) ed[i] = b[pos + i];
        pos += 32;
        int ml_len = b.length - pos;
        if (ml_len <= 0) return null;
        uint8[] ml = new uint8[ml_len];
        for (int i = 0; i < ml_len; i++) ml[i] = b[pos + i];
        AccountIdentityPub pub = new AccountIdentityPub();
        pub.pub_ed25519 = ed;
        pub.pub_mldsa   = ml;
        return pub;
    }
}

/**
 * Account Identity Key: holds both private and public parts.
 *
 * Mirrors Go's AccountIdentityKey{PrivEd25519, PubEd25519, PrivMLDSA, PubMLDSA}.
 */
public class AccountIdentityKey : GLib.Object {
    public uint8[] priv_ed25519 { get; set; }
    public uint8[] pub_ed25519  { get; set; }
    public uint8[] priv_mldsa   { get; set; }
    public uint8[] pub_mldsa    { get; set; }

    public AccountIdentityKey() {
        priv_ed25519 = new uint8[0];
        pub_ed25519  = new uint8[0];
        priv_mldsa   = new uint8[0];
        pub_mldsa    = new uint8[0];
    }

    /** Generate a fresh AccountIdentityKey using wolfssl primitives. */
    public static AccountIdentityKey generate() throws GLib.Error {
        Bytes ed_pub_b;
        Bytes ed_priv_b;
        global::X3dhpq.Crypto.generate_ed25519(out ed_pub_b, out ed_priv_b);
        Bytes ml_pub_b;
        Bytes ml_priv_b;
        global::X3dhpq.Crypto.generate_mldsa65(out ml_pub_b, out ml_priv_b);

        AccountIdentityKey aik = new AccountIdentityKey();
        aik.priv_ed25519 = copy_bytes(ed_priv_b);
        aik.pub_ed25519  = copy_bytes(ed_pub_b);
        aik.priv_mldsa   = copy_bytes(ml_priv_b);
        aik.pub_mldsa    = copy_bytes(ml_pub_b);
        return aik;
    }

    /** Return the public-only view. */
    public AccountIdentityPub public_key() {
        AccountIdentityPub pub = new AccountIdentityPub();
        pub.pub_ed25519 = pub_ed25519;
        pub.pub_mldsa   = pub_mldsa;
        return pub;
    }
}

/**
 * Device Identity Key: Ed25519 + X25519 + ML-DSA-65 key material.
 *
 * Mirrors Go's DeviceIdentityKey{PrivX25519, PubX25519, PrivEd25519, PubEd25519,
 *                                 PrivMLDSA, PubMLDSA}.
 *
 * When reconstructed from a wire DIK pub (unmarshal_dik_pub), the private
 * fields are empty arrays — the struct is pub-only in that case.
 */
public class DeviceIdentityKey : GLib.Object {
    public uint8[] priv_x25519  { get; set; }
    public uint8[] pub_x25519   { get; set; }
    public uint8[] priv_ed25519 { get; set; }
    public uint8[] pub_ed25519  { get; set; }
    public uint8[] priv_mldsa   { get; set; }
    public uint8[] pub_mldsa    { get; set; }

    public DeviceIdentityKey() {
        priv_x25519  = new uint8[0];
        pub_x25519   = new uint8[0];
        priv_ed25519 = new uint8[0];
        pub_ed25519  = new uint8[0];
        priv_mldsa   = new uint8[0];
        pub_mldsa    = new uint8[0];
    }

    /** Generate a fresh DeviceIdentityKey. */
    public static DeviceIdentityKey generate() throws GLib.Error {
        Bytes x_pub_b;
        Bytes x_priv_b;
        global::X3dhpq.Crypto.generate_x25519(out x_pub_b, out x_priv_b);
        Bytes ed_pub_b;
        Bytes ed_priv_b;
        global::X3dhpq.Crypto.generate_ed25519(out ed_pub_b, out ed_priv_b);
        Bytes ml_pub_b;
        Bytes ml_priv_b;
        global::X3dhpq.Crypto.generate_mldsa65(out ml_pub_b, out ml_priv_b);

        DeviceIdentityKey dik = new DeviceIdentityKey();
        dik.priv_x25519  = copy_bytes(x_priv_b);
        dik.pub_x25519   = copy_bytes(x_pub_b);
        dik.priv_ed25519 = copy_bytes(ed_priv_b);
        dik.pub_ed25519  = copy_bytes(ed_pub_b);
        dik.priv_mldsa   = copy_bytes(ml_priv_b);
        dik.pub_mldsa    = copy_bytes(ml_pub_b);
        return dik;
    }
}

// ── Pairing FSM types ───────────────────────────────────────────────────────

public errordomain PairingError {
    PROTOCOL,
    AUTH,
    INTERNAL
}

public enum PairingStep {
    INIT,
    SENT_PAKE1,
    SENT_CONFIRM,
    WAIT_DIK,
    SENT_PAYLOAD,
    DONE
}

public class PairingOptions : GLib.Object {
    public uint32  new_device_id     { get; set; }
    public bool    share_primary     { get; set; }
    public uint8[] state_blob        { get; set; default = new uint8[0]; }
    public uint8   new_device_flags  { get; set; }
    // Trust Manifest Phase 2 (§E2): the CONFIRMER's own DIK private halves. The
    // newcomer's DeviceCertificate is issued (signed) under these, NOT under the
    // account AIK — pairing is a DIK delegation, and the manifest ADD entry (also
    // DIK-signed by the confirmer) is what actually confers trust. When null the
    // FSM falls back to signing the DC under the AIK (legacy/self-genesis path).
    public uint8[]? dik_priv_ed25519 { get; set; default = null; }
    public uint8[]? dik_priv_mldsa   { get; set; default = null; }
}

public class PairingResult : GLib.Object {
    public AccountIdentityPub  aik_pub    { get; set; }
    public DeviceCertificate   cert       { get; set; }
    public AccountIdentityKey? aik_priv   { get; set; }   // null if not shared
    public uint8[]             state_blob { get; set; default = new uint8[0]; }
}

// ── Module-private constants ─────────────────────────────────────────────────

private const uint8 FLAG_PRIMARY = 1;

// ── Module-private utility ───────────────────────────────────────────────────

/** Copy a GLib.Bytes into a fresh uint8[]. */
private static uint8[] copy_bytes(Bytes src) {
    unowned uint8[] data = src.get_data();
    uint8[] cp = new uint8[data.length];
    for (int i = 0; i < data.length; i++) cp[i] = data[i];
    return cp;
}

/**
 * make_nonce mirrors pairing.go line 316.
 *
 * 12-byte buffer:
 *   nonce[0]     = role_tag  ('E' or 'N')
 *   nonce[1..3]  = 0x00
 *   nonce[4..11] = uint64 big-endian counter
 */
private static uint8[] make_nonce(uint8 role_tag, uint64 counter) {
    uint8[] nonce = new uint8[12];
    nonce[0]  = role_tag;
    nonce[1]  = 0x00;
    nonce[2]  = 0x00;
    nonce[3]  = 0x00;
    nonce[4]  = (uint8)((counter >> 56) & 0xff);
    nonce[5]  = (uint8)((counter >> 48) & 0xff);
    nonce[6]  = (uint8)((counter >> 40) & 0xff);
    nonce[7]  = (uint8)((counter >> 32) & 0xff);
    nonce[8]  = (uint8)((counter >> 24) & 0xff);
    nonce[9]  = (uint8)((counter >> 16) & 0xff);
    nonce[10] = (uint8)((counter >>  8) & 0xff);
    nonce[11] = (uint8)( counter        & 0xff);
    return nonce;
}

/**
 * append_u16 writes a 2-byte big-endian length into buf at pos.
 */
private static void append_u16(uint8[] buf, ref int pos, int val) {
    buf[pos]     = (uint8)((val >> 8) & 0xff);
    buf[pos + 1] = (uint8)( val       & 0xff);
    pos += 2;
}

/**
 * append_bytes copies src into buf starting at pos, then advances pos.
 */
private static void append_bytes(uint8[] buf, ref int pos, uint8[] src) {
    for (int i = 0; i < src.length; i++) buf[pos + i] = src[i];
    pos += src.length;
}

/**
 * read_field16: read a uint16-BE length-prefixed field from b at *pos.
 * Advances *pos past the field.
 * Returns false on underflow.
 *
 * Uses bool+out rather than uint8[]? return to avoid Vala treating
 * zero-length arrays as null in a nullable context.
 */
private static bool read_field16(uint8[] b, ref int pos, out uint8[] field) {
    field = new uint8[0];
    if (pos + 2 > b.length) return false;
    int flen = (int)(((uint16) b[pos] << 8) | b[pos + 1]);
    pos += 2;
    if (pos + flen > b.length) return false;
    if (flen > 0) {
        field = new uint8[flen];
        for (int i = 0; i < flen; i++) field[i] = b[pos + i];
    }
    pos += flen;
    return true;
}

/**
 * marshal_dik_pub mirrors pairing.go line 326.
 *
 * Wire: uint16-BE(len(ed))||ed || uint16-BE(len(x))||x || uint16-BE(len(ml))||ml
 */
private static uint8[] marshal_dik_pub(DeviceIdentityKey dik) {
    uint8[] ed = dik.pub_ed25519;
    uint8[] x  = dik.pub_x25519;
    uint8[] ml = dik.pub_mldsa;
    int total = 2 + ed.length + 2 + x.length + 2 + ml.length;
    uint8[] buf = new uint8[total];
    int pos = 0;
    append_u16(buf, ref pos, ed.length);
    append_bytes(buf, ref pos, ed);
    append_u16(buf, ref pos, x.length);
    append_bytes(buf, ref pos, x);
    append_u16(buf, ref pos, ml.length);
    append_bytes(buf, ref pos, ml);
    return buf;
}

/**
 * unmarshal_dik_pub mirrors pairing.go line 346.
 *
 * Private fields are left empty — only public keys are on the wire.
 */
private static DeviceIdentityKey? unmarshal_dik_pub(uint8[] b) {
    int pos = 0;
    uint8[] ed;
    uint8[] x;
    uint8[] ml;
    if (!read_field16(b, ref pos, out ed)) return null;
    if (!read_field16(b, ref pos, out x))  return null;
    if (!read_field16(b, ref pos, out ml)) return null;

    DeviceIdentityKey dik = new DeviceIdentityKey();
    dik.pub_ed25519 = ed;
    dik.pub_x25519  = x;
    dik.pub_mldsa   = ml;
    return dik;
}

/**
 * marshal_issuance_payload mirrors pairing.go lines 380–415.
 *
 * Wire layout:
 *   uint16(len(dc))         || dc
 *   uint16(len(aikPub))     || aikPub
 *   uint8(hasPriv)
 *   uint16(len(aikPriv))    || aikPriv   (empty when hasPriv==0)
 *   uint32(len(stateBlob))  || stateBlob
 */
private static uint8[] marshal_issuance_payload(
    DeviceCertificate  dc,
    AccountIdentityKey aik,
    bool               share_priv,
    uint8[]            state_blob
) {
    uint8[] dc_bytes       = dc.marshal();
    uint8[] aik_pub_bytes  = aik.public_key().marshal();
    uint8[] aik_priv_bytes = share_priv ? marshal_aik_priv(aik) : new uint8[0];
    uint8   has_priv       = share_priv ? 1 : 0;

    int size = 2 + dc_bytes.length
             + 2 + aik_pub_bytes.length
             + 1
             + 2 + aik_priv_bytes.length
             + 4 + state_blob.length;
    uint8[] buf = new uint8[size];
    int pos = 0;

    append_u16(buf, ref pos, dc_bytes.length);
    append_bytes(buf, ref pos, dc_bytes);

    append_u16(buf, ref pos, aik_pub_bytes.length);
    append_bytes(buf, ref pos, aik_pub_bytes);

    buf[pos] = has_priv;
    pos++;

    append_u16(buf, ref pos, aik_priv_bytes.length);
    append_bytes(buf, ref pos, aik_priv_bytes);

    // uint32 big-endian length for state blob
    buf[pos]     = (uint8)((state_blob.length >> 24) & 0xff);
    buf[pos + 1] = (uint8)((state_blob.length >> 16) & 0xff);
    buf[pos + 2] = (uint8)((state_blob.length >>  8) & 0xff);
    buf[pos + 3] = (uint8)( state_blob.length        & 0xff);
    pos += 4;
    append_bytes(buf, ref pos, state_blob);

    return buf;
}

/**
 * unmarshal_issuance_payload mirrors pairing.go lines 418–490.
 */
private static PairingResult? unmarshal_issuance_payload(uint8[] b) {
    int pos = 0;

    uint8[] dc_bytes;
    if (!read_field16(b, ref pos, out dc_bytes)) return null;
    DeviceCertificate? dc = DeviceCertificate.unmarshal(new Bytes(dc_bytes));
    if (dc == null) return null;

    uint8[] aik_pub_bytes;
    if (!read_field16(b, ref pos, out aik_pub_bytes)) return null;
    AccountIdentityPub? aik_pub = AccountIdentityPub.unmarshal(aik_pub_bytes);
    if (aik_pub == null) return null;

    if (pos + 1 > b.length) return null;
    uint8 has_priv = b[pos];
    pos++;

    uint8[] aik_priv_bytes;
    if (!read_field16(b, ref pos, out aik_priv_bytes)) return null;

    if (pos + 4 > b.length) return null;
    uint32 state_len = ((uint32) b[pos] << 24)
                     | ((uint32) b[pos + 1] << 16)
                     | ((uint32) b[pos + 2] << 8)
                     | (uint32) b[pos + 3];
    pos += 4;
    // 64-bit comparison so a corrupt/huge state_len can't wrap to a negative
    // int and reach `new uint8[(int) state_len]` (giant-allocation abort).
    if ((int64) pos + (int64) state_len > (int64) b.length) return null;
    uint8[] state_blob = new uint8[(int) state_len];
    for (int i = 0; i < (int) state_len; i++) state_blob[i] = b[pos + i];

    PairingResult res = new PairingResult();
    res.aik_pub    = (!) aik_pub;
    res.cert       = (!) dc;
    res.state_blob = state_blob;

    if (has_priv == 1 && aik_priv_bytes.length > 0) {
        AccountIdentityKey? aik = unmarshal_aik_priv(aik_priv_bytes);
        if (aik == null) return null;
        res.aik_priv = aik;
    }
    return res;
}

/**
 * marshal_aik_priv mirrors pairing.go lines 493–510.
 *
 * 4 length-prefixed fields: priv_ed25519 || pub_ed25519 || priv_mldsa || pub_mldsa
 * Now carries priv_mldsa to match the PQonversations 4-field wire form, so the
 * new primary can produce hybrid Ed25519+ML-DSA-65 signatures per §7.7.
 */
private static uint8[] marshal_aik_priv(AccountIdentityKey aik) {
    uint8[] priv_ed = aik.priv_ed25519;
    uint8[] pub_ed  = aik.pub_ed25519;
    uint8[] priv_ml = aik.priv_mldsa;
    uint8[] pub_ml  = aik.pub_mldsa;
    int total = 2 + priv_ed.length + 2 + pub_ed.length + 2 + priv_ml.length + 2 + pub_ml.length;
    uint8[] buf = new uint8[total];
    int pos = 0;
    append_u16(buf, ref pos, priv_ed.length);
    append_bytes(buf, ref pos, priv_ed);
    append_u16(buf, ref pos, pub_ed.length);
    append_bytes(buf, ref pos, pub_ed);
    append_u16(buf, ref pos, priv_ml.length);
    append_bytes(buf, ref pos, priv_ml);
    append_u16(buf, ref pos, pub_ml.length);
    append_bytes(buf, ref pos, pub_ml);
    return buf;
}

/**
 * unmarshal_aik_priv mirrors pairing.go lines 513–546.
 *
 * Reads 4 length-prefixed fields: priv_ed25519 || pub_ed25519 || priv_mldsa || pub_mldsa
 */
private static AccountIdentityKey? unmarshal_aik_priv(uint8[] b) {
    int pos = 0;
    uint8[] priv_ed;
    uint8[] pub_ed;
    uint8[] priv_ml;
    uint8[] pub_ml;
    if (!read_field16(b, ref pos, out priv_ed)) return null;
    if (!read_field16(b, ref pos, out pub_ed))  return null;
    if (!read_field16(b, ref pos, out priv_ml)) return null;
    if (!read_field16(b, ref pos, out pub_ml))  return null;

    AccountIdentityKey aik = new AccountIdentityKey();
    aik.priv_ed25519 = priv_ed;
    aik.pub_ed25519  = pub_ed;
    aik.priv_mldsa   = priv_ml;
    aik.pub_mldsa    = pub_ml;
    return aik;
}

// ── PairingExisting ─────────────────────────────────────────────────────────

/**
 * PairingExisting implements the pairing FSM for the existing (already-enrolled)
 * device — the CPace initiator, role tag 'E'.
 *
 * Mirrors Go's PairingExisting / NewPairingExisting (pairing.go lines 76–205).
 */
public class PairingExisting : GLib.Object {

    private AccountIdentityKey  aik;
    private CPaceState          cpace_state;
    private uint8[]             sid;
    private PairingOptions      opts;
    private uint8[]?            session_key;
    private PairingStep         current_step;
    private uint64              enc_counter;
    private uint64              dec_counter;
    private DeviceCertificate?  issued_cert;

    /**
     * Construct a new PairingExisting session.
     */
    public PairingExisting(
        AccountIdentityKey aik,
        string             code,
        uint8[]            sid,
        PairingOptions     opts
    ) throws GLib.Error {
        this.aik  = aik;
        this.sid  = sid;
        this.opts = opts;

        CPaceContext ctx = CPaceContext();
        ctx.bare_jid            = "";
        ctx.initiator_full_jid  = "";
        ctx.responder_full_jid  = "";
        ctx.server_domain       = "";
        ctx.initiator_aik_pub   = new uint8[0];
        ctx.responder_aik_pub   = new uint8[0];
        ctx.purpose             = "device-pairing";

        this.cpace_state  = CPaceState.create(CPaceRole.INITIATOR, (uint8[]) code.data, sid, ctx);
        this.current_step = PairingStep.INIT;
        this.enc_counter  = 0;
        this.dec_counter  = 0;
    }

    public bool is_done() {
        return current_step == PairingStep.DONE;
    }

    public DeviceCertificate? get_issued_cert() {
        return issued_cert;
    }

    /**
     * Advance the FSM by one step.
     *
     * Returns the reply message, or null when no reply is needed.
     */
    public PairingMsg? step(PairingMsg? in_msg) throws PairingError, GLib.Error {
        switch (current_step) {

        case PairingStep.INIT:
            // E → N: PAKE1(Y_E)
            uint8[] msg1 = cpace_state.message1();
            current_step = PairingStep.SENT_PAKE1;
            return new PairingMsg(PairingMsg.TYPE_PAKE1, msg1);

        case PairingStep.SENT_PAKE1:
            // E ← N: PAKE2(Y_N). Derive session key; send ConfirmE.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_PAKE2) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_PAKE2");
            }
            session_key = cpace_state.process(in_msg.payload);
            uint8[] tag = cpace_state.confirm((!) session_key);
            current_step = PairingStep.SENT_CONFIRM;
            return new PairingMsg(PairingMsg.TYPE_CONFIRM, tag);

        case PairingStep.SENT_CONFIRM:
            // E ← N: ConfirmN. Verify; no reply.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_CONFIRM) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_CONFIRM");
            }
            if (!cpace_state.verify_confirm((!) session_key, in_msg.payload)) {
                throw new PairingError.AUTH("pairing: authentication failed (wrong code or key confirm)");
            }
            current_step = PairingStep.WAIT_DIK;
            return null;

        case PairingStep.WAIT_DIK:
            // E ← N: Payload(enc(DIK_pub)). Decrypt, issue DC, send issuance payload.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_PAYLOAD) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_PAYLOAD");
            }
            uint8[] plain_dik;
            try {
                plain_dik = do_decrypt(in_msg.payload, 'N');
            } catch (GLib.Error e) {
                throw new PairingError.AUTH("pairing: authentication failed (decrypt DIK)");
            }
            DeviceIdentityKey? dik = unmarshal_dik_pub(plain_dik);
            if (dik == null) {
                throw new PairingError.PROTOCOL("pairing: failed to unmarshal DIK pub");
            }
            uint8 flags = opts.new_device_flags;
            if (opts.share_primary) {
                flags |= FLAG_PRIMARY;
            }
            // Trust Manifest Phase 2 (§E2): sign the newcomer DC under the
            // CONFIRMER's DIK when available (pairing is a DIK delegation). Fall
            // back to the account AIK only when no DIK priv was supplied.
            Bytes issue_priv_ed;
            Bytes issue_priv_mldsa;
            if (opts.dik_priv_ed25519 != null && opts.dik_priv_mldsa != null
                    && ((!) opts.dik_priv_ed25519).length > 0 && ((!) opts.dik_priv_mldsa).length > 0) {
                issue_priv_ed = new Bytes((!) opts.dik_priv_ed25519);
                issue_priv_mldsa = new Bytes((!) opts.dik_priv_mldsa);
            } else {
                issue_priv_ed = new Bytes(aik.priv_ed25519);
                issue_priv_mldsa = new Bytes(aik.priv_mldsa);
            }
            DeviceCertificate dc = DeviceCertificate.issue(
                opts.new_device_id,
                new Bytes(((!) dik).pub_ed25519),
                new Bytes(((!) dik).pub_x25519),
                new Bytes(((!) dik).pub_mldsa),
                issue_priv_ed,
                issue_priv_mldsa,
                flags
            );
            issued_cert = dc;
            // §E1: AIK_priv never travels — force share_priv=false in the payload.
            uint8[] issuance = marshal_issuance_payload(dc, aik, false, opts.state_blob);
            uint8[] enc_payload = do_encrypt(issuance, 'E');
            current_step = PairingStep.SENT_PAYLOAD;
            return new PairingMsg(PairingMsg.TYPE_PAYLOAD, enc_payload);

        case PairingStep.SENT_PAYLOAD:
            // E ← N: ACK(enc("ok")). Verify; done.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_ACK) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_ACK");
            }
            uint8[] ack_plain;
            try {
                ack_plain = do_decrypt(in_msg.payload, 'N');
            } catch (GLib.Error e) {
                throw new PairingError.AUTH("pairing: authentication failed (decrypt ACK)");
            }
            if (ack_plain.length != 2 || ack_plain[0] != 'o' || ack_plain[1] != 'k') {
                throw new PairingError.PROTOCOL("pairing: unexpected ACK payload");
            }
            current_step = PairingStep.DONE;
            return null;

        default:
            throw new PairingError.PROTOCOL("pairing: FSM in unexpected state");
        }
    }

    // encrypt with 'E' role tag (own role); uses enc_counter
    private uint8[] do_encrypt(uint8[] plaintext, uint8 role_tag) throws GLib.Error {
        uint8[] nonce = make_nonce(role_tag, enc_counter++);
        Bytes ct = global::X3dhpq.Crypto.aes256gcm_encrypt(
            new Bytes((!) session_key),
            new Bytes(nonce),
            new Bytes(plaintext),
            new Bytes(sid)
        );
        return copy_bytes(ct);
    }

    // decrypt with 'N' peer role tag; uses dec_counter
    private uint8[] do_decrypt(uint8[] ciphertext, uint8 peer_role_tag) throws GLib.Error {
        uint8[] nonce = make_nonce(peer_role_tag, dec_counter++);
        Bytes pt = global::X3dhpq.Crypto.aes256gcm_decrypt(
            new Bytes((!) session_key),
            new Bytes(nonce),
            new Bytes(ciphertext),
            new Bytes(sid)
        );
        return copy_bytes(pt);
    }
}

// ── PairingNew ──────────────────────────────────────────────────────────────

/**
 * PairingNew implements the pairing FSM for the new (not-yet-enrolled) device —
 * the CPace responder, role tag 'N'.
 *
 * Mirrors Go's PairingNew / NewPairingNew (pairing.go lines 207–314).
 */
public class PairingNew : GLib.Object {

    private DeviceIdentityKey  dik;
    private CPaceState         cpace_state;
    private uint8[]            sid;
    private uint8[]?           session_key;
    private PairingStep        current_step;
    private uint64             enc_counter;
    private uint64             dec_counter;
    private PairingResult?     result;

    /**
     * Construct a new PairingNew session.
     */
    public PairingNew(
        DeviceIdentityKey dik,
        string            code,
        uint8[]           sid
    ) throws GLib.Error {
        this.dik = dik;
        this.sid = sid;

        CPaceContext ctx = CPaceContext();
        ctx.bare_jid            = "";
        ctx.initiator_full_jid  = "";
        ctx.responder_full_jid  = "";
        ctx.server_domain       = "";
        ctx.initiator_aik_pub   = new uint8[0];
        ctx.responder_aik_pub   = new uint8[0];
        ctx.purpose             = "device-pairing";

        this.cpace_state  = CPaceState.create(CPaceRole.RESPONDER, (uint8[]) code.data, sid, ctx);
        this.current_step = PairingStep.INIT;
        this.enc_counter  = 0;
        this.dec_counter  = 0;
    }

    public bool is_done() {
        return current_step == PairingStep.DONE;
    }

    public PairingResult? get_result() {
        return result;
    }

    /**
     * Advance the FSM by one step.
     *
     * Returns the reply message, or null when no reply is needed.
     * At SENT_CONFIRM the caller passes null (no inbound message expected).
     */
    public PairingMsg? step(PairingMsg? in_msg) throws PairingError, GLib.Error {
        switch (current_step) {

        case PairingStep.INIT:
            // N ← E: PAKE1(Y_E). Reply PAKE2(Y_N), derive session key.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_PAKE1) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_PAKE1");
            }
            uint8[] msg1 = cpace_state.message1();
            session_key  = cpace_state.process(in_msg.payload);
            current_step = PairingStep.SENT_PAKE1;
            return new PairingMsg(PairingMsg.TYPE_PAKE2, msg1);

        case PairingStep.SENT_PAKE1:
            // N ← E: ConfirmE. Verify; send ConfirmN.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_CONFIRM) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_CONFIRM");
            }
            if (!cpace_state.verify_confirm((!) session_key, in_msg.payload)) {
                throw new PairingError.AUTH("pairing: authentication failed (wrong code or key confirm)");
            }
            uint8[] tag  = cpace_state.confirm((!) session_key);
            current_step = PairingStep.SENT_CONFIRM;
            return new PairingMsg(PairingMsg.TYPE_CONFIRM, tag);

        case PairingStep.SENT_CONFIRM:
            // Caller passes null here; no inbound expected.
            // N → E: Payload(enc(DIK_pub)).
            uint8[] dik_payload = marshal_dik_pub(dik);
            uint8[] enc_dik     = do_encrypt(dik_payload, 'N');
            current_step        = PairingStep.WAIT_DIK;
            return new PairingMsg(PairingMsg.TYPE_PAYLOAD, enc_dik);

        case PairingStep.WAIT_DIK:
            // N ← E: Payload(enc(issuance)). Decrypt, save result, send ACK.
            if (in_msg == null || in_msg.msg_type != PairingMsg.TYPE_PAYLOAD) {
                throw new PairingError.PROTOCOL("pairing: expected TYPE_PAYLOAD");
            }
            uint8[] plain_issuance;
            try {
                plain_issuance = do_decrypt(in_msg.payload, 'E');
            } catch (GLib.Error e) {
                throw new PairingError.AUTH("pairing: authentication failed (decrypt issuance)");
            }
            PairingResult? r = unmarshal_issuance_payload(plain_issuance);
            if (r == null) {
                throw new PairingError.PROTOCOL("pairing: failed to unmarshal issuance payload");
            }
            result = r;
            uint8[] ack_plain = { 'o', 'k' };
            uint8[] ack_enc   = do_encrypt(ack_plain, 'N');
            current_step      = PairingStep.DONE;
            return new PairingMsg(PairingMsg.TYPE_ACK, ack_enc);

        default:
            throw new PairingError.PROTOCOL("pairing: FSM in unexpected state");
        }
    }

    // encrypt with 'N' role tag (own role); uses enc_counter
    private uint8[] do_encrypt(uint8[] plaintext, uint8 role_tag) throws GLib.Error {
        uint8[] nonce = make_nonce(role_tag, enc_counter++);
        Bytes ct = global::X3dhpq.Crypto.aes256gcm_encrypt(
            new Bytes((!) session_key),
            new Bytes(nonce),
            new Bytes(plaintext),
            new Bytes(sid)
        );
        return copy_bytes(ct);
    }

    // decrypt with 'E' peer role tag; uses dec_counter
    private uint8[] do_decrypt(uint8[] ciphertext, uint8 peer_role_tag) throws GLib.Error {
        uint8[] nonce = make_nonce(peer_role_tag, dec_counter++);
        Bytes pt = global::X3dhpq.Crypto.aes256gcm_decrypt(
            new Bytes((!) session_key),
            new Bytes(nonce),
            new Bytes(ciphertext),
            new Bytes(sid)
        );
        return copy_bytes(pt);
    }
}

} // namespace Dino.Plugins.X3dhpq.Protocol
