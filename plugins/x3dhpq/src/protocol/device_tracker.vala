// x3dhpq-xep-draft.md §11.8: sealed device-state tracker.
//
// Lets an authorized device sync — and a new device learn an identity exists —
// while every other device is offline. Published to PEP node
// `urn:xmppqr:x3dhpq:devtracker:0` (+notify). The item is AIK-signed (hybrid)
// and its payload is sealed to the set of currently-authorized devices: a
// random content key AES-256-GCM-encrypts the payload, and one hybrid
// (X25519 + ML-KEM-768) `<emk>` copy of the content key is produced per
// authorized device's published bundle key — REUSING the exact 1:1 envelope
// construction (Protocol.initiate_session / Protocol.encrypt_transport_key /
// Protocol.respond_session / Protocol.decrypt_transport_key from pairwise.vala)
// rather than a new hybrid-KEM wrapper. Being able to decrypt the tracker IS
// the proof of authorization (§11.8).
//
// Plaintext payload layout (all integers big-endian), domain separator
// "X3DHPQ-DevTrackerPayload-v1\0":
//   device_count       uint32
//   { device_id uint32 | cert_len uint32 | DC.marshal() }*device_count
//   head_count         uint32
//   { hash 32 bytes }*head_count       (DeviceDag.current_heads())
//   has_aik_priv       uint8 (0/1)
//   [ aik_priv_ed_len uint32 | aik_priv_ed
//     aik_priv_mldsa_len uint32 | aik_priv_mldsa ]   (only if has_aik_priv=1)
//
// Outer SignedPart (what the account AIK hybrid-signs), domain separator
// "X3DHPQ-DevTracker-v1\0":
//   issued_at          uint64
//   sealer_device_id   uint32           (attribution only, mirrors the 1:1
//                                         envelope's sender-device attribute)
//   ct_len             uint32 | ct
//   recipient_count    uint32
//   { device_id uint32 | hdr_len uint32 | hdr | emk_len uint32 | emk }*recipient_count
// marshal = SignedPart | u16 sigEdLen|sigEd(64) | u16 sigMlLen|sigMl(3309)

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

// Outcome of interpreting a fetched/delivered devtracker:0 item (§11.8 case
// 1/2/3). ABSENT covers both "no item at all" and "present but unverifiable/
// malformed" — both fall back to the legacy devicelist-only check rather than
// mutating any local state.
public enum TrackerOutcome {
    ABSENT,
    AUTHORIZED,
    NOT_AUTHORIZED,
}

// Parsed <prekey> block inside one tracker <recipient> — identical fields to
// the 1:1 envelope's <prekey ek= opk-id= kemkey-id= kem-ct=><dc/><aik-ed25519/>
// <aik-mldsa/></prekey>, just decoded from base64/attributes into raw bytes.
// Populated by StreamModule's XML parser (kept out of this file to keep the
// Protocol namespace's byte-codec classes free of an Xmpp/StanzaNode dependency).
public class DevTrackerPrekeyWire : Object {
    public uint8[] ek = new uint8[0];
    public uint32 opk_id = 0;
    public uint32 kemkey_id = 0;
    public uint8[] kem_ct = new uint8[0];
    public uint8[] dc = new uint8[0];
    public uint8[] aik_ed25519 = new uint8[0];
    public uint8[] aik_mldsa = new uint8[0];
}

public class DevTrackerRecipientWire : Object {
    public uint32 device_id = 0;
    public uint8[] hdr_bytes = new uint8[0];
    public uint8[] emk_bytes = new uint8[0];
    public DevTrackerPrekeyWire? prekey = null;
}

// Fully parsed devtracker:0 item, ready for DeviceTrackerSigned.signed_part
// reconstruction and per-recipient decrypt attempts.
public class DevTrackerParsed : Object {
    public uint64 issued_at = 0;
    public uint32 sealer_device_id = 0;
    public uint8[] ct = new uint8[0];
    public Gee.ArrayList<DevTrackerRecipientWire> recipients = new Gee.ArrayList<DevTrackerRecipientWire>();
    public uint8[] sig_ed = new uint8[0];
    public uint8[] sig_mldsa = new uint8[0];
}

public class DeviceTrackerDevice : Object {
    public uint32 device_id = 0;
    public uint8[] cert_bytes = new uint8[0];
}

public class DeviceTrackerPayload : Object {
    public Gee.ArrayList<DeviceTrackerDevice> devices = new Gee.ArrayList<DeviceTrackerDevice>();
    public Gee.ArrayList<Bytes> dag_heads = new Gee.ArrayList<Bytes>();
    public Bytes? aik_priv_ed25519 = null;
    public Bytes? aik_priv_mldsa = null;

    private static void put_u32(uint8[] b, ref int off, uint32 v) {
        b[off++] = (uint8)(v >> 24); b[off++] = (uint8)(v >> 16);
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static uint32 get_u32(uint8[] b, ref int off) {
        uint32 v = ((uint32) b[off] << 24) | ((uint32) b[off+1] << 16) | ((uint32) b[off+2] << 8) | (uint32) b[off+3];
        off += 4; return v;
    }

    public uint8[] marshal() {
        int size = 4;
        foreach (var d in devices) size += 4 + 4 + d.cert_bytes.length;
        size += 4;
        foreach (Bytes h in dag_heads) size += 32;
        size += 1;
        bool has_priv = aik_priv_ed25519 != null && aik_priv_mldsa != null;
        uint8[] ed_bytes = has_priv ? bytes_to_uint8_array((!) aik_priv_ed25519) : new uint8[0];
        uint8[] ml_bytes = has_priv ? bytes_to_uint8_array((!) aik_priv_mldsa) : new uint8[0];
        if (has_priv) size += 4 + ed_bytes.length + 4 + ml_bytes.length;

        uint8[] buf = new uint8[size];
        int off = 0;
        put_u32(buf, ref off, (uint32) devices.size);
        foreach (var d in devices) {
            put_u32(buf, ref off, d.device_id);
            put_u32(buf, ref off, (uint32) d.cert_bytes.length);
            if (d.cert_bytes.length > 0) {
                Memory.copy((uint8*) buf + off, d.cert_bytes, d.cert_bytes.length);
                off += d.cert_bytes.length;
            }
        }
        put_u32(buf, ref off, (uint32) dag_heads.size);
        foreach (Bytes h in dag_heads) {
            unowned uint8[] hd = h.get_data();
            int n = int.min(32, hd.length);
            if (n > 0) Memory.copy((uint8*) buf + off, hd, n);
            off += 32;
        }
        buf[off++] = (uint8) (has_priv ? 1 : 0);
        if (has_priv) {
            put_u32(buf, ref off, (uint32) ed_bytes.length);
            if (ed_bytes.length > 0) { Memory.copy((uint8*) buf + off, ed_bytes, ed_bytes.length); off += ed_bytes.length; }
            put_u32(buf, ref off, (uint32) ml_bytes.length);
            if (ml_bytes.length > 0) { Memory.copy((uint8*) buf + off, ml_bytes, ml_bytes.length); off += ml_bytes.length; }
        }
        return buf;
    }

    public static DeviceTrackerPayload? unmarshal(uint8[] b) {
        if (b.length < 4) return null;
        var payload = new DeviceTrackerPayload();
        int off = 0;
        int64 dev_count = (int64) get_u32(b, ref off);
        if (dev_count < 0 || dev_count > 1000000) return null;
        for (int64 i = 0; i < dev_count; i++) {
            if ((int64) off + 8 > (int64) b.length) return null;
            uint32 device_id = get_u32(b, ref off);
            uint32 cert_len = get_u32(b, ref off);
            if ((int64) off + (int64) cert_len > (int64) b.length) return null;
            var d = new DeviceTrackerDevice();
            d.device_id = device_id;
            d.cert_bytes = new uint8[cert_len];
            if (cert_len > 0) Memory.copy(d.cert_bytes, (uint8*) b + off, (int) cert_len);
            off += (int) cert_len;
            payload.devices.add(d);
        }
        if ((int64) off + 4 > (int64) b.length) return null;
        int64 head_count = (int64) get_u32(b, ref off);
        if (head_count < 0 || head_count > 1000000) return null;
        for (int64 i = 0; i < head_count; i++) {
            if ((int64) off + 32 > (int64) b.length) return null;
            uint8[] h = new uint8[32];
            Memory.copy(h, (uint8*) b + off, 32);
            off += 32;
            payload.dag_heads.add(new Bytes(h));
        }
        if ((int64) off + 1 > (int64) b.length) return null;
        uint8 has_priv = b[off++];
        if (has_priv == 1) {
            if ((int64) off + 4 > (int64) b.length) return null;
            uint32 ed_len = get_u32(b, ref off);
            if ((int64) off + (int64) ed_len > (int64) b.length) return null;
            uint8[] ed = new uint8[ed_len];
            if (ed_len > 0) Memory.copy(ed, (uint8*) b + off, (int) ed_len);
            off += (int) ed_len;
            if ((int64) off + 4 > (int64) b.length) return null;
            uint32 ml_len = get_u32(b, ref off);
            if ((int64) off + (int64) ml_len > (int64) b.length) return null;
            uint8[] ml = new uint8[ml_len];
            if (ml_len > 0) Memory.copy(ml, (uint8*) b + off, (int) ml_len);
            off += (int) ml_len;
            payload.aik_priv_ed25519 = new Bytes(ed);
            payload.aik_priv_mldsa = new Bytes(ml);
        }
        return payload;
    }
}

// One sealed recipient copy inside a tracker item: the hybrid header + emk
// (produced by Protocol.encrypt_transport_key), exactly the same shape as the
// 1:1 envelope's <key rid><hdr/><emk/></key>.
public class DeviceTrackerRecipient : Object {
    public uint32 device_id = 0;
    public uint8[] hdr_bytes = new uint8[0];
    public uint8[] emk_bytes = new uint8[0];
}

// §11.8 "Queued enrollment request": a disabled/pending device choosing
// Associate publishes a signed enrollment request (its DIK/bundle public keys
// + a fresh pairing nonce) to its own pair-hello rendezvous (§10.1a method B)
// so it PERSISTS there rather than only firing a live +notify — any already-
// authorized device sees it on its next connect. Signed with the device's own
// DIK (both Ed25519 and ML-DSA-65) since a disabled/pending device by
// definition holds no AIK_priv yet; this only proves possession of the DIK
// that was published in the request (tamper-evidence), not account authority
// — actual authorization still requires the human-verified manual code/QR
// handshake (§10.6.2) the request merely queues.
public class EnrollRequestSigned : Object {
    private static uint8[] prefix() {
        return { 'X','3','D','H','P','Q','-','E','n','r','o','l','l','R','e','q','-','v','1', 0x00 };
    }

    private static void put_u32(uint8[] b, ref int off, uint32 v) {
        b[off++] = (uint8)(v >> 24); b[off++] = (uint8)(v >> 16);
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }

    public static uint8[] signed_part(uint32 device_id, uint8[] full_jid_bytes, uint8[] sid,
            uint8[] dik_ed25519, uint8[] dik_x25519, uint8[] dik_mldsa) {
        uint8[] PREFIX = prefix();
        int size = PREFIX.length + 4 + 4 + full_jid_bytes.length + 4 + sid.length
            + 4 + dik_ed25519.length + 4 + dik_x25519.length + 4 + dik_mldsa.length;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u32(buf, ref off, device_id);
        put_u32(buf, ref off, (uint32) full_jid_bytes.length);
        if (full_jid_bytes.length > 0) { Memory.copy((uint8*) buf + off, full_jid_bytes, full_jid_bytes.length); off += full_jid_bytes.length; }
        put_u32(buf, ref off, (uint32) sid.length);
        if (sid.length > 0) { Memory.copy((uint8*) buf + off, sid, sid.length); off += sid.length; }
        put_u32(buf, ref off, (uint32) dik_ed25519.length);
        if (dik_ed25519.length > 0) { Memory.copy((uint8*) buf + off, dik_ed25519, dik_ed25519.length); off += dik_ed25519.length; }
        put_u32(buf, ref off, (uint32) dik_x25519.length);
        if (dik_x25519.length > 0) { Memory.copy((uint8*) buf + off, dik_x25519, dik_x25519.length); off += dik_x25519.length; }
        put_u32(buf, ref off, (uint32) dik_mldsa.length);
        if (dik_mldsa.length > 0) { Memory.copy((uint8*) buf + off, dik_mldsa, dik_mldsa.length); off += dik_mldsa.length; }
        return buf;
    }
}

public class DeviceTrackerSigned : Object {
    private static uint8[] prefix() {
        return { 'X','3','D','H','P','Q','-','D','e','v','T','r','a','c','k','e','r','-','v','1', 0x00 };
    }

    private static void put_u32(uint8[] b, ref int off, uint32 v) {
        b[off++] = (uint8)(v >> 24); b[off++] = (uint8)(v >> 16);
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static void put_u64(uint8[] b, ref int off, uint64 v) {
        for (int i = 7; i >= 0; i--) b[off++] = (uint8)(v >> (i * 8));
    }

    public static uint8[] signed_part(uint64 issued_at, uint32 sealer_device_id, uint8[] ct,
            Gee.List<DeviceTrackerRecipient> recipients) {
        uint8[] PREFIX = prefix();
        int size = PREFIX.length + 8 + 4 + 4 + ct.length + 4;
        foreach (var r in recipients) {
            size += 4 + 4 + r.hdr_bytes.length + 4 + r.emk_bytes.length;
        }
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, issued_at);
        put_u32(buf, ref off, sealer_device_id);
        put_u32(buf, ref off, (uint32) ct.length);
        if (ct.length > 0) { Memory.copy((uint8*) buf + off, ct, ct.length); off += ct.length; }
        put_u32(buf, ref off, (uint32) recipients.size);
        foreach (var r in recipients) {
            put_u32(buf, ref off, r.device_id);
            put_u32(buf, ref off, (uint32) r.hdr_bytes.length);
            if (r.hdr_bytes.length > 0) { Memory.copy((uint8*) buf + off, r.hdr_bytes, r.hdr_bytes.length); off += r.hdr_bytes.length; }
            put_u32(buf, ref off, (uint32) r.emk_bytes.length);
            if (r.emk_bytes.length > 0) { Memory.copy((uint8*) buf + off, r.emk_bytes, r.emk_bytes.length); off += r.emk_bytes.length; }
        }
        return buf;
    }
}

}
