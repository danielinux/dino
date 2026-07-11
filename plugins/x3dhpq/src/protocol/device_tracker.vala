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
// CANONICAL WIRE FORMAT (§11.8 "Tracker item wire format (normative,
// canonical)"). PQonversations is the canonical implementation; this codec is
// deliberately byte-for-byte aligned to
// eu.siacs.conversations.crypto.x3dhpq.X3dhpqService's
// publishSealedDeviceTracker/interpretDeviceTracker and
// im.conversations.android.xmpp.model.x3dhpq.devtracker.DevTracker, NOT to the
// (looser) spec prose, which abbreviates the payload domain separator as
// "X3DHPQ-DevTracker\0" — the shipping PQ engine actually signs/frames with
// "X3DHPQ-DevTracker-v1\0" (outer) / "X3DHPQ-DevTracker-Payload-v1\0" (inner);
// those are the bytes both clients must agree on to interoperate, so they are
// what this file reproduces.
//
// Outer element: reuses the 1:1 pairwise-envelope wire shape verbatim (§9.3/
// §9.3a) instead of a bespoke `<recipient>` wrapper — one `<key rid=X
// xmlns='urn:xmppqr:x3dhpq:envelope:0'>` (`<hdr>`/`<emk>`/`<prekey>`, always
// present since every seal is a fresh PQXDH "first message") per authorized
// device, one `<payload xmlns='urn:xmppqr:x3dhpq:envelope:0'>`, and the hybrid
// AIK `<sig>`/`<mldsa-sig>` (namespace `urn:xmppqr:x3dhpq:devicelist:0`, mirrors
// where the devicelist places them) as the LAST children of `<devtracker>`:
//
//   <devtracker xmlns='urn:xmppqr:x3dhpq:devtracker:0'
//               sender-device='..' sender-jid='..' ts='..'
//               version='..' issued-at='..'>
//     <key xmlns='urn:xmppqr:x3dhpq:envelope:0' rid='..'>
//       <hdr>..</hdr><emk>..</emk>
//       <prekey ek='..' opk-id='..' kemkey-id='..' kem-ct='..'>
//         <dc>..</dc><aik-ed25519>..</aik-ed25519><aik-mldsa>..</aik-mldsa>
//       </prekey>
//     </key>
//     ...
//     <payload xmlns='urn:xmppqr:x3dhpq:envelope:0'>..</payload>
//     <sig xmlns='urn:xmppqr:x3dhpq:devicelist:0'>..</sig>
//     <mldsa-sig xmlns='urn:xmppqr:x3dhpq:devicelist:0'>..</mldsa-sig>
//   </devtracker>
//
// Inner plaintext payload layout (all integers big-endian), domain separator
// "X3DHPQ-DevTracker-Payload-v1\0" (matches
// X3dhpqService.DEVTRACKER_PAYLOAD_DOMAIN exactly):
//   snapshot_len       uint32 | <§11.7 Snapshot payload>
//                          (owner_aik_fp(20) | epoch(uint64=0) | count(uint32)
//                           | { device_id(uint32) | cert_len(uint32) | DC.marshal() }*
//                          — DeviceAuditEntryV2.build_snapshot_payload verbatim)
//   head_count         uint32
//   { head_len uint32 | hash head_len bytes }*head_count   (DeviceDag.current_heads())
//   has_aik_priv       uint8 (0/1)
//   [ blob_len uint32 | <AccountIdentityKey.marshal()> ]   (only if has_aik_priv=1)
// where AccountIdentityKey.marshal() (matches the Java x3dhpq-core engine's
// AccountIdentityKey.marshal() EXACTLY — NOT the 4-field length-prefixed
// pairing-issuance format in pairing.vala's marshal_aik_priv, which is a
// different, unrelated wire shape reused verbatim from pairing.go):
//   privEd25519(32) | privMLDSA(4032) | AccountIdentityPub.marshal()(1987) = 6051 bytes fixed.
//
// Outer SignedPart (what the account AIK hybrid-signs), domain separator
// "X3DHPQ-DevTracker-v1\0" (matches X3dhpqService.DEVTRACKER_SIGNED_DOMAIN):
// hashes the bulk content instead of inlining it, so the signed input stays
// small and fixed-size while still binding the signature to every byte
// actually published (matches X3dhpqService.deviceTrackerSignedPart exactly):
//   "X3DHPQ-DevTracker-v1\0"
//   | version(uint64) | issued_at(uint64)
//   | SHA-256(payload ciphertext)(32)
//   | key_count(uint32)
//   | SHA-256(canonical per-key digest, keys sorted by rid ascending)(32)
// where the canonical per-key digest input is, per key (sorted by rid asc):
//   rid(uint32) | hdr_len(uint32) | hdr | emk_len(uint32) | emk
// (the <prekey> block is NOT covered by the keys hash, exactly like PQ).
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

// Parsed <prekey> block inside one tracker <key> — identical fields to the 1:1
// envelope's <prekey ek= opk-id= kemkey-id= kem-ct=><dc/><aik-ed25519/>
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

// One parsed `<key rid=..>` block — the canonical per-recipient wire shape
// reused verbatim from the 1:1 envelope (§9.3/§9.3a).
public class DevTrackerRecipientWire : Object {
    public uint32 device_id = 0;
    public uint8[] hdr_bytes = new uint8[0];
    public uint8[] emk_bytes = new uint8[0];
    public DevTrackerPrekeyWire? prekey = null;
}

// Fully parsed devtracker:0 item, ready for DeviceTrackerSigned.signed_part
// reconstruction and per-recipient decrypt attempts.
public class DevTrackerParsed : Object {
    public uint32 sender_device = 0;
    public string sender_jid = "";
    public string ts = "";
    public uint64 version = 0;
    public uint64 issued_at = 0;
    public uint8[] ct = new uint8[0];
    public Gee.ArrayList<DevTrackerRecipientWire> recipients = new Gee.ArrayList<DevTrackerRecipientWire>();
    public uint8[] sig_ed = new uint8[0];
    public uint8[] sig_mldsa = new uint8[0];
}

// §11.8 plaintext devtracker payload: the folded DeviceState (as a §11.7
// Snapshot) + current DAG head hashes + an optional sealed AIK_priv.
public class DeviceTrackerPayload : Object {
    private static uint8[] domain() {
        return { 'X','3','D','H','P','Q','-','D','e','v','T','r','a','c','k','e','r','-',
                  'P','a','y','l','o','a','d','-','v','1', 0x00 };
    }

    // Owner AIK fingerprint (BLAKE2b-160 of AccountIdentityPub.marshal()) —
    // the §11.7 Snapshot's owner_aik_fp field. MUST be set by the publisher
    // before marshal(); populated from the parsed Snapshot on unmarshal().
    public uint8[] owner_aik_fp = new uint8[20];
    public Gee.ArrayList<DeviceSnapshotDevice> devices = new Gee.ArrayList<DeviceSnapshotDevice>();
    public Gee.ArrayList<Bytes> dag_heads = new Gee.ArrayList<Bytes>();
    public Bytes? aik_priv_ed25519 = null;
    public Bytes? aik_priv_mldsa = null;
    // Only needed by the publisher when aik_priv_* is set, to build the
    // canonical AccountIdentityKey.marshal() blob's trailing
    // AccountIdentityPub.marshal() tail. Unused (left empty) on the parse side.
    public uint8[] aik_pub_ed25519 = new uint8[0];
    public uint8[] aik_pub_mldsa = new uint8[0];

    private static void put_u32(uint8[] b, ref int off, uint32 v) {
        b[off++] = (uint8)(v >> 24); b[off++] = (uint8)(v >> 16);
        b[off++] = (uint8)(v >> 8); b[off++] = (uint8) v;
    }
    private static uint32 get_u32(uint8[] b, ref int off) {
        uint32 v = ((uint32) b[off] << 24) | ((uint32) b[off+1] << 16) | ((uint32) b[off+2] << 8) | (uint32) b[off+3];
        off += 4; return v;
    }

    // Canonical AccountIdentityKey.marshal() — matches the Java x3dhpq-core
    // engine EXACTLY: privEd25519(32) | privMLDSA(4032) | AccountIdentityPub.
    // marshal()(1987) = 6051 bytes fixed. Deliberately distinct from pairing.
    // vala's marshal_aik_priv (a different, 4-field length-prefixed format
    // used ONLY by the pairing-issuance handshake).
    private static uint8[] canonical_aik_marshal(uint8[] priv_ed25519, uint8[] priv_mldsa,
            uint8[] pub_ed25519, uint8[] pub_mldsa) {
        uint8[] pub_bytes = DeviceAuditEntryV2.aik_pub_marshal(pub_ed25519, pub_mldsa);
        uint8[] buf = new uint8[priv_ed25519.length + priv_mldsa.length + pub_bytes.length];
        int off = 0;
        if (priv_ed25519.length > 0) { Memory.copy((uint8*) buf + off, priv_ed25519, priv_ed25519.length); }
        off += priv_ed25519.length;
        if (priv_mldsa.length > 0) { Memory.copy((uint8*) buf + off, priv_mldsa, priv_mldsa.length); }
        off += priv_mldsa.length;
        if (pub_bytes.length > 0) { Memory.copy((uint8*) buf + off, pub_bytes, pub_bytes.length); }
        return buf;
    }

    // Inverse of canonical_aik_marshal — only the two private-key fields are
    // extracted (the trailing AccountIdentityPub is not consumed by any
    // current caller). Requires the fixed 6051-byte total length.
    private static bool canonical_aik_unmarshal(uint8[] b, out uint8[] priv_ed25519, out uint8[] priv_mldsa) {
        priv_ed25519 = new uint8[0];
        priv_mldsa = new uint8[0];
        if (b.length != 6051) return false;
        priv_ed25519 = new uint8[32];
        Memory.copy(priv_ed25519, b, 32);
        priv_mldsa = new uint8[4032];
        Memory.copy(priv_mldsa, (uint8*) b + 32, 4032);
        return true;
    }

    public uint8[] marshal() {
        var sp = new DeviceSnapshotPayload();
        sp.owner_aik_fp = owner_aik_fp;
        sp.epoch = 0;
        sp.devices = devices;
        uint8[] snapshot = DeviceAuditEntryV2.build_snapshot_payload(sp);

        bool has_priv = aik_priv_ed25519 != null && aik_priv_mldsa != null;
        uint8[] aik_blob = new uint8[0];
        if (has_priv) {
            aik_blob = canonical_aik_marshal(
                bytes_to_uint8_array((!) aik_priv_ed25519), bytes_to_uint8_array((!) aik_priv_mldsa),
                aik_pub_ed25519, aik_pub_mldsa);
        }

        uint8[] DOMAIN = domain();
        int size = DOMAIN.length + 4 + snapshot.length + 4;
        foreach (Bytes h in dag_heads) size += 4 + (int) h.get_size();
        size += 1;
        if (has_priv) size += 4 + aik_blob.length;

        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, DOMAIN, DOMAIN.length); off += DOMAIN.length;
        put_u32(buf, ref off, (uint32) snapshot.length);
        if (snapshot.length > 0) { Memory.copy((uint8*) buf + off, snapshot, snapshot.length); off += snapshot.length; }
        put_u32(buf, ref off, (uint32) dag_heads.size);
        foreach (Bytes h in dag_heads) {
            unowned uint8[] hd = h.get_data();
            put_u32(buf, ref off, (uint32) hd.length);
            if (hd.length > 0) { Memory.copy((uint8*) buf + off, hd, hd.length); off += hd.length; }
        }
        buf[off++] = (uint8) (has_priv ? 1 : 0);
        if (has_priv) {
            put_u32(buf, ref off, (uint32) aik_blob.length);
            if (aik_blob.length > 0) { Memory.copy((uint8*) buf + off, aik_blob, aik_blob.length); off += aik_blob.length; }
        }
        return buf;
    }

    public static DeviceTrackerPayload? unmarshal(uint8[] b) {
        uint8[] DOMAIN = domain();
        if (b.length < DOMAIN.length) return null;
        for (int i = 0; i < DOMAIN.length; i++) {
            if (b[i] != DOMAIN[i]) return null;
        }
        int off = DOMAIN.length;

        if (off + 4 > b.length) return null;
        int64 snap_len = (int64) get_u32(b, ref off);
        if (snap_len < 0 || (int64) off + snap_len > (int64) b.length) return null;
        uint8[] snap_bytes = new uint8[snap_len];
        if (snap_len > 0) Memory.copy(snap_bytes, (uint8*) b + off, (int) snap_len);
        off += (int) snap_len;
        DeviceSnapshotPayload? sp = DeviceAuditEntryV2.parse_snapshot_payload(snap_bytes);
        if (sp == null) return null;

        var payload = new DeviceTrackerPayload();
        payload.owner_aik_fp = ((!) sp).owner_aik_fp;
        payload.devices = ((!) sp).devices;

        if (off + 4 > b.length) return null;
        int64 head_count = (int64) get_u32(b, ref off);
        if (head_count < 0 || head_count > 1000000) return null;
        for (int64 i = 0; i < head_count; i++) {
            if ((int64) off + 4 > (int64) b.length) return null;
            uint32 hlen = get_u32(b, ref off);
            if ((int64) off + (int64) hlen > (int64) b.length) return null;
            uint8[] h = new uint8[hlen];
            if (hlen > 0) Memory.copy(h, (uint8*) b + off, (int) hlen);
            off += (int) hlen;
            payload.dag_heads.add(new Bytes(h));
        }

        if (off + 1 > b.length) return null;
        uint8 has_priv = b[off++];
        if (has_priv == 1) {
            if (off + 4 > b.length) return null;
            int64 blob_len = (int64) get_u32(b, ref off);
            if (blob_len < 0 || (int64) off + blob_len > (int64) b.length) return null;
            uint8[] blob = new uint8[blob_len];
            if (blob_len > 0) Memory.copy(blob, (uint8*) b + off, (int) blob_len);
            off += (int) blob_len;
            uint8[] priv_ed;
            uint8[] priv_ml;
            if (!canonical_aik_unmarshal(blob, out priv_ed, out priv_ml)) return null;
            payload.aik_priv_ed25519 = new Bytes(priv_ed);
            payload.aik_priv_mldsa = new Bytes(priv_ml);
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

    // Matches X3dhpqService.deviceTrackerSignedPart exactly: hashes the
    // payload ciphertext and a canonical per-key digest (keys sorted by rid
    // ascending, rid|hdr_len|hdr|emk_len|emk each — the <prekey> block is NOT
    // included) rather than inlining the bulk content.
    public static uint8[] signed_part(uint64 version, uint64 issued_at, uint8[] payload_ct,
            Gee.List<DeviceTrackerRecipient> recipients) throws GLib.Error {
        uint8[] PREFIX = prefix();

        var sorted = new Gee.ArrayList<DeviceTrackerRecipient>();
        sorted.add_all(recipients);
        sorted.sort((a, b) => (a.device_id < b.device_id) ? -1 : (a.device_id > b.device_id ? 1 : 0));

        Bytes payload_hash_b = global::X3dhpq.Crypto.sha256(new Bytes(payload_ct));
        unowned uint8[] payload_hash = payload_hash_b.get_data();

        int keys_size = 0;
        foreach (var r in sorted) keys_size += 4 + 4 + r.hdr_bytes.length + 4 + r.emk_bytes.length;
        uint8[] key_bytes = new uint8[keys_size];
        int koff = 0;
        foreach (var r in sorted) {
            put_u32(key_bytes, ref koff, r.device_id);
            put_u32(key_bytes, ref koff, (uint32) r.hdr_bytes.length);
            if (r.hdr_bytes.length > 0) { Memory.copy((uint8*) key_bytes + koff, r.hdr_bytes, r.hdr_bytes.length); koff += r.hdr_bytes.length; }
            put_u32(key_bytes, ref koff, (uint32) r.emk_bytes.length);
            if (r.emk_bytes.length > 0) { Memory.copy((uint8*) key_bytes + koff, r.emk_bytes, r.emk_bytes.length); koff += r.emk_bytes.length; }
        }
        Bytes keys_hash_b = global::X3dhpq.Crypto.sha256(new Bytes(key_bytes));
        unowned uint8[] keys_hash = keys_hash_b.get_data();

        int size = PREFIX.length + 8 + 8 + payload_hash.length + 4 + keys_hash.length;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, version);
        put_u64(buf, ref off, issued_at);
        Memory.copy((uint8*) buf + off, payload_hash, payload_hash.length);
        off += payload_hash.length;
        put_u32(buf, ref off, (uint32) sorted.size);
        Memory.copy((uint8*) buf + off, keys_hash, keys_hash.length);
        off += keys_hash.length;
        return buf;
    }
}

}
