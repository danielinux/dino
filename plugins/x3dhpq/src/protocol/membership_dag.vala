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
// v3 signed_part layout (all integers big-endian):
//   "X3DHPQ-Audit-v3\0" (16)
//   lamport          uint64          (> max(parent.lamport), enforced)
//   signer_fp        20 bytes        (raw BLAKE2b-160 of the AUTHOR'S ACCOUNT AIK)
//   issuer_device_id uint32          (the device that actually authored this entry)
//   issuer_dc_len    uint16 | issuer_dc  (that device's AIK-signed DeviceCertificate)
//   parent_count     uint16
//   parents[N]     32 bytes each     (SHA-256(marshal(parent)))
//   action         uint8
//   payload_len    uint32
//   payload        payload_len bytes
//   timestamp      int64 (as uint64)
// marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl
// entry_hash = SHA-256(marshal)
//
// Why entries name a device (v3): through v2 an entry was signed directly by the account
// AIK and carried no device identity. Combined with §11.8 — which replicates AIK_priv to
// every authorized device — that made room administration unrevokable: a phone revoked
// from the account manifest still held the account root, so it could keep minting valid
// AddMember/RemoveMember/AddAdmin entries forever, and no verifier could distinguish its
// entries from a surviving device's. §7.5's containment argument covers the device-manifest
// subsystem only; the group journal is independent and was never covered by it. v3 proves
// account AIK -> currently authorized device DIK -> journal action, so revoking the DIK
// revokes its ability to administer rooms.
//
// Actions: AddMember=5, RemoveMember=6 (+optional ban flag byte), AddAdmin=7,
// RemoveAdmin=8, Snapshot=10, DeviceSetChange=11, RetireMember=12.
// Payload for 5/7/8 reuses the v1 24-byte
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
    /* D4.2 — an account announcing that its own device set changed.
     * Payload: aik_fp(20) | manifest_version(uint64).
     *
     * Group membership is at ACCOUNT-AIK level while sender chains go to individual
     * DEVICES, so revoking one device from an account's Trust Manifest leaves that
     * account a room member and nothing rotates — while the revoked device still
     * holds every other member's current sender chain key and its own per-epoch
     * signing key. This entry is what turns a device-set change into a room epoch
     * rotation, which is what actually severs the revoked device: the fresh chain
     * key and signing keypair are distributed only to currently authorized devices. */
    DEVICE_SET_CHANGE = 11,
    /* §13.5c — a member's whole ACCOUNT IDENTITY was replaced by a reset (§12).
     * Payload: retired_aik_fp(20) | evidence_kind(1) | evidence_len(uint16) | evidence.
     *
     * §13.5b covers one DEVICE leaving an account; this covers the account itself
     * being re-rooted. Until this entry existed the room listed the old AIK as a
     * member forever, which made §11.8's and §13.1a.0's claim — that a thief holding
     * AIK_priv is left only the loud path of minting a new genesis identity — false
     * for groups: the stolen AIK stayed a member and kept receiving every rotation.
     *
     * Retiring and admitting are deliberately SEPARATE steps. Nothing distinguishes a
     * genuine reset from one minted by whoever stole AIK_priv, so bundling them would
     * let the thief retire the victim and take their seat. Split, the thief can only
     * retire a key they already control (no escalation), and admission still needs an
     * admin who performed the §12.2 out-of-band verification. */
    RETIRE_MEMBER = 12,
}

/* §13.5c evidence kinds. Read as a plain uint8 off the wire; anything else makes the
 * entry unauthorized. */
public enum RetireEvidenceKind {
    /* The complete §12.3 RotationPointer blob, verbatim, signatures included. The
     * entry PROVES ITSELF, so the author vouches for nothing and any current member
     * may relay it. */
    ROTATION_POINTER = 1,
    /* The author attests it re-verified the successor out-of-band per §12.2. This IS
     * the author's word, so owner-or-admin only, and evidence_len MUST be 0. */
    WITNESSED = 2,
}

// Resolve a signer's AIK public keys from its raw-hex fingerprint. Returns false
// if the AIK is not (yet) known, in which case the entry is skipped in the fold.
public delegate bool AikResolver(string signer_fp_hex, out Bytes ed, out Bytes mldsa);

/* §13.1a: asks whether a device is currently revoked for an account, so the fold can reject
 * entries authored by a device that has since lost authority. Verifying an entry's
 * certificate chain only proves the account certified that device at some point; a revoked
 * phone keeps a valid DC (and, under §11.8, the account root), so without this it could keep
 * administering rooms forever. */
public delegate bool DeviceRevocationChecker(string signer_fp_hex, uint32 device_id);

/* D6 (§13.1a.0 step 5) — verdict on whether an entry's ISSUING DEVICE may author
 * journal entries for its account. */
public enum IssuerAuthStatus {
    /* The device appears in a Trust Manifest fold this receiver accepted and is not
     * tombstoned. Fold the entry. */
    AUTHORIZED,
    /* A POSITIVE revocation: we hold a tombstone (§11.4) for this (account, device id).
     * Reject — hard, and permanently: no manifest we could later fetch undoes a
     * tombstone, so there is nothing to wait for. This is the only definitive negative;
     * everything else that is merely *unproven* is UNRESOLVED. */
    REJECTED,
    /* Authorization cannot be decided YET. Two shapes, and §13.1a.0's failure policy
     * treats them identically:
     *   (a) we hold NO manifest for that account at all; and
     *   (b) we DO hold manifest history and this device id has never appeared in it —
     *       the forged-DC shape (AIK_priv is replicated to every authorized device
     *       (§11.8), so a device revoked as id 42 can mint a fresh DIK, pick an unseen
     *       id and self-sign a valid DC under the stolen account root).
     * (b) is tempting to REJECT as a definitive negative, and it is not one: an
     * ever-authorized set is only as complete as the manifests THIS receiver happened
     * to fold, so a client that joined late or missed a manifest version legitimately
     * lacks the entry that authorized a device its peers folded. Rejecting there
     * permanently skips an entry the peers folded and the two fold_hashes never
     * reconverge. Quarantine defeats the attack just as completely — the entry is never
     * folded until authorization is positively established — while self-healing when
     * the gap was merely local. Fail closed on the FOLD, not on the ENTRY.
     * The entry is QUARANTINED: kept in the store, not folded, re-evaluated once the
     * author's manifest arrives. Failing open here would restore the attack; discarding
     * would let a transient lookup gap permanently erase a room's history. */
    UNRESOLVED,
}

/* D6 (§13.1a.0 step 5) resolver policy, extracted from the app-layer lookups so it can
 * be pinned directly by a test.
 *
 * The shared conformance corpus CANNOT pin this: `device_auth` is a harness INPUT
 * there, so a vector states the resolved status and pins only what the fold does GIVEN
 * one. Which status a receiver's own manifest bookkeeping produces is exactly the part
 * left unpinned — and it is where the two reference clients silently diverged (Dino
 * returned REJECTED for `manifest held / device never seen`, PQonversations returned
 * UNRESOLVED), which folds different member sets from identical entries. See
 * tests/issuer_status.vala. */
public static IssuerAuthStatus classify_issuer(bool owner_known, bool tombstoned,
                                               bool has_manifest_history,
                                               bool ever_authorized) {
    // We cannot even name the account, so we certainly hold no manifest for it.
    if (!owner_known) return IssuerAuthStatus.UNRESOLVED;
    // Checked BEFORE the history test: a tombstone is a positive result and stands on
    // its own, and the check order is part of the cross-client contract.
    if (tombstoned) return IssuerAuthStatus.REJECTED;
    if (!has_manifest_history) return IssuerAuthStatus.UNRESOLVED;
    return ever_authorized ? IssuerAuthStatus.AUTHORIZED : IssuerAuthStatus.UNRESOLVED;
}

/* Quarantine RELEASE condition: whether an issuer verdict should make the receiver go
 * and fetch that account's Trust Manifest.
 *
 * Derived from the verdict itself rather than from a second, parallel test of the
 * underlying facts. That is the point: EVERY UNRESOLVED shape is releasable by a
 * manifest we do not hold yet — the no-history one obviously, and the
 * history-held-but-id-never-seen one because the authorizing entry may simply live in a
 * manifest version we never folded. Wiring the fetch to only one of the two shapes
 * leaves the other quarantined for good, which is indistinguishable from dropping it.
 * A tombstone needs no fetch (no manifest undoes one), and neither does AUTHORIZED. */
public static bool issuer_status_wants_manifest_fetch(IssuerAuthStatus status, bool owner_known) {
    // An account we cannot name has no node to fetch from.
    return owner_known && status == IssuerAuthStatus.UNRESOLVED;
}

/* D6: resolves the issuer verdict above. Returning AUTHORIZED for everything
 * reproduces the pre-D6 (vulnerable) behaviour, so callers must supply a real one. */
public delegate IssuerAuthStatus DeviceIssuerChecker(string signer_fp_hex, uint32 device_id);

public static string hex_of(uint8[] b) {
    StringBuilder sb = new StringBuilder();
    foreach (uint8 x in b) sb.append_printf("%02x", x);
    return sb.str;
}

public class JournalEntryV2 : Object {
    public uint64 lamport { get; set; }
    public uint8[] signer_fp { get; set; }            // 20 bytes (author's ACCOUNT AIK fp)
    public uint32 issuer_device_id { get; set; }      // device that authored this entry
    public uint8[] issuer_dc { get; set; default = new uint8[0]; }  // its AIK-signed DC
    public Gee.ArrayList<Bytes> parents { get; set; default = new Gee.ArrayList<Bytes>(); } // each 32 bytes
    public uint8 action { get; set; }
    public uint8[] payload { get; set; }
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }
    public uint8[] mldsa_signature { get; set; }

    private static uint8[] v2_prefix() {
        return { 'X','3','D','H','P','Q','-','A','u','d','i','t','-','v','3', 0x00 };
    }

    public uint8[] signed_part() {
        uint8[] PREFIX = v2_prefix();
        int size = PREFIX.length + 8 + 20 + 4 + 2 + issuer_dc.length
                 + 2 + parents.size * 32 + 1 + 4 + payload.length + 8;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, PREFIX, PREFIX.length);
        off += PREFIX.length;
        put_u64(buf, ref off, lamport);
        Memory.copy((uint8*) buf + off, signer_fp, 20);
        off += 20;
        put_u32(buf, ref off, issuer_device_id);
        put_u16(buf, ref off, (uint16) issuer_dc.length);
        if (issuer_dc.length > 0) {
            Memory.copy((uint8*) buf + off, issuer_dc, issuer_dc.length);
            off += issuer_dc.length;
        }
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

    /* Verifies the full chain: the account AIK certified the issuing device, and that
     * device's DIK signed this entry.
     *   1. the embedded DC parses and verifies under the author's ACCOUNT AIK;
     *   2. the DC's device id equals issuer_device_id, so one device's certificate cannot
     *      be replayed to author as a different device of the same account;
     *   3. both hybrid signatures verify under the DC's DIK public keys.
     * Signing with the DIK rather than the AIK is the point: it is what lets revoking a
     * device revoke its room-administration authority. Whether the device is CURRENTLY
     * authorized is a separate fold-level check, since only the fold knows the receiver's
     * revocation state. */
    public bool verify(Bytes signer_ed, Bytes signer_mldsa) throws GLib.Error {
        if (signature.length == 0 || mldsa_signature.length == 0) return false;
        if (issuer_dc.length == 0) return false;

        DeviceCertificate? dc = DeviceCertificate.unmarshal(new Bytes(issuer_dc));
        if (dc == null) return false;
        if (((!) dc).device_id != issuer_device_id) return false;
        try {
            if (!((!) dc).verify(signer_ed, signer_mldsa)) return false;
        } catch (GLib.Error e) {
            return false;
        }

        uint8[] sp = signed_part();
        try {
            if (!global::X3dhpq.Crypto.ed25519_verify(((!) dc).dik_pub_ed25519, new Bytes(sp), new Bytes(signature))) return false;
            return global::X3dhpq.Crypto.mldsa65_verify(((!) dc).dik_pub_mldsa, new Bytes(sp), new Bytes(mldsa_signature));
        } catch (GLib.Error e) {
            /* wolfSSL raises SIG_VERIFY_E rather than returning false. */
            return false;
        }
    }

    public static bool is_v2(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        if (b.length < PREFIX.length) return false;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return false;
        return true;
    }

    public static JournalEntryV2? unmarshal(uint8[] b) {
        uint8[] PREFIX = v2_prefix();
        int min = PREFIX.length + 8 + 20 + 4 + 2 + 2 + 1 + 4 + 8 + 2 + 2;
        if (b.length < min) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) if (b[off + i] != PREFIX[i]) return null;
        off += PREFIX.length;

        JournalEntryV2 e = new JournalEntryV2();
        e.lamport = get_u64(b, ref off);
        e.signer_fp = new uint8[20];
        Memory.copy(e.signer_fp, (uint8*) b + off, 20);
        off += 20;
        e.issuer_device_id = get_u32(b, ref off);
        int dc_len = (int) get_u16(b, ref off);
        if (dc_len < 0) return null;
        if ((int64) off + (int64) dc_len + 2 + 1 + 4 + 8 + 2 + 2 > (int64) b.length) return null;
        e.issuer_dc = new uint8[dc_len];
        if (dc_len > 0) {
            Memory.copy(e.issuer_dc, (uint8*) b + off, dc_len);
            off += dc_len;
        }
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

    // D4.2 DeviceSetChange payload: aik_fp(20) | manifest_version(uint64 BE).
    public static uint8[] build_device_set_change_payload(uint8[] fp20, uint64 manifest_version) {
        uint8[] buf = new uint8[28];
        Memory.copy(buf, fp20, 20);
        int off = 20;
        put_u64(buf, ref off, manifest_version);
        return buf;
    }

    public static bool parse_device_set_change_payload(uint8[] p, out uint8[] fp20, out uint64 manifest_version) {
        fp20 = new uint8[20];
        manifest_version = 0;
        if (p.length < 28) return false;
        Memory.copy(fp20, p, 20);
        int off = 20;
        manifest_version = get_u64(p, ref off);
        return true;
    }

    /* §13.5c RetireMember payload (cross-client contract, big-endian):
     *   retired_aik_fp(20) | evidence_kind(uint8) | evidence_len(uint16) | evidence
     *
     * For kind 2 (witnessed) `evidence` MUST be empty: an unconstrained blob there is a
     * smuggling channel with no verifier, and the successor is deliberately not named
     * because nothing in a witnessed entry would bind it. */
    public static uint8[] build_retire_payload(uint8[] fp20, uint8 evidence_kind, uint8[] evidence) {
        int size = 20 + 1 + 2 + evidence.length;
        uint8[] buf = new uint8[size];
        Memory.copy(buf, fp20, 20);
        int off = 20;
        buf[off++] = evidence_kind;
        put_u16(buf, ref off, (uint16) evidence.length);
        if (evidence.length > 0) {
            Memory.copy((uint8*) buf + off, evidence, evidence.length);
        }
        return buf;
    }

    /* Strict: a declared evidence_len that does not exactly match the remaining bytes is
     * a parse failure, so trailing junk cannot ride along inside an otherwise-valid
     * payload. Returns false on any malformation; the fold treats that as unauthorized. */
    public static bool parse_retire_payload(uint8[] p, out uint8[] fp20,
                                            out uint8 evidence_kind, out uint8[] evidence) {
        fp20 = new uint8[20];
        evidence_kind = 0;
        evidence = new uint8[0];
        if (p.length < 23) return false;
        Memory.copy(fp20, p, 20);
        int off = 20;
        evidence_kind = p[off++];
        int len = (int) get_u16(p, ref off);
        if ((int64) off + (int64) len != (int64) p.length) return false;
        evidence = new uint8[len];
        if (len > 0) Memory.copy(evidence, (uint8*) p + off, len);
        return true;
    }

    // v1->v2 bridge Snapshot payload (cross-client contract, big-endian):
    //   owner_fp(20) | epoch(8) | member_count(4) |
    //   member[ fp(20) | is_admin(1) ]* |
    //   banned_count(4) | banned[ fp(20) | removal_epoch(4) ]* |
    //   retired_count(4) | retired[ fp(20) ]*        (§13.5c)
    // Pubkeys are NOT embedded — resolved via the AIK/devicelist layer.
    //
    // The retired block carries §13.5c state to a late joiner that never saw the
    // RetireMember entries themselves; without it a pruned-history client would fold
    // the dead identity back into the room. Retired fingerprints are emitted ASCENDING
    // by raw byte value so the encoding is canonical for a given set.
    public static uint8[] build_snapshot_payload(SnapshotPayload sp) {
        int mc = sp.member_fps.size;
        int bc = sp.banned_fps.size;
        int rc = sp.retired_fps.size;
        int size = 20 + 8 + 4 + mc * 21 + 4 + bc * 24 + 4 + rc * 20;
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
        put_u32(buf, ref off, (uint32) rc);
        var sorted_retired = new Gee.ArrayList<Bytes>();
        sorted_retired.add_all(sp.retired_fps);
        sorted_retired.sort((a, b) => Memory.cmp(a.get_data(), b.get_data(), 20));
        foreach (Bytes fp in sorted_retired) {
            Memory.copy((uint8*) buf + off, fp.get_data(), 20); off += 20;
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
        if ((int64) off + (int64) bc * 24 + 4 > (int64) p.length) return null;
        for (int i = 0; i < bc; i++) {
            uint8[] fp = new uint8[20];
            Memory.copy(fp, (uint8*) p + off, 20); off += 20;
            uint32 rep = get_u32(p, ref off);
            sp.banned_fps.add(new Bytes(fp));
            sp.banned_epochs.add(rep);
        }
        /* §13.5c retired block. Required, not optional: this is an alpha wire with no
         * backward-compatibility obligation, and treating a missing block as "no retired
         * members" would let a truncating relay silently resurrect a retired identity in
         * every late joiner. */
        int rc = (int) get_u32(p, ref off);
        if (rc < 0 || rc > 100000) return null;
        if ((int64) off + (int64) rc * 20 > (int64) p.length) return null;
        for (int i = 0; i < rc; i++) {
            uint8[] fp = new uint8[20];
            Memory.copy(fp, (uint8*) p + off, 20); off += 20;
            sp.retired_fps.add(new Bytes(fp));
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
    /* §13.5c: identities replaced by an account reset. Encoded ascending by raw byte
     * value; build_snapshot_payload sorts, so callers may add in any order. */
    public Gee.ArrayList<Bytes> retired_fps = new Gee.ArrayList<Bytes>();
}

/* §13.5c presentation record for one retirement. Never serialised onto the wire.
 *
 * `successor_fp_hex` is populated ONLY for kind 1, from pointer.new_aik, and is a value
 * to DISPLAY so the user compares the right fingerprint out of band — it confers no
 * trust, is never admitted, and is never pinned. For kind 2 there is deliberately no
 * successor at all: nothing in a witnessed entry would bind one. */
public class RetiredEvidence : Object {
    public uint8 kind { get; set; default = 0; }
    // The member that authored the entry. For kind 2 this is WHOSE WORD it is.
    public string author_fp_hex { get; set; default = ""; }
    // Kind 1 only: the successor the owner CLAIMS to have moved to. Display only.
    public string successor_fp_hex { get; set; default = ""; }
}

public class DagState : Object {
    public Gee.HashSet<string> members = new Gee.HashSet<string>();     // fp_hex
    public Gee.HashSet<string> admins = new Gee.HashSet<string>();      // fp_hex
    public Gee.HashMap<string, uint32> removed = new Gee.HashMap<string, uint32>(); // fp_hex -> removal epoch
    public Gee.HashSet<string> banned = new Gee.HashSet<string>();      // fp_hex
    /* §13.5c: AIKs whose ACCOUNT IDENTITY was replaced by a reset (§12).
     *
     * Deliberately DISTINCT from `removed` and `banned`. It means "this identity is
     * dead", not "this person was ejected", so the successor — who joins under its own
     * fingerprint by an ordinary AddMember — is never fighting the removal-wins /
     * fail-closed re-admission rules of §13.1a. Retirement is permanent within a
     * journal: there is no un-retire action, and an AddMember naming a retired
     * fingerprint is a no-op. */
    public Gee.HashSet<string> retired = new Gee.HashSet<string>();     // fp_hex
    /* §13.5c client surfacing: how each retirement was evidenced, so the UI can tell the
     * user whether they are looking at a signature made by the old key (kind 1) or at
     * another member's word (kind 2). Local presentation state — it is NOT part of the
     * wire encoding and NOT part of fold_hash. */
    public Gee.HashMap<string, RetiredEvidence> retired_evidence =
        new Gee.HashMap<string, RetiredEvidence>();                     // fp_hex -> evidence
    public string? owner_fp = null;                                     // fp_hex
    public uint32 epoch = 0;
    /* D4.2: highest Trust Manifest version each account has announced through a
     * DeviceSetChange entry. An entry whose version is NOT GREATER than the recorded
     * one is accepted but is not rotation-causing, so a replayed entry cannot inflate
     * the epoch (and, through install-once, burn epoch numbers). */
    public Gee.HashMap<string, uint64?> device_set_version = new Gee.HashMap<string, uint64?>();
    /* D5.1: SHA-256 over the concatenation of every ACCEPTED entry_hash in canonical
     * fold order. Zeroed 32 bytes when nothing folded. */
    public uint8[] fold_hash = new uint8[32];

    /* Per-entry disposition of the fold, as entry_hash hex, in CANONICAL fold order.
     *
     * `accepted` is exactly the list fold_hash is computed over (§13.5a), so publishing
     * it turns a fold_hash mismatch from "some digest differs" into "you accepted a
     * different set of entries, here it is" — which is the difference between a
     * cross-client corpus that localises a divergence and one that only reports it.
     *
     * `unauthorized` and `quarantined` are deliberately SEPARATE (§13.1a.0 failure
     * policy). An unauthorized entry is a decided negative and stays decided; a
     * quarantined one is undecided — it stays in the store and is re-evaluated once the
     * author's Trust Manifest arrives. Collapsing them loses the entry permanently on a
     * transient lookup gap, so a fold that cannot tell them apart cannot be checked for
     * getting it right. None of the three is on the wire or part of fold_hash. */
    public Gee.ArrayList<string> accepted = new Gee.ArrayList<string>();
    public Gee.ArrayList<string> unauthorized = new Gee.ArrayList<string>();
    public Gee.ArrayList<string> quarantined = new Gee.ArrayList<string>();

    /* D5.1: epoch_id = SHA-256("X3DHPQ-EpochId-v1\0" || len||roomJID || epoch
     *                          || fold_hash)[0..8] as a big-endian uint64.
     *
     * Two folds that differ only by a late concurrent entry produce different
     * fold_hashes and therefore different epoch_ids even when the numeric epoch is
     * identical — which is what lets a contradicted epoch be retired and replaced
     * instead of being permanently unusable under install-once. */
    public uint64 epoch_id(string room_jid) {
        try {
            return GroupMessageHeader.derive_epoch_id(room_jid, epoch, fold_hash);
        } catch (GLib.Error e) {
            return 0;
        }
    }
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
        return recompute_checked(resolver, pinned_owner_fp, null);
    }

    public DagState recompute_checked(AikResolver resolver, string? pinned_owner_fp,
                                      DeviceRevocationChecker? revocation_checker) {
        return recompute_authorized(resolver, pinned_owner_fp, revocation_checker, null);
    }

    // `issuer_checker` (D6) supersedes `revocation_checker` when supplied: it answers
    // the stronger question of whether the ISSUING DEVICE has ever appeared in a Trust
    // Manifest fold this receiver accepted, which "is it tombstoned?" alone cannot.
    public DagState recompute_authorized(AikResolver resolver, string? pinned_owner_fp,
                                         DeviceRevocationChecker? revocation_checker,
                                         DeviceIssuerChecker? issuer_checker) {
        var st = new DagState();
        var order = canonical_order();
        var removal_node = new Gee.HashMap<string, string>();
        // D5.1: entry_hashes of every ACCEPTED entry, in canonical fold order. Lives on
        // the state so a caller can see WHICH entries produced the fold_hash, and which
        // were refused versus merely held (§13.1a.0).
        var accepted_hashes = st.accepted;
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
            /* §13.1a.0 failure policy: an entry failing steps 1–4 — unresolvable signer,
             * unparseable or unverifiable DC, bad hybrid signature — is UNAUTHORIZED.
             * Only step 5 quarantines, and there only when authorization is UNDECIDED
             * (no manifest held, or held-but-device-never-seen); a positive tombstone
             * is unauthorized, not quarantined. */
            Bytes ed, ml;
            if (!resolver(signer_hex, out ed, out ml)) {
                st.unauthorized.add(e.hash_hex());
                continue;
            }
            try {
                if (!e.verify(ed, ml)) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
            } catch (GLib.Error err) {
                st.unauthorized.add(e.hash_hex());
                continue;
            }

            /* §13.1a: the certificate chain proves the account certified this device at
             * SOME point, not that it is still authorized. Rejecting entries from a revoked
             * device is what makes room administration actually revocable; without it,
             * revoking a device removes it from the account manifest while leaving it able
             * to add, remove and promote members in every room its account administers. */
            if (revocation_checker != null
                    && revocation_checker(signer_hex, e.issuer_device_id)) {
                st.unauthorized.add(e.hash_hex());
                continue;
            }

            /* D6 (§13.1a.0 step 5): the issuing device MUST be in this receiver's
             * EVER-AUTHORIZED set for the author's account, and MUST NOT be
             * tombstoned. The verification chain above proves only that the account
             * AIK certified this device — and AIK_priv is replicated to every
             * authorized device (§11.8), so a revoked device can mint a fresh DIK,
             * pick a device id nobody has ever seen, and self-sign a valid DC under
             * the stolen root. Tombstoning the id it USED to have does not cover the
             * new one.
             *
             * UNRESOLVED — authorization undecided, whether because we hold no
             * manifest for that account or because we hold history the device has
             * never appeared in — does not fold the entry either, but the entry stays
             * in the store and is re-evaluated on the next fold once the manifest
             * arrives: quarantine, not discard. Only a positive tombstone is a
             * definitive refusal. */
            if (issuer_checker != null) {
                IssuerAuthStatus status = issuer_checker(signer_hex, e.issuer_device_id);
                if (status == IssuerAuthStatus.UNRESOLVED) {
                    /* Held, not refused: absent from `accepted` AND absent from
                     * `unauthorized`, so a caller can tell "we cannot decide yet" from
                     * "we decided no". */
                    st.quarantined.add(e.hash_hex());
                    continue;
                }
                if (status != IssuerAuthStatus.AUTHORIZED) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
            }

            if (!genesis_established) {
                // A genesis must be a root: an entry descending from another entry
                // cannot be the start of the room's history.
                if (e.parents.size != 0) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
                // A first-in-canonical-order Snapshot is a virtual genesis
                // (v1->v2 bridge / MAM-prune-proof catch-up): TOFU-pin owner_fp
                // and import its asserted member/admin/banned sets. The snapshot
                // signer MUST be an asserted admin of the set it declares.
                if (e.action == (uint8) MemberAuditActionV2.SNAPSHOT) {
                    SnapshotPayload? sp = JournalEntryV2.parse_snapshot_payload(e.payload);
                    if (sp == null) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }
                    string owner_hex = hex_of(sp.owner_fp);
                    // The asserted owner is payload data the signer chose, so it is
                    // exactly as attacker-controlled as the signer field. Only the pin
                    // constrains it.
                    if (pinned_owner_fp != null && pinned_owner_fp.down() != owner_hex.down()) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }
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
                    if (!imp_admins.contains(signer_hex)) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }
                    st.owner_fp = owner_hex;
                    foreach (string mh in imp_members) st.members.add(mh);
                    foreach (string ah in imp_admins) st.admins.add(ah);
                    for (int bi = 0; bi < sp.banned_fps.size; bi++) {
                        string bh = hex_of(sp.banned_fps.get(bi).get_data());
                        st.banned.add(bh);
                        st.removed.set(bh, sp.banned_epochs.get(bi));
                    }
                    /* §13.5c: a late joiner converges on the retired set from the
                     * snapshot, so it never folds a dead identity back into the room. */
                    for (int ri = 0; ri < sp.retired_fps.size; ri++) {
                        st.retired.add(hex_of(sp.retired_fps.get(ri).get_data()));
                    }
                    /* The asserted `epoch` is NOT imported (§13.1a.0 "Epoch derivation",
                     * normative): the epoch MUST be the number of authorized
                     * rotation-causing entries IN THE CURRENT FOLD, and a Snapshot is a
                     * passive checkpoint that causes no rotation (§13.5 trigger 2), so a
                     * fold rooted at one starts the count at 0 and the first
                     * rotation-causing descendant makes it 1.
                     *
                     * The snapshot's `epoch` field is payload metadata the signer chose,
                     * in exactly the sense §13.1a.1 gives `epoch_after`: advisory, to be
                     * cross-checked and warned about, never trusted over the folded
                     * state. Importing it lets any admin authoring a snapshot pick the
                     * room's epoch number — including 0xFFFFFFFF, which under
                     * install-once-per-epoch (§13.4a.2) burns the whole remaining epoch
                     * space for every client that folds it.
                     *
                     * CROSS-CLIENT NOTE: §13.5 trigger 2 still carries the sentence "A
                     * client that uses a snapshot as virtual genesis starts from the
                     * snapshot's asserted epoch", which says the opposite. That sentence
                     * is in a non-normative trigger list and is contradicted by two
                     * normative MUSTs; conformance/v2/journal-fold.json
                     * (`snapshot-as-virtual-genesis`) pins the count reading. The spec
                     * sentence needs to go. */
                    st.epoch = 0;
                    genesis_established = true;
                    accepted_hashes.add(e.hash_hex());
                    continue;
                }
                // A plain genesis: the signer becomes owner. The AIK resolver is seeded
                // from the whole local key cache — every contact whose bundle we ever
                // fetched, not just room members — so without the pin ANY known contact
                // could author a root entry, have any member relay it (§13.1a permits
                // relay by anyone), and sort it ahead of the real genesis by choosing
                // its own lamport/signer_fp/hash. On the next fold that stranger is
                // owner: permanent admin, irremovable, undemotable.
                if (pinned_owner_fp != null && pinned_owner_fp.down() != signer_hex.down()) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
                st.owner_fp = signer_hex;
                st.admins.add(signer_hex);
                st.members.add(signer_hex);
                st.epoch = 0;
                genesis_established = true;
                accepted_hashes.add(e.hash_hex());
                continue;
            }

            /* §13.5c: parse the RetireMember payload BEFORE the authorization gate,
             * because who may author one depends on the evidence kind it carries. */
            uint8[] retire_fp = new uint8[20];
            uint8 retire_kind = 0;
            uint8[] retire_evidence = new uint8[0];
            bool retire_parsed = false;
            if (e.action == (uint8) MemberAuditActionV2.RETIRE_MEMBER) {
                retire_parsed = JournalEntryV2.parse_retire_payload(
                    e.payload, out retire_fp, out retire_kind, out retire_evidence);
                if (!retire_parsed) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
            }

            /* D4.2 rule 1: a DeviceSetChange speaks only for its author's own device
             * set, so it needs MEMBERSHIP, not adminship — any member may announce
             * that its own devices changed. Every other action still requires admin. */
            if (e.action == (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE) {
                if (!st.members.contains(signer_hex)) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
            } else if (e.action == (uint8) MemberAuditActionV2.RETIRE_MEMBER) {
                /* §13.5c: the authorization gate branches on the evidence kind, ahead of
                 * the generic owner-or-admin rule, the same way DeviceSetChange branches
                 * on membership.
                 *
                 * kind 1 — the embedded RotationPointer proves itself, re-verified below
                 * against the retired member's own AIK, so the author vouches for nothing
                 * and is only a relay: ANY CURRENT MEMBER may carry it. Restricting it to
                 * admins would mean a room whose admins are all offline cannot act on
                 * evidence every member can check for itself.
                 *
                 * kind 2 — nothing is proved; the entry IS the author's word that they
                 * re-verified the successor out-of-band per §12.2. OWNER OR ADMIN only. */
                if (retire_kind == (uint8) RetireEvidenceKind.ROTATION_POINTER) {
                    if (!st.members.contains(signer_hex)) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }
                } else if (retire_kind == (uint8) RetireEvidenceKind.WITNESSED) {
                    if (!st.admins.contains(signer_hex)) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }
                } else {
                    st.unauthorized.add(e.hash_hex());   // unknown evidence kind
                    continue;
                }
            } else if (!st.admins.contains(signer_hex)) {
                st.unauthorized.add(e.hash_hex());
                continue;
            }

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

            bool rotation_causing = is_rotation_causing(e.action);

            /* D4.2 rules 2–4, evaluated BEFORE the epoch is advanced because whether a
             * DeviceSetChange rotates depends on its payload and on the recorded
             * version, not on its action alone. */
            if (e.action == (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE) {
                uint8[] claimed_fp;
                uint64 manifest_version;
                if (!JournalEntryV2.parse_device_set_change_payload(e.payload, out claimed_fp, out manifest_version)) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
                /* Rule 2: an account speaks only for ITS OWN device set. Any other
                 * value makes the entry unauthorized — otherwise one member could
                 * force epoch churn in another member's name. */
                if (hex_of(claimed_fp).down() != signer_hex.down()) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }
                /* Rule 3: not-greater than the recorded version ⇒ accepted (it folds,
                 * and counts towards fold_hash) but NOT rotation-causing. Replaying an
                 * old entry must not inflate the epoch: install-once (§13.4a.2) makes
                 * every burnt epoch number permanently unusable for a real chain. */
                uint64 recorded = st.device_set_version.has_key(signer_hex)
                    ? (uint64) st.device_set_version.get(signer_hex) : (uint64) 0;
                if (manifest_version <= recorded) {
                    rotation_causing = false;
                } else {
                    /* Rule 4: record and rotate, exactly like Add/RemoveMember (§13.5).
                     * The rotation mints a fresh chain key and a fresh per-epoch signing
                     * keypair handed only to currently authorized devices — that, not the
                     * bookkeeping, is what severs the revoked device. */
                    st.device_set_version.set(signer_hex, manifest_version);
                    rotation_causing = true;
                }
            }

            /* §13.5c RetireMember, evaluated here for the same reason DeviceSetChange is:
             * whether it rotates depends on its payload and on already-folded state, not
             * on its action alone. */
            if (e.action == (uint8) MemberAuditActionV2.RETIRE_MEMBER) {
                string retired_hex = hex_of(retire_fp);

                /* Step 1 — the target MUST resolve to a CURRENT MEMBER of the room, OR be
                 * one this journal has already retired. You cannot retire someone who was
                 * never there: without this a stray entry naming any fingerprint at all
                 * would enter the retired set, and since retirement is permanent and
                 * blocks AddMember, that is a durable denial of admission against a
                 * stranger.
                 *
                 * The already-retired arm is what makes the replay guard below reachable.
                 * The first accepted RetireMember takes the target OUT of `members`, so a
                 * strict current-member test would make every subsequent copy of the same
                 * entry UNAUTHORIZED rather than "accepted but not rotation-causing" —
                 * and the two clients' fold_hashes would then diverge permanently the
                 * first time anyone relayed the persistent pointer twice. */
                if (!st.members.contains(retired_hex) && !st.retired.contains(retired_hex)) {
                    st.unauthorized.add(e.hash_hex());
                    continue;
                }

                var ev = new RetiredEvidence();
                ev.kind = retire_kind;
                ev.author_fp_hex = signer_hex;

                if (retire_kind == (uint8) RetireEvidenceKind.ROTATION_POINTER) {
                    /* THE evidence is re-verified LOCALLY, by every receiver. A kind-1
                     * entry is trusted because the pointer proves itself, never because
                     * the authoring member vouched for it — the author is only a relay,
                     * and treating its relay as an assertion would hand any member the
                     * power to retire any other. */
                    Bytes t_ed, t_ml;
                    if (!resolver(retired_hex, out t_ed, out t_ml)) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }

                    // Step 2 — a malformed blob makes the entry unauthorized.
                    RotationPointer? rp = RotationPointer.unmarshal(retire_evidence);
                    if (rp == null) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }

                    /* Step 3 — BOTH signatures over the pointer's signed_part, against
                     * the AIK the ROOM holds for the member being retired (not against a
                     * key the pointer supplies for itself). */
                    if (!((!) rp).verify_with(t_ed, t_ml)) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }

                    /* Step 4 — fingerprint(pointer.old_aik) == retired_aik_fp. Without
                     * it a pointer legitimately issued for one identity is replayable to
                     * retire a DIFFERENT one: the signature check above would still pass
                     * whenever the two identities share an AIK resolution path. */
                    uint8[] old_fp = ((!) rp).old_aik_fp_raw();
                    if (old_fp.length != 20 || hex_of(old_fp) != retired_hex) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }

                    /* pointer.new_aik is read but NOT TRUSTED. It is deliberately not
                     * consulted here: it is not added to members, not made an admin, and
                     * not pinned. §12.2 requires per-receiver out-of-band verification to
                     * adopt a new identity and no journal entry substitutes for that.
                     * Admitting it here would invert the whole mechanism — whoever stole
                     * AIK_priv could retire the victim AND take their seat, turning a
                     * recovery tool into an eviction primitive. The UI may DISPLAY it so
                     * the user compares the right value out of band — which is all this
                     * assignment is: a string handed to the presentation layer, never
                     * consulted by the fold. */
                    uint8[] new_fp = ((!) rp).new_aik_fp_raw();
                    if (new_fp.length == 20) ev.successor_fp_hex = hex_of(new_fp);
                } else {
                    /* kind 2 — witnessed. evidence_len MUST be 0. A non-zero length is a
                     * smuggling channel with no verifier, so it makes the entry
                     * unauthorized rather than merely being ignored. The successor is
                     * deliberately not named: nothing here would bind it, and a
                     * named-but-unverified successor sitting in the journal is exactly
                     * the value that later gets mistaken for authoritative. */
                    if (retire_evidence.length != 0) {
                        st.unauthorized.add(e.hash_hex());
                        continue;
                    }
                }

                /* Replay guard, same shape as §13.5b: a repeat naming an ALREADY-retired
                 * fingerprint is accepted (it folds and counts towards fold_hash) but is
                 * NOT rotation-causing. Letting a replay bump the epoch would burn epoch
                 * numbers, and install-once (§13.4a.2) makes every burnt number
                 * permanently unusable for a real chain. */
                rotation_causing = !st.retired.contains(retired_hex);
                /* First evidence wins, in canonical order: a later relay of the same
                 * retirement must not overwrite what the user was shown — EXCEPT that a
                 * kind-1 entry supersedes an already-recorded kind-2 for the same
                 * identity (§13.5c "two strengths of retirement").
                 *
                 * The exception is load-bearing, not cosmetic. Kind 2 is an admin's word
                 * and is authoritative for room membership only; kind 1 is a signature by
                 * the retired key itself and is what licenses discarding that peer's
                 * pairwise assertions and refusing to send to it. An admin who witnesses
                 * first and a member who relays the pointer second is an ordinary
                 * ordering, and without this a client that saw them in that order would
                 * keep talking to a key it holds signed evidence is dead — while a client
                 * that saw only the kind-1 stops. That is exactly the divergence §13.5c
                 * forbids. Never the reverse: unsigned word cannot demote a signature.
                 *
                 * Local presentation state — retired_evidence is NOT part of the wire
                 * encoding and NOT part of fold_hash, so this cannot fork the fold. */
                RetiredEvidence? seen = st.retired_evidence.get(retired_hex);
                if (seen == null
                        || (ev.kind == (uint8) RetireEvidenceKind.ROTATION_POINTER
                            && ((!) seen).kind != (uint8) RetireEvidenceKind.ROTATION_POINTER)) {
                    st.retired_evidence.set(retired_hex, ev);
                }
            }

            accepted_hashes.add(e.hash_hex());

            if (rotation_causing) {
                st.epoch = st.epoch + 1;
            }

            switch (e.action) {
                case (uint8) MemberAuditActionV2.ADD_MEMBER:
                    if (subj_hex == st.owner_fp) break;
                    /* §13.5c: an AddMember naming a RETIRED fingerprint is a NO-OP. The
                     * key is retired permanently and the successor joins under its own
                     * fingerprint; resurrecting the dead one would undo the rotation that
                     * severed it and hand the room straight back to whoever holds it. */
                    if (st.retired.contains(subj_hex)) break;
                    if (can_readd(st, removal_node, subj_hex, e)) {
                        st.members.add(subj_hex);
                        st.removed.unset(subj_hex);
                    }
                    break;
                case (uint8) MemberAuditActionV2.ADD_ADMIN:
                    if (st.retired.contains(subj_hex)) break;   // §13.5c, as above
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
                case (uint8) MemberAuditActionV2.DEVICE_SET_CHANGE:
                    /* No membership effect: the whole point of the entry is the epoch
                     * rotation handled above. */
                    break;
                case (uint8) MemberAuditActionV2.RETIRE_MEMBER:
                    /* §13.5c fold effect. The retired identity leaves members AND admins
                     * and enters `retired`; the rotation counted above is what actually
                     * severs it, since the fresh chain key and per-epoch signing key are
                     * only ever handed to the members that remain. Idempotent, so the
                     * replayed (non-rotating) case is harmless.
                     *
                     * The SUCCESSOR is not touched here — see the evidence block above.
                     *
                     * NOTE (cross-client): there is deliberately NO owner exemption here,
                     * unlike RemoveMember/RemoveAdmin. §13.1a makes the owner irremovable
                     * because removal is an ejection someone else performs; a retirement
                     * is a statement that the owner's own key is dead, and an owner who
                     * resets their account needs it to reach the room exactly as much as
                     * anyone else. The durable owner pin is unaffected. */
                    st.members.remove(subj_hex);
                    st.admins.remove(subj_hex);
                    st.retired.add(subj_hex);
                    break;
            }
        }

        /* D5.1: fold_hash = SHA-256( concat of every accepted entry_hash, in canonical
         * fold order ). Accepted means "passed every authorization check and was
         * applied" — entries skipped above never contribute, so two receivers that
         * accept the same entries agree, and a fold that reverses an earlier
         * authorization produces a different hash even at an unchanged epoch count. */
        st.fold_hash = compute_fold_hash(accepted_hashes);
        return st;
    }

    private static uint8[] compute_fold_hash(Gee.ArrayList<string> accepted_hashes_hex) {
        uint8[] buf = new uint8[accepted_hashes_hex.size * 32];
        int off = 0;
        foreach (string h in accepted_hashes_hex) {
            for (int i = 0; i < 32; i++) {
                int hi = hex_nibble_value(h[2 * i]);
                int lo = hex_nibble_value(h[2 * i + 1]);
                buf[off++] = (uint8) (((hi < 0 ? 0 : hi) << 4) | (lo < 0 ? 0 : lo));
            }
        }
        try {
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha256(new Bytes(buf)));
        } catch (GLib.Error e) {
            return new uint8[32];
        }
    }

    private static int hex_nibble_value(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
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
