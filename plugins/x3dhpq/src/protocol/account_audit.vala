// Account audit-chain subscriber and verifier for PEP node urn:xmppqr:x3dhpq:audit:0.
// Implements XEP-XQR §11: append-only chain of AIK-signed AuditEntry records.
// Wire format: signed_part = "X3DHPQ-Audit-v1\0"(16) | seq(8 BE) | prev_hash(32) |
//              action(1) | payload_len(4 BE) | payload | timestamp(8 BE)
// Marshal = signed_part | uint16-be(ed_len) | ed_sig | uint16-be(mldsa_len) | mldsa_sig
// Hash = SHA-256(Marshal())

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public errordomain AccountAuditError {
    BAD_CHAIN,
    BAD_SIGNATURE
}

// Account-level audit actions per §11.4.
public enum AccountAuditAction {
    ADD_DEVICE       = 1,
    REMOVE_DEVICE    = 2,
    ROTATE_AIK       = 3,
    RECOVER_BACKUP   = 4,
}

// AuditEntry models the §11.2 wire fields for account-level audit events.
// This is a separate type from MemberAuditEntry (actions 5/6 used for MUC journals)
// because the action space and UX semantics are distinct.
public class AuditEntry : Object {
    public uint64 seq { get; set; }
    public uint8[] prev_hash { get; set; }   // 32 bytes
    public uint8 action { get; set; }
    public uint8[] payload { get; set; }
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }        // Ed25519, 64 bytes
    public uint8[] mldsa_signature { get; set; }  // ML-DSA-65, 3309 bytes

    // Exactly 16 bytes: "X3DHPQ-Audit-v1" (15) + 0x00.
    // Domain separator "X3DHPQ-Audit-v1\0" (16 bytes). Returned as a fresh LOCAL
    // each call — a `static uint8[]` field initializer reports .length == 0 at
    // runtime in this valac, which dropped the prefix and broke cross-client
    // signing/parsing. Built byte-by-byte so the embedded NUL isn't truncated.
    private static uint8[] audit_prefix() {
        return { 'X','3','D','H','P','Q','-','A','u','d','i','t','-','v','1', 0x00 };
    }

    // §11.3 SignedPart: prefix | seq(8 BE) | prev_hash(32) | action(1) |
    //                   payload_len(4 BE) | payload | timestamp(8 BE)
    public uint8[] signed_part() {
        uint8[] AUDIT_PREFIX = audit_prefix();
        int size = AUDIT_PREFIX.length + 8 + 32 + 1 + 4 + payload.length + 8;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, AUDIT_PREFIX, AUDIT_PREFIX.length);
        off += AUDIT_PREFIX.length;
        buf[off++] = (uint8)(seq >> 56);
        buf[off++] = (uint8)(seq >> 48);
        buf[off++] = (uint8)(seq >> 40);
        buf[off++] = (uint8)(seq >> 32);
        buf[off++] = (uint8)(seq >> 24);
        buf[off++] = (uint8)(seq >> 16);
        buf[off++] = (uint8)(seq >> 8);
        buf[off++] = (uint8) seq;
        Memory.copy((uint8*) buf + off, prev_hash, 32);
        off += 32;
        buf[off++] = action;
        uint32 pl = (uint32) payload.length;
        buf[off++] = (uint8)(pl >> 24);
        buf[off++] = (uint8)(pl >> 16);
        buf[off++] = (uint8)(pl >> 8);
        buf[off++] = (uint8) pl;
        Memory.copy((uint8*) buf + off, payload, payload.length);
        off += payload.length;
        uint64 ts = (uint64) timestamp;
        buf[off++] = (uint8)(ts >> 56);
        buf[off++] = (uint8)(ts >> 48);
        buf[off++] = (uint8)(ts >> 40);
        buf[off++] = (uint8)(ts >> 32);
        buf[off++] = (uint8)(ts >> 24);
        buf[off++] = (uint8)(ts >> 16);
        buf[off++] = (uint8)(ts >> 8);
        buf[off++] = (uint8) ts;
        return buf;
    }

    // §11.3 Marshal: signed_part | uint16-be(ed_len) | ed_sig | uint16-be(mldsa_len) | mldsa_sig
    public uint8[] marshal() {
        uint8[] sp = signed_part();
        int size = sp.length + 2 + signature.length + 2 + mldsa_signature.length;
        uint8[] buf = new uint8[size];
        Memory.copy(buf, sp, sp.length);
        int off = sp.length;
        uint16 sig_len = (uint16) signature.length;
        buf[off++] = (uint8)(sig_len >> 8);
        buf[off++] = (uint8) sig_len;
        Memory.copy((uint8*) buf + off, signature, signature.length);
        off += signature.length;
        uint16 ml_len = (uint16) mldsa_signature.length;
        buf[off++] = (uint8)(ml_len >> 8);
        buf[off++] = (uint8) ml_len;
        Memory.copy((uint8*) buf + off, mldsa_signature, mldsa_signature.length);
        return buf;
    }

    // §11.3 Hash: SHA-256(Marshal())
    public uint8[] compute_hash() {
        uint8[] m = marshal();
        try {
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha256(new Bytes(m)));
        } catch (GLib.Error e) {
            warning("AuditEntry.compute_hash: sha256 failed: %s", e.message);
            return new uint8[32];
        }
    }

    // Hybrid verify per §7.7 and §11.5: both Ed25519 AND ML-DSA-65 must pass.
    public bool verify(Bytes aik_pub_ed25519, Bytes aik_pub_mldsa) throws GLib.Error {
        if (signature.length == 0 || mldsa_signature.length == 0) return false;
        uint8[] sp = signed_part();
        bool ok_ed = global::X3dhpq.Crypto.ed25519_verify(
            aik_pub_ed25519, new Bytes(sp), new Bytes(signature));
        if (!ok_ed) return false;
        return global::X3dhpq.Crypto.mldsa65_verify(
            aik_pub_mldsa, new Bytes(sp), new Bytes(mldsa_signature));
    }

    // Static factory from wire bytes; returns null on malformed input.
    public static AuditEntry? unmarshal(uint8[] b) {
        uint8[] PREFIX = audit_prefix();
        int min_size = PREFIX.length + 8 + 32 + 1 + 4 + 8 + 2 + 2;
        if (b.length < min_size) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) {
            if (b[off + i] != PREFIX[i]) return null;
        }
        off += PREFIX.length;

        AuditEntry e = new AuditEntry();
        e.seq = uint64_from_bytes(b, off);
        off += 8;
        e.prev_hash = new uint8[32];
        Memory.copy(e.prev_hash, (uint8*) b + off, 32);
        off += 32;
        e.action = b[off++];
        uint32 pl = uint32_from_bytes(b, off);
        off += 4;
        // 64-bit comparison so a corrupt/huge length can't wrap or become a
        // negative int and reach `new uint8[(int) pl]` (giant-allocation abort).
        if ((int64) off + (int64) pl + 8 + 2 + 2 > (int64) b.length) return null;
        e.payload = new uint8[(int) pl];
        if (pl > 0) Memory.copy(e.payload, (uint8*) b + off, (int) pl);
        off += (int) pl;
        e.timestamp = int64_from_bytes(b, off);
        off += 8;

        if (off + 2 > b.length) return null;
        int sig_len = (int) uint16_from_bytes(b, off);
        off += 2;
        if (off + sig_len > b.length) return null;
        e.signature = new uint8[sig_len];
        if (sig_len > 0) Memory.copy(e.signature, (uint8*) b + off, sig_len);
        off += sig_len;

        if (off + 2 > b.length) return null;
        int ml_len = (int) uint16_from_bytes(b, off);
        off += 2;
        if (off + ml_len > b.length) return null;
        e.mldsa_signature = new uint8[ml_len];
        if (ml_len > 0) Memory.copy(e.mldsa_signature, (uint8*) b + off, ml_len);

        if (sig_len == 0 || ml_len == 0) return null;
        return e;
    }
}

// AccountAuditChain verifies an ordered sequence of AuditEntry records (oldest → newest)
// against the account's AIK, persists the tail-hash in memory (DB persistence is a TODO),
// and emits audit_entry_observed for each new entry that passes verification.
public class AccountAuditChain : GLib.Object {

    // Fired for each verified new entry with the action code and a human-readable
    // description per §11.6 UX guidance. Callers (UI layer) connect to this signal.
    public signal void audit_entry_observed(int action, string detail);

    private Database? db;

    // TODO: persist tail_hash to the database so it survives restarts. For now it is
    // kept in memory only; the chain must be re-verified from genesis on each login.
    private uint8[] tail_hash;   // 32 bytes; zero = no entries seen yet
    private uint64 next_seq = 0;
    private int64 last_timestamp = 0;
    private bool genesis_seen = false;

    public AccountAuditChain(Database? db) {
        this.db = db;
        this.tail_hash = new uint8[32];   // zero = genesis anchor
    }

    // verify_and_apply checks each entry in chain (oldest → newest) against aik_pub,
    // advances the internal chain state, and emits audit_entry_observed for every valid
    // new entry. Throws AccountAuditError on any verification failure.
    //
    // aik_pub_ed25519 and aik_pub_mldsa are the AIK public key halves sourced from the
    // database (account_identity table or peer_account_identity for remote contacts).
    public void verify_and_apply(int account_id, Bytes aik_pub_ed25519, Bytes aik_pub_mldsa,
                                 Gee.List<AuditEntry> chain) throws AccountAuditError {
        foreach (AuditEntry entry in chain) {
            // §11.5 rule 1: seq must be contiguous.
            if (entry.seq != next_seq) {
                throw new AccountAuditError.BAD_CHAIN(
                    "seq mismatch: expected %llu got %llu".printf(next_seq, entry.seq));
            }

            // §11.5 rule 2: prev_hash anchor.
            if (next_seq == 0) {
                // Genesis: prev_hash must be 32 zero bytes.
                bool all_zero = true;
                foreach (uint8 b in entry.prev_hash) {
                    if (b != 0) { all_zero = false; break; }
                }
                if (!all_zero) {
                    throw new AccountAuditError.BAD_CHAIN("genesis entry prev_hash must be zero");
                }
            } else {
                // Subsequent: prev_hash must equal hash of previous entry.
                for (int i = 0; i < 32; i++) {
                    if (entry.prev_hash[i] != tail_hash[i]) {
                        throw new AccountAuditError.BAD_CHAIN(
                            "prev_hash mismatch at seq %llu".printf(entry.seq));
                    }
                }
            }

            // §11.5 rule 3: timestamp monotonicity (skip for very first entry).
            if (next_seq > 0 && entry.timestamp < last_timestamp) {
                throw new AccountAuditError.BAD_CHAIN(
                    "timestamp regression at seq %llu".printf(entry.seq));
            }

            // §11.5 rules 4-5: both signatures must verify.
            bool sig_ok = false;
            try {
                sig_ok = entry.verify(aik_pub_ed25519, aik_pub_mldsa);
            } catch (GLib.Error e) {
                throw new AccountAuditError.BAD_SIGNATURE(
                    "signature verification threw at seq %llu: %s".printf(entry.seq, e.message));
            }
            if (!sig_ok) {
                throw new AccountAuditError.BAD_SIGNATURE(
                    "hybrid signature failed at seq %llu".printf(entry.seq));
            }

            // Entry is valid — advance chain state.
            tail_hash = entry.compute_hash();
            last_timestamp = entry.timestamp;
            next_seq++;
            genesis_seen = true;

            // Emit the §11.6 UX notification.
            audit_entry_observed(entry.action, action_detail(entry));
        }
    }

    // Returns true once at least one entry has been verified.
    public bool has_entries() {
        return genesis_seen;
    }

    private string action_detail(AuditEntry entry) {
        switch (entry.action) {
            case (uint8) AccountAuditAction.ADD_DEVICE:
                return "A new device was added to your account.";
            case (uint8) AccountAuditAction.REMOVE_DEVICE:
                return "A device was removed from your account.";
            case (uint8) AccountAuditAction.ROTATE_AIK:
                return "Your account's identity key has rotated. If this was not you, your primary device may be compromised.";
            case (uint8) AccountAuditAction.RECOVER_BACKUP:
                return "Your account was recovered from a backup.";
            default:
                return "An unknown account audit event (action=%d) was recorded.".printf(entry.action);
        }
    }
}

}
