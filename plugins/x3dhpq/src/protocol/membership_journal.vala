// Membership journal verifier for per-MUC PEP node urn:xmppqr:x3dhpq:group:0.
// Mirrors audit_chain.go AuditEntry signed-part format.
// AuditAction extended with AddMember=5, RemoveMember=6 (XEP §13 extension).
// signed_part = "X3DHPQ-Audit-v1\0" | seq(8 BE) | prev_hash(32) | action(1) | payload_len(4 BE) | payload | timestamp(8 BE)
// Payload for AddMember/RemoveMember: aik_fp(20 bytes raw blake2b-160) | epoch_after(4 BE)
// Both Ed25519 and ML-DSA-65 signatures must verify against the room owner's AIK.

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

public enum MemberAuditAction {
    ADD_MEMBER = 5,
    REMOVE_MEMBER = 6,
}

public class MemberAuditEntry : Object {
    public uint64 seq { get; set; }
    public uint8[] prev_hash { get; set; }   // 32 bytes
    public uint8 action { get; set; }
    public uint8[] payload { get; set; }
    public int64 timestamp { get; set; }
    public uint8[] signature { get; set; }
    public uint8[] mldsa_signature { get; set; }

    // Exactly 16 bytes: "X3DHPQ-Audit-v1" (15) + 0x00 trailing.
    // The Vala string literal "X3DHPQ-Audit-v1\x00" yields only 15 bytes via
    // string.data because the embedded NUL terminates the C string view, so
    // we build the prefix byte-by-byte to match the canonical wire layout
    // (Conversations Java + Go reference both write 16 bytes).
    private static uint8[] AUDIT_PREFIX = {
        'X','3','D','H','P','Q','-','A','u','d','i','t','-','v','1', 0x00
    };

    public uint8[] signed_part() {
        int size = AUDIT_PREFIX.length + 8 + 32 + 1 + 4 + payload.length + 8;
        uint8[] buf = new uint8[size];
        int off = 0;
        Memory.copy(buf, AUDIT_PREFIX, AUDIT_PREFIX.length);
        off += AUDIT_PREFIX.length;
        // seq uint64 BE
        buf[off++] = (uint8)(seq >> 56);
        buf[off++] = (uint8)(seq >> 48);
        buf[off++] = (uint8)(seq >> 40);
        buf[off++] = (uint8)(seq >> 32);
        buf[off++] = (uint8)(seq >> 24);
        buf[off++] = (uint8)(seq >> 16);
        buf[off++] = (uint8)(seq >> 8);
        buf[off++] = (uint8) seq;
        // prev_hash 32 bytes
        Memory.copy((uint8*) buf + off, prev_hash, 32);
        off += 32;
        // action 1 byte
        buf[off++] = action;
        // payload_len uint32 BE
        uint32 pl = (uint32) payload.length;
        buf[off++] = (uint8)(pl >> 24);
        buf[off++] = (uint8)(pl >> 16);
        buf[off++] = (uint8)(pl >> 8);
        buf[off++] = (uint8) pl;
        Memory.copy((uint8*) buf + off, payload, payload.length);
        off += payload.length;
        // timestamp int64 as uint64 BE
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

    public uint8[] compute_hash() {
        uint8[] marshalled = marshal();
        try {
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha256(new Bytes(marshalled)));
        } catch (GLib.Error e) {
            warning("MemberAuditEntry.compute_hash: sha256 failed: %s", e.message);
            return new uint8[32];
        }
    }

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

    public bool verify(Bytes owner_aik_ed25519, Bytes owner_aik_mldsa) throws GLib.Error {
        if (signature.length == 0 || mldsa_signature.length == 0) return false;
        uint8[] sp = signed_part();
        bool ok_ed = global::X3dhpq.Crypto.ed25519_verify(
            owner_aik_ed25519, new Bytes(sp), new Bytes(signature));
        if (!ok_ed) return false;
        return global::X3dhpq.Crypto.mldsa65_verify(
            owner_aik_mldsa, new Bytes(sp), new Bytes(mldsa_signature));
    }

    public static MemberAuditEntry? unmarshal(uint8[] b) {
        uint8[] PREFIX = AUDIT_PREFIX;
        int min_size = PREFIX.length + 8 + 32 + 1 + 4 + 8 + 2 + 2;
        if (b.length < min_size) return null;
        int off = 0;
        for (int i = 0; i < PREFIX.length; i++) {
            if (b[off + i] != PREFIX[i]) return null;
        }
        off += PREFIX.length;

        MemberAuditEntry e = new MemberAuditEntry();
        e.seq = uint64_from_bytes(b, off);
        off += 8;
        e.prev_hash = new uint8[32];
        Memory.copy(e.prev_hash, (uint8*) b + off, 32);
        off += 32;
        e.action = b[off++];
        uint32 pl = uint32_from_bytes(b, off);
        off += 4;
        if (off + (int) pl + 8 + 2 > b.length) return null;
        e.payload = new uint8[(int) pl];
        if (pl > 0) Memory.copy(e.payload, (uint8*) b + off, (int) pl);
        off += (int) pl;
        e.timestamp = (int64) uint64_from_bytes(b, off);
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

    // Build payload bytes for AddMember/RemoveMember:
    // aik_fp_raw(20 bytes) | epoch_after(4 BE)
    public static uint8[] build_member_payload(uint8[] aik_fp_raw_20, uint32 epoch_after) {
        uint8[] buf = new uint8[24];
        Memory.copy(buf, aik_fp_raw_20, 20);
        buf[20] = (uint8)(epoch_after >> 24);
        buf[21] = (uint8)(epoch_after >> 16);
        buf[22] = (uint8)(epoch_after >> 8);
        buf[23] = (uint8) epoch_after;
        return buf;
    }

    // Extract aik_fp_raw and epoch_after from payload.
    public static bool parse_member_payload(uint8[] payload, out uint8[] aik_fp_raw, out uint32 epoch_after) {
        aik_fp_raw = {};
        epoch_after = 0;
        if (payload.length < 24) return false;
        aik_fp_raw = new uint8[20];
        Memory.copy(aik_fp_raw, payload, 20);
        epoch_after = uint32_from_bytes(payload, 20);
        return true;
    }
}

// Stateful verifier for an ordered sequence of membership journal entries.
public class MembershipJournal : Object {
    private uint64 next_seq = 0;
    private uint8[] last_hash;      // 32 bytes, zero initially
    private int64 last_timestamp = 0;
    // fp_hex -> true (active members)
    private HashMap<string, bool> current_members = new HashMap<string, bool>();
    // fp_hex -> epoch at removal
    private HashMap<string, uint32> removed_aiks = new HashMap<string, uint32>();

    public MembershipJournal() {
        last_hash = new uint8[32];  // zero
    }

    // Returns true if the entry is valid and advances state.
    public bool append(MemberAuditEntry entry, Bytes owner_aik_ed, Bytes owner_aik_mldsa) throws GLib.Error {
        if (entry.seq != next_seq) return false;
        if (next_seq == 0) {
            // genesis: prev_hash must be zero
            bool all_zero = true;
            foreach (uint8 b in entry.prev_hash) {
                if (b != 0) { all_zero = false; break; }
            }
            if (!all_zero) return false;
        } else {
            // prev_hash must match hash of previous entry
            for (int i = 0; i < 32; i++) {
                if (entry.prev_hash[i] != last_hash[i]) return false;
            }
        }
        if (entry.timestamp < last_timestamp) return false;
        bool sig_ok = false;
        try {
            sig_ok = entry.verify(owner_aik_ed, owner_aik_mldsa);
        } catch (GLib.Error e) {
            return false;
        }
        if (!sig_ok) return false;

        // Update state for group actions.
        if (entry.action == (uint8) MemberAuditAction.ADD_MEMBER) {
            uint8[] fp_raw;
            uint32 ep;
            if (!MemberAuditEntry.parse_member_payload(entry.payload, out fp_raw, out ep)) return false;
            string fp_hex = bytes_to_hex(fp_raw);
            removed_aiks.unset(fp_hex);
            current_members[fp_hex] = true;
        } else if (entry.action == (uint8) MemberAuditAction.REMOVE_MEMBER) {
            uint8[] fp_raw;
            uint32 ep;
            if (!MemberAuditEntry.parse_member_payload(entry.payload, out fp_raw, out ep)) return false;
            string fp_hex = bytes_to_hex(fp_raw);
            current_members.unset(fp_hex);
            removed_aiks[fp_hex] = ep;
        }

        last_hash = entry.compute_hash();
        last_timestamp = entry.timestamp;
        next_seq++;
        return true;
    }

    public bool has_any_entries() {
        return next_seq > 0;
    }

    public HashMap<string, bool> get_members() {
        return current_members;
    }

    public HashMap<string, uint32> get_removed_aiks() {
        return removed_aiks;
    }

    private string bytes_to_hex(uint8[] b) {
        StringBuilder sb = new StringBuilder();
        foreach (uint8 byte in b) {
            sb.append_printf("%02x", byte);
        }
        return sb.str;
    }
}

}
