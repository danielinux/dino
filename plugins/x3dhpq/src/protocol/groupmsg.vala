// Group message header and AEAD helpers matching groupmsg.go wire format.
// Header is exactly 14 bytes: uint16 version | uint32 epoch | uint32 sender_device_id | uint32 chain_index (all BE).
// Nonce: "GMSG" || epoch(4 BE) || chain_index(4 BE) = 12 bytes.
// AAD: header.marshal() || room_jid_utf8.

namespace Dino.Plugins.X3dhpq.Protocol {

public class GroupMessageHeader : Object {
    public uint16 version { get; set; default = 1; }
    public uint32 epoch { get; set; }
    public uint32 sender_device_id { get; set; }
    public uint32 chain_index { get; set; }

    public uint8[] marshal() {
        uint8[] buf = new uint8[14];
        buf[0] = (uint8)(version >> 8);
        buf[1] = (uint8) version;
        buf[2] = (uint8)(epoch >> 24);
        buf[3] = (uint8)(epoch >> 16);
        buf[4] = (uint8)(epoch >> 8);
        buf[5] = (uint8) epoch;
        buf[6] = (uint8)(sender_device_id >> 24);
        buf[7] = (uint8)(sender_device_id >> 16);
        buf[8] = (uint8)(sender_device_id >> 8);
        buf[9] = (uint8) sender_device_id;
        buf[10] = (uint8)(chain_index >> 24);
        buf[11] = (uint8)(chain_index >> 16);
        buf[12] = (uint8)(chain_index >> 8);
        buf[13] = (uint8) chain_index;
        return buf;
    }

    public static GroupMessageHeader? unmarshal(uint8[] b) {
        if (b.length < 14) return null;
        uint16 v = (uint16)(((uint16) b[0] << 8) | b[1]);
        if (v != 1) return null;
        GroupMessageHeader h = new GroupMessageHeader();
        h.version = v;
        h.epoch = uint32_from_bytes(b, 2);
        h.sender_device_id = uint32_from_bytes(b, 6);
        h.chain_index = uint32_from_bytes(b, 10);
        return h;
    }

    // "GMSG" || epoch(4 BE) || chain_index(4 BE)
    public uint8[] aead_nonce() {
        uint8[] n = new uint8[12];
        n[0] = 'G'; n[1] = 'M'; n[2] = 'S'; n[3] = 'G';
        n[4] = (uint8)(epoch >> 24);
        n[5] = (uint8)(epoch >> 16);
        n[6] = (uint8)(epoch >> 8);
        n[7] = (uint8) epoch;
        n[8]  = (uint8)(chain_index >> 24);
        n[9]  = (uint8)(chain_index >> 16);
        n[10] = (uint8)(chain_index >> 8);
        n[11] = (uint8) chain_index;
        return n;
    }

    // §13.3: header.marshal() || room_jid_utf8 || heads_tag
    //
    // heads_tag is 0x00 when no <heads> element accompanies the message, and
    // 0x01 || uint16-be(len) || <canonical heads payload> when one does.
    //
    // Binding <heads> here is what makes §13.1b work at all. The advertisement is a
    // cleartext XML sibling of the ciphertext, so without it in the AAD a malicious relay
    // can strip it, blank it, swap in another well-formed frontier, or equivocate per
    // recipient — and the GCM tag still verifies, defeating the very adversary the
    // mechanism exists to detect. Encoding the ABSENT case matters as much as the value:
    // otherwise a stripped element looks identical to a sender with no frontier.
    //
    // Failing closed costs nothing here: a relay that tampers now gets the message
    // rejected, which it could equally have achieved by dropping the stanza.
    public uint8[] aad_with_heads(string room_jid, uint8[]? heads_payload) {
        uint8[] hdr = marshal();
        uint8[] jid = string_to_bytes(room_jid);
        uint8[] tag;
        if (heads_payload == null) {
            tag = new uint8[] { 0x00 };
        } else {
            uint8[] hp = (!) heads_payload;
            tag = new uint8[3 + hp.length];
            tag[0] = 0x01;
            tag[1] = (uint8) ((hp.length >> 8) & 0xff);
            tag[2] = (uint8) (hp.length & 0xff);
            for (int i = 0; i < hp.length; i++) {
                tag[3 + i] = hp[i];
            }
        }
        return concat_byte_arrays(concat_byte_arrays(hdr, jid), tag);
    }

    // Convenience overload for messages carrying no <heads> advertisement.
    public uint8[] aad(string room_jid) {
        return aad_with_heads(room_jid, null);
    }
}

// §13.1b anti-withholding: membership-journal DAG head list carried in a
// group envelope's <heads> child.
//
// Wire encoding (base64 of this binary form):
//   uint16 n_heads (BE) | n_heads × 32-byte SHA-256 head hash, sorted ascending
//
// A head is a journal entry not referenced as a parents[] element by any
// other entry — the current DAG frontier (§13.1a). Sorting makes the
// encoding deterministic across implementations (hash-map iteration order
// is not). The element is omitted entirely when n_heads == 0.
//
// KAT: see tests/membership_dag.vala (group_heads_kat_vector) — MUST match
// PQonversations' libs/x3dhpq-core GroupHeadsTest byte-for-byte.
public class GroupHeads : Object {
    public const size_t HEAD_LENGTH = 32;

    public static uint8[] encode(Gee.ArrayList<Bytes> heads) throws Error {
        var sorted = new Gee.ArrayList<Bytes>();
        foreach (Bytes h in heads) {
            if ((size_t) h.get_size() != HEAD_LENGTH) {
                throw new IOError.FAILED("heads: entry must be 32 bytes");
            }
            sorted.add(h);
        }
        if (sorted.size > 0xFFFF) {
            throw new IOError.FAILED("heads: too many entries");
        }
        sorted.sort((a, b) => {
            uint8[] da = bytes_to_uint8_array(a);
            uint8[] db_ = bytes_to_uint8_array(b);
            int n = (da.length < db_.length) ? da.length : db_.length;
            for (int i = 0; i < n; i++) {
                if (da[i] != db_[i]) return (int) da[i] - (int) db_[i];
            }
            return da.length - db_.length;
        });
        uint8[] buf = new uint8[2 + 32 * (int) sorted.size];
        buf[0] = (uint8) (sorted.size >> 8);
        buf[1] = (uint8) sorted.size;
        size_t off = 2;
        foreach (Bytes h in sorted) {
            uint8[] hd = bytes_to_uint8_array(h);
            Memory.copy((uint8*) buf + off, hd, 32);
            off += 32;
        }
        return buf;
    }

    public static Gee.ArrayList<Bytes> decode(uint8[] raw) throws Error {
        if (raw.length < 2) {
            throw new IOError.FAILED("heads: empty payload");
        }
        int n = ((int) raw[0] << 8) | raw[1];
        if (raw.length != 2 + 32 * n) {
            throw new IOError.FAILED("heads: length %u inconsistent with n=%d".printf(raw.length, n));
        }
        var out = new Gee.ArrayList<Bytes>();
        for (int i = 0; i < n; i++) {
            uint8[] piece = new uint8[32];
            Memory.copy(piece, raw + (2 + 32 * i), 32);
            out.add(new Bytes(piece));
        }
        return out;
    }

    // True iff every hash in `a` is present in `b` (order-insensitive).
    public static bool covers(Gee.ArrayList<Bytes> a, Gee.ArrayList<Bytes> b) {
        var bs = new Gee.HashSet<string>();
        foreach (Bytes h in b) {
            bs.add(hex_of(bytes_to_uint8_array(h)));
        }
        foreach (Bytes h in a) {
            if (!bs.contains(hex_of(bytes_to_uint8_array(h)))) {
                return false;
            }
        }
        return true;
    }
}

}
