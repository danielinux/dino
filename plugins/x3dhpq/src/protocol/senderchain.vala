// Megolm-style symmetric sender chain matching senderchain.go.
// Wire: epoch(4) | ck_len(4)=32 | ck(32) | next_index(4) | num_skipped(4) | [idx(4) mk_len(4)=32 mk(32)]...
// Step: mk = HMAC-SHA-256(ck, 0x01); next_ck = HMAC-SHA-256(ck, 0x02).

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

private const int MAX_SKIPPED = 256;

public class SenderChain : Object {
    public uint32 epoch { get; set; }
    public uint8[] chain_key { get; set; }   // 32 bytes
    public uint32 next_index { get; set; }
    // skipped message keys: index -> mk (stored as Bytes to avoid array-as-generic-arg)
    private HashMap<uint32, Bytes> skipped = new HashMap<uint32, Bytes>();

    public static SenderChain new_random(uint32 epoch) throws GLib.Error {
        SenderChain sc = new SenderChain();
        sc.epoch = epoch;
        sc.chain_key = bytes_to_uint8_array(global::X3dhpq.Crypto.random_bytes(32));
        sc.next_index = 0;
        return sc;
    }

    public static SenderChain? restore(uint32 epoch, uint8[] ck, uint32 next_index) {
        if (ck.length != 32) return null;
        SenderChain sc = new SenderChain();
        sc.epoch = epoch;
        sc.chain_key = ck.copy();
        sc.next_index = next_index;
        return sc;
    }

    // Returns message key; advances chain_key and next_index. index is returned via out param.
    public uint8[]? step(out uint32 index) throws GLib.Error {
        uint8[] mk = bytes_to_uint8_array(
            global::X3dhpq.Crypto.hmac_sha256(new Bytes(chain_key), new Bytes({ 0x01 })));
        uint8[] next_ck = bytes_to_uint8_array(
            global::X3dhpq.Crypto.hmac_sha256(new Bytes(chain_key), new Bytes({ 0x02 })));
        index = next_index;
        chain_key = next_ck;
        next_index++;
        return mk;
    }

    // Get message key at `target`, advancing/caching skipped keys as needed.
    public uint8[]? message_key_at(uint32 target) throws GLib.Error {
        if (skipped.has_key(target)) {
            Bytes mk_b = skipped[target];
            skipped.unset(target);
            return bytes_to_uint8_array(mk_b);
        }
        if (target < next_index) {
            throw new IOError.FAILED("senderchain: requested index already advanced past");
        }
        while (next_index < target) {
            if (skipped.size >= MAX_SKIPPED) {
                throw new IOError.FAILED("senderchain: too many skipped keys");
            }
            uint32 idx;
            uint8[]? mk = step(out idx);
            if (mk == null) return null;
            skipped[idx] = new Bytes(mk);
        }
        uint32 idx;
        return step(out idx);
    }

    // Wire format matching senderchain.go Marshal.
    public uint8[] marshal() {
        uint32 num_skipped = (uint32) skipped.size;
        int size = 4 + 4 + 32 + 4 + 4 + (int) num_skipped * (4 + 4 + 32);
        uint8[] buf = new uint8[size];
        int off = 0;

        buf[off++] = (uint8)(epoch >> 24);
        buf[off++] = (uint8)(epoch >> 16);
        buf[off++] = (uint8)(epoch >> 8);
        buf[off++] = (uint8) epoch;

        buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 32;
        Memory.copy((uint8*) buf + off, chain_key, 32);
        off += 32;

        buf[off++] = (uint8)(next_index >> 24);
        buf[off++] = (uint8)(next_index >> 16);
        buf[off++] = (uint8)(next_index >> 8);
        buf[off++] = (uint8) next_index;

        buf[off++] = (uint8)(num_skipped >> 24);
        buf[off++] = (uint8)(num_skipped >> 16);
        buf[off++] = (uint8)(num_skipped >> 8);
        buf[off++] = (uint8) num_skipped;

        foreach (var entry in skipped.entries) {
            uint32 idx = entry.key;
            uint8[] mk = bytes_to_uint8_array(entry.value);
            buf[off++] = (uint8)(idx >> 24);
            buf[off++] = (uint8)(idx >> 16);
            buf[off++] = (uint8)(idx >> 8);
            buf[off++] = (uint8) idx;
            buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 32;
            Memory.copy((uint8*) buf + off, mk, 32);
            off += 32;
        }
        return buf;
    }

    public static SenderChain? unmarshal(uint8[] b) {
        if (b.length < 48) return null;
        int off = 0;

        uint32 ep = uint32_from_bytes(b, off);
        off += 4;
        uint32 ck_len = uint32_from_bytes(b, off);
        off += 4;
        if (ck_len != 32 || off + 32 > b.length) return null;
        uint8[] ck = new uint8[32];
        Memory.copy(ck, (uint8*) b + off, 32);
        off += 32;
        if (off + 8 > b.length) return null;
        uint32 ni = uint32_from_bytes(b, off);
        off += 4;
        uint32 num_sk = uint32_from_bytes(b, off);
        off += 4;

        if (num_sk > (uint32) MAX_SKIPPED) return null;

        SenderChain sc = new SenderChain();
        sc.epoch = ep;
        sc.chain_key = ck;
        sc.next_index = ni;

        for (uint32 i = 0; i < num_sk; i++) {
            if (off + 4 + 4 + 32 > b.length) return null;
            uint32 idx = uint32_from_bytes(b, off);
            off += 4;
            uint32 mk_len = uint32_from_bytes(b, off);
            off += 4;
            if (mk_len != 32 || off + 32 > b.length) return null;
            uint8[] mk = new uint8[32];
            Memory.copy(mk, (uint8*) b + off, 32);
            off += 32;
            sc.skipped[idx] = new Bytes(mk);
        }
        return sc;
    }
}

}
