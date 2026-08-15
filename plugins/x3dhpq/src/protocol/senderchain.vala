// Megolm-style symmetric sender chain matching senderchain.go.
// Wire: epoch(4) | ck_len(4)=32 | ck(32) | next_index(4) | num_skipped(4) | [idx(4) mk_len(4)=32 mk(32)]...
// Step: mk = HMAC-SHA-256(ck, 0x01); next_ck = HMAC-SHA-256(ck, 0x02).

using Gee;

namespace Dino.Plugins.X3dhpq.Protocol {

private const int MAX_SKIPPED = 256;

// A message key derived for a chain index, together with the chain mutation that
// accepting it would imply. Nothing is applied until commit() runs, so a message whose
// AEAD tag does not verify leaves the chain exactly as it was (§13.7).
public class PendingMessageKey : Object {
    public uint8[] message_key { get; private set; }
    private SenderChain chain;
    private bool from_skipped_table;
    private uint32 skipped_index;
    private uint8[]? new_chain_key;
    private uint32 new_next_index;
    private HashMap<uint32, Bytes>? new_skipped;

    public PendingMessageKey.from_skipped(SenderChain chain, uint32 index, uint8[] mk) {
        this.chain = chain;
        this.message_key = mk;
        this.from_skipped_table = true;
        this.skipped_index = index;
    }

    public PendingMessageKey.from_ratchet(SenderChain chain, uint8[] mk, uint8[] new_ck,
                                          uint32 new_next_index, HashMap<uint32, Bytes> new_skipped) {
        this.chain = chain;
        this.message_key = mk;
        this.from_skipped_table = false;
        this.new_chain_key = new_ck;
        this.new_next_index = new_next_index;
        this.new_skipped = new_skipped;
    }

    // Apply the chain mutation. Call ONLY after the ciphertext has authenticated.
    public void commit() {
        if (from_skipped_table) {
            chain.consume_skipped(skipped_index);
            return;
        }
        chain.apply_ratchet((!) new_chain_key, new_next_index, (!) new_skipped);
    }
}

public class SenderChain : Object {
    public uint32 epoch { get; set; }
    public uint8[] chain_key { get; set; }   // 32 bytes
    public uint32 next_index { get; set; }

    /* §13.3a per-epoch sender authentication.
     *  - On our SEND chain, sig_priv is the Ed25519 private key we sign every outgoing
     *    group message with, and sig_pub is the half we advertise in the announcement.
     *  - On a RECV chain only sig_pub is set: the key we verify that sender against.
     * Deliberately NOT derivable from the chain key, which every member holds — that
     * asymmetry is the entire point. */
    public uint8[] sig_priv { get; set; default = new uint8[0]; }
    public uint8[] sig_pub { get; set; default = new uint8[0]; }
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

    // Commit hooks used by PendingMessageKey once a message has authenticated.
    internal void consume_skipped(uint32 index) {
        skipped.unset(index);
    }

    internal void apply_ratchet(uint8[] new_ck, uint32 new_next_index, HashMap<uint32, Bytes> new_skipped) {
        foreach (var entry in new_skipped.entries) {
            skipped[entry.key] = entry.value;
        }
        chain_key = new_ck;
        next_index = new_next_index;
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
    //
    // DEPRECATED for the receive path: this mutates the chain BEFORE the caller has
    // authenticated anything. Use derive_message_key_at() + PendingMessageKey.commit()
    // so the mutation is conditional on the AEAD tag verifying (§13.7).
    public uint8[]? message_key_at(uint32 target) throws GLib.Error {
        PendingMessageKey? pending = derive_message_key_at(target);
        if (pending == null) return null;
        ((!) pending).commit();
        return ((!) pending).message_key;
    }

    // Derive the message key for `target` WITHOUT mutating the chain. The caller
    // authenticates the ciphertext first and only then calls commit().
    //
    // The chain ratchet is one-way — next_index never moves backwards — and the group
    // message header, including chain_index, is plaintext and unauthenticated until the
    // AEAD tag is checked. Advancing first therefore made the chain state writable by
    // anyone able to place a group stanza in the room, member or not: repeated forged
    // messages with rising indices walk next_index past the genuine sender's position,
    // after which every real message from that sender is permanently rejected as
    // "already advanced past". MAX_SKIPPED does not prevent this, because it bounds the
    // work of a single call, not the cumulative advance across calls. Forged messages
    // that consume cached skipped keys destroy genuine out-of-order messages the same way.
    public PendingMessageKey? derive_message_key_at(uint32 target) throws GLib.Error {
        if (skipped.has_key(target)) {
            // Peek only — the entry is removed in commit().
            return new PendingMessageKey.from_skipped(this, target, bytes_to_uint8_array(skipped[target]));
        }
        if (target < next_index) {
            throw new IOError.FAILED("senderchain: requested index already advanced past");
        }
        var pending_skipped = new Gee.HashMap<uint32, Bytes>();
        uint8[] ck = chain_key.copy();
        uint32 index = next_index;
        while (index < target) {
            if (skipped.size + pending_skipped.size >= MAX_SKIPPED) {
                throw new IOError.FAILED("senderchain: too many skipped keys");
            }
            uint8[] mk = bytes_to_uint8_array(
                global::X3dhpq.Crypto.hmac_sha256(new Bytes(ck), new Bytes({ 0x01 })));
            ck = bytes_to_uint8_array(
                global::X3dhpq.Crypto.hmac_sha256(new Bytes(ck), new Bytes({ 0x02 })));
            pending_skipped[index] = new Bytes(mk);
            index++;
        }
        uint8[] final_mk = bytes_to_uint8_array(
            global::X3dhpq.Crypto.hmac_sha256(new Bytes(ck), new Bytes({ 0x01 })));
        uint8[] final_ck = bytes_to_uint8_array(
            global::X3dhpq.Crypto.hmac_sha256(new Bytes(ck), new Bytes({ 0x02 })));
        return new PendingMessageKey.from_ratchet(this, final_mk, final_ck, index + 1, pending_skipped);
    }

    // Wire format matching senderchain.go Marshal.
    public uint8[] marshal() {
        uint32 num_skipped = (uint32) skipped.size;
        /* Trailing: uint16 sig_priv_len | sig_priv | uint16 sig_pub_len | sig_pub (§13.3a).
         * Persisting the signing key matters: losing it across a restart would leave us
         * unable to sign in an epoch we have already announced ourselves for, and peers
         * hold the advertised public key and would reject everything we sent afterwards. */
        int size = 4 + 4 + 32 + 4 + 4 + (int) num_skipped * (4 + 4 + 32)
                 + 2 + sig_priv.length + 2 + sig_pub.length;
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

        buf[off++] = (uint8)((sig_priv.length >> 8) & 0xff);
        buf[off++] = (uint8)(sig_priv.length & 0xff);
        if (sig_priv.length > 0) {
            Memory.copy((uint8*) buf + off, sig_priv, sig_priv.length);
            off += sig_priv.length;
        }
        buf[off++] = (uint8)((sig_pub.length >> 8) & 0xff);
        buf[off++] = (uint8)(sig_pub.length & 0xff);
        if (sig_pub.length > 0) {
            Memory.copy((uint8*) buf + off, sig_pub, sig_pub.length);
            off += sig_pub.length;
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

        /* §13.3a signing key. A chain persisted before this field existed simply has no
         * trailing bytes; it is restored without a key and the caller must re-key or
         * re-announce before sending, rather than emitting unsigned messages. */
        if (off + 2 <= b.length) {
            int spriv_len = (int) uint16_from_bytes(b, off);
            off += 2;
            if (spriv_len < 0 || off + spriv_len > b.length) return null;
            if (spriv_len > 0) {
                uint8[] spriv = new uint8[spriv_len];
                Memory.copy(spriv, (uint8*) b + off, spriv_len);
                sc.sig_priv = spriv;
                off += spriv_len;
            }
            if (off + 2 <= b.length) {
                int spub_len = (int) uint16_from_bytes(b, off);
                off += 2;
                if (spub_len < 0 || off + spub_len > b.length) return null;
                if (spub_len > 0) {
                    uint8[] spub = new uint8[spub_len];
                    Memory.copy(spub, (uint8*) b + off, spub_len);
                    sc.sig_pub = spub;
                    off += spub_len;
                }
            }
        }
        return sc;
    }
}

}
