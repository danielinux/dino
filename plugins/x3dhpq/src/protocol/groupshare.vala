// SenderChainAnnouncement wire format matching groupshare.go byte-for-byte.
// Layout:
//   uint16 version(=1)
//   uint16 aik_pub_len | <aik_pub bytes>
//   uint32 sender_device_id
//   uint16 room_jid_len | <room_jid UTF-8>
//   uint32 epoch
//   uint32 chain_key_len(=32) | <chain_key 32 bytes>
//   uint32 next_index
//
// The aik_pub bytes are the canonical AccountIdentityPub.Marshal() encoding:
//   uint16 version(=1) | uint8 has_mldsa | 32-byte ed25519_pub | variable mldsa_pub.
// In Vala we store/restore the raw bytes as-is; callers supply pre-marshalled AIK bytes.

namespace Dino.Plugins.X3dhpq.Protocol {

public class SenderChainAnnouncement : Object {
    // Raw canonical encoding of AccountIdentityPub (from peer bundle / identity store).
    public uint8[] sender_aik_pub_bytes { get; set; }
    public uint32 sender_device_id { get; set; }
    public string room_jid { get; set; }
    public uint32 epoch { get; set; }
    public uint8[] chain_key { get; set; }  // 32 bytes
    public uint32 next_index { get; set; }

    // Returns the AIK fingerprint string via blake2b-160 of the AIK bytes
    // encoded as described in account_fingerprint() in util.vala.
    public string aik_fingerprint() throws GLib.Error {
        // aik bytes already contain the canonical encoding including version+flags.
        // We need ed25519 (32 bytes at offset 3) and mldsa remainder to call account_fingerprint.
        // Shorter path: use blake2b-160 directly on the canonical bytes prepended with {0,1,1}.
        // The canonical marshal starts with uint16 version | uint8 has_mldsa | ed25519(32) | mldsa...
        // account_fingerprint encodes as {0,1,1} | ed25519 | mldsa and hashes.
        // Parse the aik bytes ourselves to extract ed25519 and mldsa.
        if (sender_aik_pub_bytes.length < 3 + 32) {
            throw new IOError.FAILED("aik pub too short for fingerprint");
        }
        // version = uint16 at [0:2], has_mldsa = [2], ed25519 = [3:35]
        uint8[] ed = new uint8[32];
        Memory.copy(ed, (uint8*) sender_aik_pub_bytes + 3, 32);
        int mldsa_off = 35;
        int mldsa_len = sender_aik_pub_bytes.length - mldsa_off;
        uint8[] mldsa_bytes = new uint8[mldsa_len];
        if (mldsa_len > 0) {
            Memory.copy(mldsa_bytes, (uint8*) sender_aik_pub_bytes + mldsa_off, mldsa_len);
        }
        return account_fingerprint(new Bytes(ed), new Bytes(mldsa_bytes));
    }

    public uint8[] marshal() {
        uint8[] room_bytes = string_to_bytes(room_jid);
        int size = 2 + 2 + sender_aik_pub_bytes.length + 4 + 2 + room_bytes.length + 4 + 4 + 32 + 4;
        uint8[] buf = new uint8[size];
        int off = 0;

        // version = 1
        buf[off++] = 0; buf[off++] = 1;

        // uint16 aik_pub_len
        uint16 aik_len = (uint16) sender_aik_pub_bytes.length;
        buf[off++] = (uint8)(aik_len >> 8);
        buf[off++] = (uint8) aik_len;
        Memory.copy((uint8*) buf + off, sender_aik_pub_bytes, sender_aik_pub_bytes.length);
        off += sender_aik_pub_bytes.length;

        // uint32 sender_device_id
        buf[off++] = (uint8)(sender_device_id >> 24);
        buf[off++] = (uint8)(sender_device_id >> 16);
        buf[off++] = (uint8)(sender_device_id >> 8);
        buf[off++] = (uint8) sender_device_id;

        // uint16 room_jid_len
        uint16 rlen = (uint16) room_bytes.length;
        buf[off++] = (uint8)(rlen >> 8);
        buf[off++] = (uint8) rlen;
        Memory.copy((uint8*) buf + off, room_bytes, room_bytes.length);
        off += room_bytes.length;

        // uint32 epoch
        buf[off++] = (uint8)(epoch >> 24);
        buf[off++] = (uint8)(epoch >> 16);
        buf[off++] = (uint8)(epoch >> 8);
        buf[off++] = (uint8) epoch;

        // uint32 chain_key_len = 32
        buf[off++] = 0; buf[off++] = 0; buf[off++] = 0; buf[off++] = 32;
        Memory.copy((uint8*) buf + off, chain_key, 32);
        off += 32;

        // uint32 next_index
        buf[off++] = (uint8)(next_index >> 24);
        buf[off++] = (uint8)(next_index >> 16);
        buf[off++] = (uint8)(next_index >> 8);
        buf[off++] = (uint8) next_index;

        return buf;
    }

    public static SenderChainAnnouncement? unmarshal(uint8[] b) {
        if (b.length < 2) return null;
        int off = 0;

        uint16 version = uint16_from_bytes(b, off);
        off += 2;
        if (version != 1) return null;

        if (off + 2 > b.length) return null;
        int aik_len = (int) uint16_from_bytes(b, off);
        off += 2;
        if (off + aik_len > b.length) return null;
        uint8[] aik_bytes = new uint8[aik_len];
        Memory.copy(aik_bytes, (uint8*) b + off, aik_len);
        off += aik_len;

        if (off + 4 > b.length) return null;
        uint32 dev_id = uint32_from_bytes(b, off);
        off += 4;

        if (off + 2 > b.length) return null;
        int room_len = (int) uint16_from_bytes(b, off);
        off += 2;
        if (off + room_len > b.length) return null;
        uint8[] room_bytes = new uint8[room_len];
        Memory.copy(room_bytes, (uint8*) b + off, room_len);
        off += room_len;
        // Null-terminate for Vala string construction.
        uint8[] room_z = new uint8[room_len + 1];
        Memory.copy(room_z, room_bytes, room_len);
        room_z[room_len] = 0;

        if (off + 4 + 4 + 32 + 4 > b.length) return null;
        uint32 ep = uint32_from_bytes(b, off);
        off += 4;
        uint32 ck_len = uint32_from_bytes(b, off);
        off += 4;
        if (ck_len != 32 || off + 32 > b.length) return null;
        uint8[] ck = new uint8[32];
        Memory.copy(ck, (uint8*) b + off, 32);
        off += 32;
        if (off + 4 > b.length) return null;
        uint32 ni = uint32_from_bytes(b, off);

        SenderChainAnnouncement ann = new SenderChainAnnouncement();
        ann.sender_aik_pub_bytes = aik_bytes;
        ann.sender_device_id = dev_id;
        ann.room_jid = (string) room_z;
        ann.epoch = ep;
        ann.chain_key = ck;
        ann.next_index = ni;
        return ann;
    }
}

}
