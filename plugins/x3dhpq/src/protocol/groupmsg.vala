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

    // header.marshal() || room_jid_utf8
    public uint8[] aad(string room_jid) {
        uint8[] hdr = marshal();
        uint8[] jid = string_to_bytes(room_jid);
        return concat_byte_arrays(hdr, jid);
    }
}

}
