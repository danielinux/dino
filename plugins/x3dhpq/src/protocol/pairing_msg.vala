namespace Dino.Plugins.X3dhpq.Protocol {

public errordomain PairingMsgError {
    MALFORMED
}

public class PairingMsg : GLib.Object {
    public const uint8 TYPE_PAKE1   = 1;
    public const uint8 TYPE_PAKE2   = 2;
    public const uint8 TYPE_CONFIRM = 3;
    public const uint8 TYPE_PAYLOAD = 4;
    public const uint8 TYPE_ACK     = 5;

    public uint8 msg_type { get; private set; }
    public uint8[] payload { get; private set; }

    public PairingMsg(uint8 msg_type, uint8[] payload) {
        this.msg_type = msg_type;
        this.payload = new uint8[payload.length];
        Memory.copy(this.payload, payload, payload.length);
    }

    public uint8[] marshal() {
        uint32 len = (uint32) payload.length;
        uint8[] buf = new uint8[5 + len];
        buf[0] = msg_type;
        buf[1] = (uint8)(len >> 24);
        buf[2] = (uint8)(len >> 16);
        buf[3] = (uint8)(len >> 8);
        buf[4] = (uint8) len;
        Memory.copy((uint8*) buf + 5, payload, len);
        return buf;
    }

    public static PairingMsg unmarshal(uint8[] raw) throws PairingMsgError {
        if (raw.length < 5) {
            throw new PairingMsgError.MALFORMED("buffer too short");
        }
        uint32 len = ((uint32) raw[1] << 24)
                   | ((uint32) raw[2] << 16)
                   | ((uint32) raw[3] << 8)
                   | (uint32) raw[4];
        if ((int) len > raw.length - 5) {
            throw new PairingMsgError.MALFORMED("payload length exceeds buffer");
        }
        uint8[] payload = new uint8[len];
        Memory.copy(payload, (uint8*) raw + 5, len);
        return new PairingMsg(raw[0], payload);
    }
}

}
