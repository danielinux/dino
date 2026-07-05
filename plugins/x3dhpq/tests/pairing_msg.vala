namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq.Protocol;

class PairingMsgTest : Gee.TestCase {

    public PairingMsgTest() {
        base("PairingMsg");
        add_test("roundtrip_pake1", test_roundtrip_pake1);
        add_test("roundtrip_empty_payload", test_roundtrip_empty_payload);
        add_test("roundtrip_1024_payload", test_roundtrip_1024_payload);
        add_test("truncated_throws_malformed", test_truncated_throws_malformed);
        add_test("lying_length_throws_malformed", test_lying_length_throws_malformed);
        add_test("marshal_output_length", test_marshal_output_length);
        add_test("marshal_big_endian_length_prefix", test_marshal_big_endian_length_prefix);
    }

    private void test_roundtrip_pake1() {
        try {
            uint8[] orig_payload = { 0xaa, 0xbb };
            PairingMsg msg = new PairingMsg(PairingMsg.TYPE_PAKE1, orig_payload);
            uint8[] wire = msg.marshal();
            PairingMsg restored = PairingMsg.unmarshal(wire);
            fail_if_not_eq_int((int) restored.msg_type, (int) PairingMsg.TYPE_PAKE1, "msg_type mismatch");
            fail_if_not_eq_uint8_arr(restored.payload, orig_payload, "payload mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_roundtrip_empty_payload() {
        try {
            uint8[] orig_payload = new uint8[0];
            PairingMsg msg = new PairingMsg(PairingMsg.TYPE_ACK, orig_payload);
            uint8[] wire = msg.marshal();
            PairingMsg restored = PairingMsg.unmarshal(wire);
            fail_if_not_eq_int((int) restored.msg_type, (int) PairingMsg.TYPE_ACK, "msg_type mismatch");
            fail_if_not_eq_int(restored.payload.length, 0, "payload should be empty");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_roundtrip_1024_payload() {
        try {
            uint8[] orig_payload = new uint8[1024];
            for (int i = 0; i < 1024; i++) {
                orig_payload[i] = (uint8)(i & 0xff);
            }
            PairingMsg msg = new PairingMsg(PairingMsg.TYPE_PAYLOAD, orig_payload);
            uint8[] wire = msg.marshal();
            PairingMsg restored = PairingMsg.unmarshal(wire);
            fail_if_not_eq_int((int) restored.msg_type, (int) PairingMsg.TYPE_PAYLOAD, "msg_type mismatch");
            fail_if_not_eq_uint8_arr(restored.payload, orig_payload, "payload mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_truncated_throws_malformed() {
        uint8[] raw = { 0x01, 0x00 };
        try {
            PairingMsg.unmarshal(raw);
            fail_if_reached("expected MALFORMED for truncated buffer");
        } catch (PairingMsgError e) {
            fail_if_not(e is PairingMsgError, "expected PairingMsgError.MALFORMED");
        } catch (Error e) {
            fail_if_reached("unexpected error type: " + e.message);
        }
    }

    private void test_lying_length_throws_malformed() {
        uint8[] raw = { 0x01, 0x00, 0x00, 0x00, 0x10, 0xaa };
        try {
            PairingMsg.unmarshal(raw);
            fail_if_reached("expected MALFORMED for lying length prefix");
        } catch (PairingMsgError e) {
            fail_if_not(e is PairingMsgError, "expected PairingMsgError.MALFORMED");
        } catch (Error e) {
            fail_if_reached("unexpected error type: " + e.message);
        }
    }

    private void test_marshal_output_length() {
        try {
            uint8[] payload = { 0x01, 0x02, 0x03 };
            PairingMsg msg = new PairingMsg(PairingMsg.TYPE_PAKE2, payload);
            uint8[] wire = msg.marshal();
            fail_if_not_eq_int(wire.length, 5 + payload.length, "marshal output length mismatch");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }

    private void test_marshal_big_endian_length_prefix() {
        try {
            uint8[] payload = { 0xca, 0xfe };
            PairingMsg msg = new PairingMsg(PairingMsg.TYPE_CONFIRM, payload);
            uint8[] wire = msg.marshal();
            uint8[] expected_len_bytes = { 0x00, 0x00, 0x00, 0x02 };
            uint8[] actual_len_bytes = wire[1:5];
            fail_if_not_eq_uint8_arr(actual_len_bytes, expected_len_bytes, "length prefix is not big-endian");
        } catch (Error e) {
            fail_if_reached(e.message);
        }
    }
}

}
