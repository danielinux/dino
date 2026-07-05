// SPDX-License-Identifier: AGPL-3.0-or-later
namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq.Protocol;

class CPaceTest : Gee.TestCase {

    public CPaceTest() {
        base("CPace");
        add_test("roundtrip",                test_roundtrip);
        add_test("wrong_password",           test_wrong_password);
        add_test("confirm_roundtrip",        test_confirm_roundtrip);
        add_test("wrong_tag_rejected",       test_wrong_tag_rejected);
        add_test("low_order_rejected",       test_low_order_rejected);
        add_test("process_short_msg_rejected", test_process_short_msg_rejected);
        add_test("hash_to_curve_interop",    test_hash_to_curve_interop);
    }

    private CPaceContext make_ctx() {
        CPaceContext ctx = CPaceContext();
        ctx.bare_jid            = "alice@example.org";
        ctx.initiator_full_jid  = "alice@example.org/phone";
        ctx.responder_full_jid  = "alice@example.org/laptop";
        ctx.server_domain       = "example.org";
        ctx.initiator_aik_pub   = { 0x01, 0x02, 0x03, 0x04 };
        ctx.responder_aik_pub   = { 0x05, 0x06, 0x07, 0x08 };
        ctx.purpose             = "pairing";
        return ctx;
    }

    private uint8[] make_sid() {
        return { 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    }

    private void test_roundtrip() {
        try {
            uint8[] password = "correct horse battery staple".data;
            uint8[] sid      = make_sid();
            CPaceContext ctx = make_ctx();

            CPaceState initiator = CPaceState.create(CPaceRole.INITIATOR, password, sid, ctx);
            CPaceState responder = CPaceState.create(CPaceRole.RESPONDER, password, sid, ctx);

            uint8[] yi = initiator.message1();
            uint8[] yr = responder.message1();

            uint8[] ki = initiator.process(yr);
            uint8[] kr = responder.process(yi);

            fail_if_not_eq_uint8_arr(ki, kr, "roundtrip: session keys must match");
        } catch (Error e) {
            fail_if_reached("roundtrip threw: " + e.message);
        }
    }

    private void test_wrong_password() {
        try {
            uint8[] pwd_i    = "correct horse battery staple".data;
            uint8[] pwd_r    = "wrong password".data;
            uint8[] sid      = make_sid();
            CPaceContext ctx = make_ctx();

            CPaceState initiator = CPaceState.create(CPaceRole.INITIATOR, pwd_i, sid, ctx);
            CPaceState responder = CPaceState.create(CPaceRole.RESPONDER, pwd_r, sid, ctx);

            uint8[] yi = initiator.message1();
            uint8[] yr = responder.message1();

            uint8[] ki = initiator.process(yr);
            uint8[] kr = responder.process(yi);

            /* Session keys must differ when passwords differ */
            bool equal = (ki.length == kr.length);
            if (equal) {
                uint8 diff = 0;
                for (int i = 0; i < ki.length; i++) {
                    diff |= ki[i] ^ kr[i];
                }
                equal = (diff == 0);
            }
            fail_if(equal, "wrong_password: session keys must differ");
        } catch (Error e) {
            fail_if_reached("wrong_password threw: " + e.message);
        }
    }

    private void test_confirm_roundtrip() {
        try {
            uint8[] password = "test-password".data;
            uint8[] sid      = make_sid();
            CPaceContext ctx = make_ctx();

            CPaceState initiator = CPaceState.create(CPaceRole.INITIATOR, password, sid, ctx);
            CPaceState responder = CPaceState.create(CPaceRole.RESPONDER, password, sid, ctx);

            uint8[] yi = initiator.message1();
            uint8[] yr = responder.message1();

            uint8[] ki = initiator.process(yr);
            uint8[] kr = responder.process(yi);

            /* Initiator confirms → responder verifies */
            uint8[] tag_i = initiator.confirm(ki);
            bool ok_r = responder.verify_confirm(kr, tag_i);
            fail_if_not(ok_r, "confirm_roundtrip: responder failed to verify initiator tag");

            /* Responder confirms → initiator verifies */
            uint8[] tag_r = responder.confirm(kr);
            bool ok_i = initiator.verify_confirm(ki, tag_r);
            fail_if_not(ok_i, "confirm_roundtrip: initiator failed to verify responder tag");
        } catch (Error e) {
            fail_if_reached("confirm_roundtrip threw: " + e.message);
        }
    }

    private void test_wrong_tag_rejected() {
        try {
            uint8[] password = "test-password".data;
            uint8[] sid      = make_sid();
            CPaceContext ctx = make_ctx();

            CPaceState initiator = CPaceState.create(CPaceRole.INITIATOR, password, sid, ctx);
            CPaceState responder = CPaceState.create(CPaceRole.RESPONDER, password, sid, ctx);

            uint8[] yi = initiator.message1();
            uint8[] yr = responder.message1();

            uint8[] ki = initiator.process(yr);
            responder.process(yi);

            /* Feed a random 16-byte tag */
            uint8[] bad_tag = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x99 };
            bool accepted = responder.verify_confirm(ki, bad_tag);
            fail_if(accepted, "wrong_tag_rejected: verify_confirm must return false for bad tag");
        } catch (Error e) {
            fail_if_reached("wrong_tag_rejected threw: " + e.message);
        }
    }

    private void test_low_order_rejected() {
        try {
            uint8[] password = "test-password".data;
            uint8[] sid      = make_sid();
            CPaceContext ctx = make_ctx();

            CPaceState initiator = CPaceState.create(CPaceRole.INITIATOR, password, sid, ctx);
            initiator.message1();

            /* Use the all-zeros low-order point */
            uint8[] lop = new uint8[32];
            initiator.process(lop);
            fail_if_reached("low_order_rejected: process() must throw for low-order point");
        } catch (CPaceError e) {
            fail_if_not_eq_int((int) e.code, (int) CPaceError.BAD_MESSAGE,
                "low_order_rejected: expected BAD_MESSAGE, got: " + e.message);
        } catch (Error e) {
            fail_if_reached("low_order_rejected: unexpected error type: " + e.message);
        }
    }

    private void test_process_short_msg_rejected() {
        try {
            uint8[] password = "test-password".data;
            uint8[] sid      = make_sid();
            CPaceContext ctx = make_ctx();

            CPaceState initiator = CPaceState.create(CPaceRole.INITIATOR, password, sid, ctx);
            initiator.message1();

            uint8[] short_msg = { 0x01, 0x02, 0x03 };
            initiator.process(short_msg);
            fail_if_reached("process_short_msg_rejected: process() must throw for short message");
        } catch (CPaceError e) {
            fail_if_not_eq_int((int) e.code, (int) CPaceError.BAD_MESSAGE,
                "process_short_msg_rejected: expected BAD_MESSAGE, got: " + e.message);
        } catch (Error e) {
            fail_if_reached("process_short_msg_rejected: unexpected error type: " + e.message);
        }
    }

    /* Cross-stack interop: verify hash_to_curve_x25519("", "X3DHPQ-CPace-v1") matches
     * the Go reference output e0be60e06b8236241ebbf304e3dccd0f26d726a318104f347d36e31af34bf46e */
    private void test_hash_to_curve_interop() {
        try {
            uint8[] expected = {
                0xe0, 0xbe, 0x60, 0xe0, 0x6b, 0x82, 0x36, 0x24,
                0x1e, 0xbb, 0xf3, 0x04, 0xe3, 0xdc, 0xcd, 0x0f,
                0x26, 0xd7, 0x26, 0xa3, 0x18, 0x10, 0x4f, 0x34,
                0x7d, 0x36, 0xe3, 0x1a, 0xf3, 0x4b, 0xf4, 0x6e,
            };
            Bytes result = X3dhpq.Crypto.hash_to_curve_x25519(
                new Bytes(new uint8[0]),
                new Bytes("X3DHPQ-CPace-v1".data)
            );
            fail_if_not_eq_uint8_arr(result.get_data(), expected,
                "hash_to_curve_interop: output does not match Go reference vector");
        } catch (Error e) {
            fail_if_reached("hash_to_curve_interop threw: " + e.message);
        }
    }
}

}
