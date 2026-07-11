namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

// Tests for the §11.8 sealed device-state tracker payload/signed-part codecs
// and the queued-enrollment-request signed-part codec. These are pure byte-
// codec tests (no PEP/network involved) — StreamModule's seal/interpret paths
// that build on top of these are exercised via the running app, not here.
class DeviceTrackerTest : Gee.TestCase {

    public DeviceTrackerTest() {
        base("DeviceTracker");
        add_test("payload_roundtrip_no_aik", test_payload_roundtrip_no_aik);
        add_test("payload_roundtrip_with_aik", test_payload_roundtrip_with_aik);
        add_test("payload_roundtrip_empty", test_payload_roundtrip_empty);
        add_test("tracker_signed_part_deterministic", test_tracker_signed_part_deterministic);
        add_test("tracker_signed_part_detects_tamper", test_tracker_signed_part_detects_tamper);
        add_test("enroll_request_signed_part_deterministic", test_enroll_request_signed_part_deterministic);
        add_test("enroll_request_signed_part_detects_tamper", test_enroll_request_signed_part_detects_tamper);
    }

    private static uint8[] bytes_to_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }

    private void test_payload_roundtrip_no_aik() {
        var payload = new DeviceTrackerPayload();
        var d1 = new DeviceTrackerDevice();
        d1.device_id = 42;
        d1.cert_bytes = { 1, 2, 3, 4, 5 };
        payload.devices.add(d1);
        var d2 = new DeviceTrackerDevice();
        d2.device_id = 7;
        d2.cert_bytes = new uint8[0];
        payload.devices.add(d2);
        payload.dag_heads.add(new Bytes(new uint8[32]));

        uint8[] marshalled = payload.marshal();
        DeviceTrackerPayload? parsed = DeviceTrackerPayload.unmarshal(marshalled);
        assert(parsed != null);
        assert(((!) parsed).devices.size == 2);
        assert(((!) parsed).devices[0].device_id == 42);
        assert(((!) parsed).devices[0].cert_bytes.length == 5);
        assert(((!) parsed).devices[1].device_id == 7);
        assert(((!) parsed).devices[1].cert_bytes.length == 0);
        assert(((!) parsed).dag_heads.size == 1);
        assert(((!) parsed).aik_priv_ed25519 == null);
        assert(((!) parsed).aik_priv_mldsa == null);
    }

    private void test_payload_roundtrip_with_aik() {
        var payload = new DeviceTrackerPayload();
        var d1 = new DeviceTrackerDevice();
        d1.device_id = 1;
        d1.cert_bytes = { 9, 9 };
        payload.devices.add(d1);
        uint8[] ed_priv = new uint8[64];
        for (int i = 0; i < ed_priv.length; i++) ed_priv[i] = (uint8) i;
        uint8[] ml_priv = new uint8[4032];
        for (int i = 0; i < ml_priv.length; i++) ml_priv[i] = (uint8) (i * 3);
        payload.aik_priv_ed25519 = new Bytes(ed_priv);
        payload.aik_priv_mldsa = new Bytes(ml_priv);

        uint8[] marshalled = payload.marshal();
        DeviceTrackerPayload? parsed = DeviceTrackerPayload.unmarshal(marshalled);
        assert(parsed != null);
        assert(((!) parsed).aik_priv_ed25519 != null);
        assert(((!) parsed).aik_priv_mldsa != null);
        assert(bytes_to_arr((!) ((!) parsed).aik_priv_ed25519).length == ed_priv.length);
        assert(bytes_to_arr((!) ((!) parsed).aik_priv_mldsa).length == ml_priv.length);
        unowned uint8[] got_ed = ((!) ((!) parsed).aik_priv_ed25519).get_data();
        for (int i = 0; i < ed_priv.length; i++) assert(got_ed[i] == ed_priv[i]);
    }

    private void test_payload_roundtrip_empty() {
        var payload = new DeviceTrackerPayload();
        uint8[] marshalled = payload.marshal();
        DeviceTrackerPayload? parsed = DeviceTrackerPayload.unmarshal(marshalled);
        assert(parsed != null);
        assert(((!) parsed).devices.size == 0);
        assert(((!) parsed).dag_heads.size == 0);
        assert(((!) parsed).aik_priv_ed25519 == null);
    }

    private Gee.ArrayList<DeviceTrackerRecipient> make_recipients() {
        var recipients = new Gee.ArrayList<DeviceTrackerRecipient>();
        var r1 = new DeviceTrackerRecipient();
        r1.device_id = 1;
        r1.hdr_bytes = { 1, 2, 3 };
        r1.emk_bytes = { 4, 5, 6, 7 };
        recipients.add(r1);
        var r2 = new DeviceTrackerRecipient();
        r2.device_id = 2;
        r2.hdr_bytes = { 8 };
        r2.emk_bytes = { 9, 9, 9 };
        recipients.add(r2);
        return recipients;
    }

    private void test_tracker_signed_part_deterministic() {
        var r1 = make_recipients();
        var r2 = make_recipients();
        uint8[] ct = { 10, 20, 30 };
        uint8[] sp1 = DeviceTrackerSigned.signed_part(1234, 55, ct, r1);
        uint8[] sp2 = DeviceTrackerSigned.signed_part(1234, 55, ct, r2);
        assert(sp1.length == sp2.length);
        for (int i = 0; i < sp1.length; i++) assert(sp1[i] == sp2[i]);
    }

    private void test_tracker_signed_part_detects_tamper() {
        var recipients = make_recipients();
        uint8[] ct = { 10, 20, 30 };
        uint8[] sp_original = DeviceTrackerSigned.signed_part(1234, 55, ct, recipients);

        // Flip one byte of one recipient's emk — the reconstructed SignedPart
        // MUST differ, exactly as a receiver reconstructing from a tampered
        // wire item would detect a signature mismatch.
        recipients[0].emk_bytes[0] ^= 0xFF;
        uint8[] sp_tampered = DeviceTrackerSigned.signed_part(1234, 55, ct, recipients);
        assert(sp_original.length == sp_tampered.length);
        bool differs = false;
        for (int i = 0; i < sp_original.length; i++) {
            if (sp_original[i] != sp_tampered[i]) { differs = true; break; }
        }
        assert(differs);
    }

    private void test_enroll_request_signed_part_deterministic() {
        uint8[] jid = { 'a', '@', 'b' };
        uint8[] sid = { 1, 2, 3, 4 };
        uint8[] ed = { 5, 6 };
        uint8[] x = { 7, 8 };
        uint8[] ml = { 9, 10 };
        uint8[] sp1 = EnrollRequestSigned.signed_part(99, jid, sid, ed, x, ml);
        uint8[] sp2 = EnrollRequestSigned.signed_part(99, jid, sid, ed, x, ml);
        assert(sp1.length == sp2.length);
        for (int i = 0; i < sp1.length; i++) assert(sp1[i] == sp2[i]);
    }

    private void test_enroll_request_signed_part_detects_tamper() {
        uint8[] jid = { 'a', '@', 'b' };
        uint8[] sid = { 1, 2, 3, 4 };
        uint8[] ed = { 5, 6 };
        uint8[] x = { 7, 8 };
        uint8[] ml = { 9, 10 };
        uint8[] sp_original = EnrollRequestSigned.signed_part(99, jid, sid, ed, x, ml);
        // A different device_id (e.g. an attacker replaying a request under a
        // different device id) MUST produce a different SignedPart.
        uint8[] sp_tampered = EnrollRequestSigned.signed_part(100, jid, sid, ed, x, ml);
        assert(sp_original.length == sp_tampered.length);
        bool differs = false;
        for (int i = 0; i < sp_original.length; i++) {
            if (sp_original[i] != sp_tampered[i]) { differs = true; break; }
        }
        assert(differs);
    }
}

}
