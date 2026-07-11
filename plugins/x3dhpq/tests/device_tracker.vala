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
        add_test("payload_canonical_vector", test_payload_canonical_vector);
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

    private static uint8[] hex_to_bytes(string hex) {
        uint8[] b = new uint8[hex.length / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (uint8) uint.parse(hex.substring(i * 2, 2), 16);
        }
        return b;
    }

    private void test_payload_roundtrip_no_aik() {
        var payload = new DeviceTrackerPayload();
        payload.owner_aik_fp = new uint8[20];
        var d1 = new DeviceSnapshotDevice();
        d1.device_id = 42;
        d1.cert_bytes = { 1, 2, 3, 4, 5 };
        payload.devices.add(d1);
        var d2 = new DeviceSnapshotDevice();
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
        payload.owner_aik_fp = new uint8[20];
        var d1 = new DeviceSnapshotDevice();
        d1.device_id = 1;
        d1.cert_bytes = { 9, 9 };
        payload.devices.add(d1);
        uint8[] ed_priv = new uint8[32];
        for (int i = 0; i < ed_priv.length; i++) ed_priv[i] = (uint8) i;
        uint8[] ml_priv = new uint8[4032];
        for (int i = 0; i < ml_priv.length; i++) ml_priv[i] = (uint8) (i * 3);
        uint8[] ed_pub = new uint8[32];
        for (int i = 0; i < ed_pub.length; i++) ed_pub[i] = (uint8) (i + 1);
        uint8[] ml_pub = new uint8[1952];
        for (int i = 0; i < ml_pub.length; i++) ml_pub[i] = (uint8) (i * 7);
        payload.aik_priv_ed25519 = new Bytes(ed_priv);
        payload.aik_priv_mldsa = new Bytes(ml_priv);
        payload.aik_pub_ed25519 = ed_pub;
        payload.aik_pub_mldsa = ml_pub;

        uint8[] marshalled = payload.marshal();
        DeviceTrackerPayload? parsed = DeviceTrackerPayload.unmarshal(marshalled);
        assert(parsed != null);
        assert(((!) parsed).aik_priv_ed25519 != null);
        assert(((!) parsed).aik_priv_mldsa != null);
        assert(bytes_to_arr((!) ((!) parsed).aik_priv_ed25519).length == ed_priv.length);
        assert(bytes_to_arr((!) ((!) parsed).aik_priv_mldsa).length == ml_priv.length);
        unowned uint8[] got_ed = ((!) ((!) parsed).aik_priv_ed25519).get_data();
        for (int i = 0; i < ed_priv.length; i++) assert(got_ed[i] == ed_priv[i]);
        unowned uint8[] got_ml = ((!) ((!) parsed).aik_priv_mldsa).get_data();
        for (int i = 0; i < ml_priv.length; i++) assert(got_ml[i] == ml_priv[i]);
    }

    private void test_payload_roundtrip_empty() {
        var payload = new DeviceTrackerPayload();
        payload.owner_aik_fp = new uint8[20];
        uint8[] marshalled = payload.marshal();
        DeviceTrackerPayload? parsed = DeviceTrackerPayload.unmarshal(marshalled);
        assert(parsed != null);
        assert(((!) parsed).devices.size == 0);
        assert(((!) parsed).dag_heads.size == 0);
        assert(((!) parsed).aik_priv_ed25519 == null);
    }

    // Shared cross-client wire vector (§11.8 canonical inner payload). This
    // EXACT hex is also asserted (or documented, if a PQ-side test proved
    // impractical) against PQonversations' X3dhpqService.
    // buildDeviceTrackerPlaintextPayload — a tracker inner plaintext of:
    //   owner_aik_fp = bytes 0x00..0x13 (20 bytes)
    //   epoch = 0
    //   devices = [ (id=1, cert=DE AD BE EF), (id=2, cert=<empty>) ]
    //   dag_heads = [ 32 bytes of 0x01 ]
    //   has_aik_priv = 0 (no AIK case)
    // Domain separator "X3DHPQ-DevTracker-Payload-v1\0" (29 bytes) MUST match
    // X3dhpqService.DEVTRACKER_PAYLOAD_DOMAIN byte-for-byte — this is the
    // literal constant the shipping PQ engine signs/frames with, not the
    // abbreviated "X3DHPQ-DevTracker\0" in the spec prose.
    private void test_payload_canonical_vector() {
        string canonical_vector_hex =
            "5833444850512d446576547261636b65722d5061796c6f61642d763100" +
            "00000034" +
            "000102030405060708090a0b0c0d0e0f10111213" +
            "0000000000000000" +
            "00000002" +
            "00000001" + "00000004" + "deadbeef" +
            "00000002" + "00000000" +
            "00000001" +
            "00000020" + "0101010101010101010101010101010101010101010101010101010101010101" +
            "00";

        var payload = new DeviceTrackerPayload();
        uint8[] fp = new uint8[20];
        for (int i = 0; i < 20; i++) fp[i] = (uint8) i;
        payload.owner_aik_fp = fp;
        var d1 = new DeviceSnapshotDevice();
        d1.device_id = 1;
        d1.cert_bytes = { 0xde, 0xad, 0xbe, 0xef };
        payload.devices.add(d1);
        var d2 = new DeviceSnapshotDevice();
        d2.device_id = 2;
        d2.cert_bytes = new uint8[0];
        payload.devices.add(d2);
        uint8[] head = new uint8[32];
        for (int i = 0; i < 32; i++) head[i] = 0x01;
        payload.dag_heads.add(new Bytes(head));

        uint8[] marshalled = payload.marshal();
        uint8[] expected = hex_to_bytes(canonical_vector_hex);
        assert(marshalled.length == expected.length);
        for (int i = 0; i < expected.length; i++) {
            assert(marshalled[i] == expected[i]);
        }

        // Round-trip through unmarshal() too, so the vector also pins the
        // parse side (a PQ-authored payload must decode identically here).
        DeviceTrackerPayload? parsed = DeviceTrackerPayload.unmarshal(expected);
        assert(parsed != null);
        assert(((!) parsed).devices.size == 2);
        assert(((!) parsed).devices[0].device_id == 1);
        assert(((!) parsed).devices[0].cert_bytes.length == 4);
        assert(((!) parsed).devices[1].device_id == 2);
        assert(((!) parsed).dag_heads.size == 1);
        assert(((!) parsed).aik_priv_ed25519 == null);
        for (int i = 0; i < 20; i++) assert(((!) parsed).owner_aik_fp[i] == fp[i]);
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
        try {
            uint8[] sp1 = DeviceTrackerSigned.signed_part(1234, 55, ct, r1);
            uint8[] sp2 = DeviceTrackerSigned.signed_part(1234, 55, ct, r2);
            assert(sp1.length == sp2.length);
            for (int i = 0; i < sp1.length; i++) assert(sp1[i] == sp2[i]);
        } catch (GLib.Error e) {
            assert_not_reached();
        }
    }

    private void test_tracker_signed_part_detects_tamper() {
        var recipients = make_recipients();
        uint8[] ct = { 10, 20, 30 };
        try {
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
        } catch (GLib.Error e) {
            assert_not_reached();
        }
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
