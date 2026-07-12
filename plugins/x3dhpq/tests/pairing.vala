// SPDX-License-Identifier: AGPL-3.0-or-later
namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

class PairingTest : Gee.TestCase {

    public PairingTest() {
        base("Pairing");
        add_test("full_roundtrip",        test_full_roundtrip);
        add_test("wrong_code_auth_error", test_wrong_code_auth_error);
        add_test("share_primary",         test_share_primary);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private uint8[] make_sid() throws GLib.Error {
        return global::X3dhpq.Crypto.random_bytes(16).get_data();
    }

    private PairingOptions make_opts(bool share_primary = false, uint8[] state_blob = new uint8[0]) {
        PairingOptions opts = new PairingOptions();
        opts.new_device_id    = 42;
        opts.share_primary    = share_primary;
        opts.state_blob       = state_blob;
        opts.new_device_flags = 0;
        return opts;
    }

    /**
     * Drive both FSMs to completion using in-process message passing.
     *
     * The 9-step exchange:
     *   1. E.step(null)      → PAKE1
     *   2. N.step(PAKE1)     → PAKE2
     *   3. E.step(PAKE2)     → ConfirmE
     *   4. N.step(ConfirmE)  → ConfirmN
     *   5. E.step(ConfirmN)  → null    (WAIT_DIK)
     *   6. N.step(null)      → Payload(DIK)
     *   7. E.step(Payload)   → Payload(issuance)
     *   8. N.step(Payload)   → ACK
     *   9. E.step(ACK)       → null    (DONE)
     */
    private void run_exchange(PairingExisting e, PairingNew n) throws GLib.Error {
        PairingMsg? msg;

        // Step 1: E → PAKE1
        msg = e.step(null);
        fail_if(msg == null, "step1: expected PAKE1, got null");

        // Step 2: N ← PAKE1 → PAKE2
        msg = n.step(msg);
        fail_if(msg == null, "step2: expected PAKE2, got null");

        // Step 3: E ← PAKE2 → ConfirmE
        msg = e.step(msg);
        fail_if(msg == null, "step3: expected ConfirmE, got null");

        // Step 4: N ← ConfirmE → ConfirmN
        msg = n.step(msg);
        fail_if(msg == null, "step4: expected ConfirmN, got null");

        // Step 5: E ← ConfirmN → null (WAIT_DIK)
        msg = e.step(msg);
        fail_if(msg != null, "step5: expected null, got a message");

        // Step 6: N.step(null) → Payload(DIK)
        msg = n.step(null);
        fail_if(msg == null, "step6: expected DIK payload, got null");

        // Step 7: E ← DIK → issuance payload
        msg = e.step(msg);
        fail_if(msg == null, "step7: expected issuance payload, got null");

        // Step 8: N ← issuance → ACK
        msg = n.step(msg);
        fail_if(msg == null, "step8: expected ACK, got null");

        // Step 9: E ← ACK → null (DONE)
        msg = e.step(msg);
        fail_if(msg != null, "step9: expected null, got a message");
    }

    // ── test cases ────────────────────────────────────────────────────────────

    /**
     * Case 1: Full 9-step round trip.
     * Both sides converge; cert.marshal() identical; aik_pub.marshal() identical.
     */
    private void test_full_roundtrip() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            DeviceIdentityKey  dik = DeviceIdentityKey.generate();
            uint8[] sid            = make_sid();
            string code            = "1234567890";  // raw 10-digit string bypassing Luhn

            PairingExisting existing = new PairingExisting(aik, code, sid, make_opts());
            PairingNew      newdev   = new PairingNew(dik, code, sid);

            run_exchange(existing, newdev);

            fail_if_not(existing.is_done(), "existing: expected DONE");
            fail_if_not(newdev.is_done(),   "newdev: expected DONE");

            DeviceCertificate? e_cert = existing.get_issued_cert();
            fail_if(e_cert == null, "existing: issued_cert is null");

            PairingResult? res = newdev.get_result();
            fail_if(res == null, "newdev: result is null");

            // cert.marshal() must be identical
            fail_if_not_eq_uint8_arr(
                ((!) e_cert).marshal(),
                ((!) res).cert.marshal(),
                "cert marshal mismatch"
            );

            // aik_pub.marshal() must be identical
            fail_if_not_eq_uint8_arr(
                aik.public_key().marshal(),
                ((!) res).aik_pub.marshal(),
                "aik_pub marshal mismatch"
            );

            // aik_priv should be null (share_primary=false)
            fail_if(((!) res).aik_priv != null, "aik_priv should be null when share_primary=false");

        } catch (Error e) {
            fail_if_reached("full_roundtrip threw: " + e.message);
        }
    }

    /**
     * Case 2: Wrong code on N side → PairingError.AUTH at step 5
     * (Existing tries to verify N's confirm tag with wrong session key).
     */
    private void test_wrong_code_auth_error() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            DeviceIdentityKey  dik = DeviceIdentityKey.generate();
            uint8[] sid            = make_sid();
            string code_e          = "1234567890";
            string code_n          = "0987654321";   // different code

            PairingExisting existing = new PairingExisting(aik, code_e, sid, make_opts());
            PairingNew      newdev   = new PairingNew(dik, code_n, sid);

            // Steps 1-4: exchange PAKE messages and confirm tags
            PairingMsg? msg;
            msg = existing.step(null);    // → PAKE1
            msg = newdev.step(msg);       // → PAKE2
            msg = existing.step(msg);     // → ConfirmE
            msg = newdev.step(msg);       // → ConfirmN  (with wrong key, verify_confirm will fail)

            // Step 5: existing verifies N's confirm — must throw AUTH
            existing.step(msg);
            fail_if_reached("wrong_code: expected PairingError.AUTH, but step completed");

        } catch (PairingError e) {
            fail_if_not_eq_int((int) e.code, (int) PairingError.AUTH,
                "wrong_code: expected AUTH error, got: " + e.message);
        } catch (Error e) {
            fail_if_reached("wrong_code: unexpected error type: " + e.message);
        }
    }

    /**
     * Case 3 (Trust Manifest Phase 2, §E1): AIK_priv NEVER travels in the issuance
     * payload, even when the caller sets share_primary=true. The confirmer forces
     * share_priv=false, so the newcomer's result.aik_priv MUST be null — the
     * newcomer becomes a member via a DIK-signed manifest ADD, not by adopting the
     * account root key. The account AIK *pub* still travels and is adopted.
     */
    private void test_share_primary() {
        try {
            AccountIdentityKey aik = AccountIdentityKey.generate();
            DeviceIdentityKey  dik = DeviceIdentityKey.generate();
            uint8[] sid            = make_sid();
            string code            = "1234567890";

            PairingExisting existing = new PairingExisting(aik, code, sid, make_opts(true));
            PairingNew      newdev   = new PairingNew(dik, code, sid);

            run_exchange(existing, newdev);

            PairingResult? res = newdev.get_result();
            fail_if(res == null, "share_primary: result is null");

            // §E1: AIK_priv must never be shared, regardless of share_primary.
            fail_if(((!) res).aik_priv != null,
                "Phase 2: aik_priv must be null even when share_primary=true (§E1)");

            // The account AIK pub is still adopted so the manifest genesis verifies.
            fail_if(((!) res).aik_pub == null, "share_primary: aik_pub should still travel");
            fail_if_not_eq_uint8_arr(
                aik.pub_ed25519,
                ((!) res).aik_pub.pub_ed25519,
                "share_primary: aik_pub.pub_ed25519 must match the account AIK"
            );
            fail_if_not_eq_uint8_arr(
                aik.pub_mldsa,
                ((!) res).aik_pub.pub_mldsa,
                "share_primary: aik_pub.pub_mldsa must match the account AIK"
            );

        } catch (Error e) {
            fail_if_reached("share_primary threw: " + e.message);
        }
    }


}

} // namespace X3dhpq.Test
