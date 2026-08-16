using Dino.Entities;
using Qlite;
using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;
using Xmpp;

namespace X3dhpq.Test {

/* §13.5c "Two strengths of retirement" (normative) + §12.3 step 3.
 *
 * A retirement is not one flag, and the spec says so in as many words: "Implementations
 * that collapse the two kinds into one 'retired' flag will diverge here — one refusing a
 * peer the other still talks to — so the distinction MUST be carried in whatever state
 * records the retirement."
 *
 *   AUTHORITATIVE — a kind-1 `RetireMember`, or the §12.3 pairwise pointer path. Backed
 *   by a signature made BY THE RETIRED KEY ITSELF. §12.3 step 3 in full: assertions under
 *   that AIK are discarded, and SENDING stops until a successor is verified out of band.
 *
 *   WITNESSED — a kind-2 `RetireMember`. The authoring admin's out-of-band attestation.
 *   Authoritative for ROOM MEMBERSHIP, because that is what an admin has standing to
 *   decide, and for nothing else. Nothing signs it, so it MUST NOT by itself discard the
 *   peer's pairwise assertions or block sending: a mistaken or malicious admin would
 *   otherwise render a peer permanently unreachable to everyone in the room.
 *
 * The tests below are written as PAIRS on purpose. Every one of them has a witnessed arm
 * and an authoritative arm over identical inputs, because the bug this suite exists to
 * catch is not "retirement does nothing" — it is "retirement does the same thing in both
 * cases", which passes any single-arm test.
 */
class RetirementStrengthTest : Gee.TestCase {

    private string db_path;
    private const string PEER = "peer@example.test";

    public RetirementStrengthTest() {
        base("RetirementStrength");
        // 1 — the distinction is carried in the state, and is monotone.
        add_test("two_strengths_are_distinct_states", test_two_strengths_distinct);
        add_test("strength_upgrades_but_never_downgrades", test_strength_monotone);
        // 1 — assertions: only an AUTHORITATIVE retirement discards them.
        add_test("witnessed_retirement_keeps_applying_peer_manifests", test_witnessed_manifest_applies);
        add_test("authoritative_retirement_discards_peer_manifests", test_authoritative_manifest_discarded);
        // 2 — sending.
        add_test("authoritative_retirement_blocks_sending", test_authoritative_blocks_send);
        add_test("witnessed_retirement_never_blocks_sending", test_witnessed_allows_send);
        // 3 — no un-retire on fresh material.
        add_test("fresh_material_under_the_retired_aik_never_un_retires", test_no_unretire_same_aik);
        add_test("a_new_aik_in_a_bundle_never_un_retires", test_no_unretire_new_aik);
        add_test("a_new_aik_is_still_reviewable_after_a_witnessed_retirement", test_witnessed_still_rotates);
    }

    public override void set_up() {
        db_path = GLib.Path.build_filename(GLib.Environment.get_tmp_dir(),
            "x3dhpq-retstrength-%u.db".printf(Random.next_int()));
    }

    public override void tear_down() {
        FileUtils.unlink(db_path);
        FileUtils.unlink(db_path + "-shm");
        FileUtils.unlink(db_path + "-wal");
    }

    // ------------------------------------------------------- the state ---

    /* The two kinds must be TWO STATES, not one flag plus a footnote. Asserted through
     * every reader that matters: the persisted string, the strength enum, the
     * authoritative gate the discard/send paths use, and the UI-facing enum — because a
     * client that distinguishes them in the database and then collapses them at the first
     * accessor has not distinguished them at all. */
    private void test_two_strengths_distinct() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            var peer = new PeerAccount();

            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);

            fail_if_not(db.flag_peer_identity_retired(a, fp, RetirementStrength.WITNESSED),
                "a witnessed retirement must be recorded");
            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "retired_witnessed",
                "a kind-2 retirement MUST NOT be persisted as the authoritative 'retired' "
                + "state — that collapse is exactly what makes the two clients diverge");
            fail_if_not(db.get_peer_retirement_strength(a, PEER) == RetirementStrength.WITNESSED,
                "the strength must read back as WITNESSED");
            fail_if(db.is_peer_identity_retired_authoritative(a, PEER),
                "a witnessed retirement is NOT authoritative: nothing signs it, and it may "
                + "not discard the peer's pairwise assertions or block sending");
            fail_if_not(db.is_peer_identity_retired(a, PEER),
                "it is still SURFACED — the user must be told a member said this");

            // ...and the authoritative arm, over the very same call shape.
            var db2 = new Dino.Plugins.X3dhpq.Database(db_path + "2");
            db2.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp2 = (!) db2.get_peer_aik_fingerprint(a, PEER);
            db2.flag_peer_identity_retired(a, fp2, RetirementStrength.AUTHORITATIVE);
            fail_if_not_eq_str(db2.get_peer_trust_state(a, PEER), "retired",
                "a kind-1 / pointer retirement is the authoritative state");
            fail_if_not(db2.is_peer_identity_retired_authoritative(a, PEER),
                "and it MUST satisfy the gate the discard and send paths read");
            FileUtils.unlink(db_path + "2");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* Monotone, in both directions that matter.
     *
     * UP, because a witnessed entry and a kind-1 relay of the same reset arrive in
     * whatever order the rooms hand them over: an admin who witnesses first and a member
     * who relays the pointer second is an ordinary sequence, and a client stuck at
     * witnessed would keep encrypting to a key it holds signed evidence is dead.
     *
     * DOWN never, because the reverse would let one admin's unsigned word cancel the
     * owner's own signed statement — and §13.5c has no un-retire at all. */
    private void test_strength_monotone() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            var peer = new PeerAccount();
            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);

            int events = 0;
            db.peer_identity_retired.connect((acct, jid, f) => { events++; });

            fail_if_not(db.flag_peer_identity_retired(a, fp, RetirementStrength.WITNESSED),
                "witnessed first");
            fail_if(db.flag_peer_identity_retired(a, fp, RetirementStrength.WITNESSED),
                "a repeat at the same strength changes nothing and must not re-prompt");
            fail_if_not_eq_int(events, 1, "exactly one event so far");

            fail_if_not(db.flag_peer_identity_retired(a, fp, RetirementStrength.AUTHORITATIVE),
                "a signature turning up later MUST upgrade the state");
            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "retired", "now authoritative");
            fail_if_not_eq_int(events, 2, "the upgrade is a real change and is surfaced once");

            fail_if(db.flag_peer_identity_retired(a, fp, RetirementStrength.WITNESSED),
                "a witnessed entry MUST NOT downgrade an authoritative retirement");
            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "retired",
                "unsigned word may never demote a signature by the retired key itself");
            fail_if_not_eq_int(events, 2, "and raises no further event");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // -------------------------------------------------- the assertions ---

    /* THE kind-2 property. A witnessed retirement is one member's attestation, so this
     * receiver's own pairwise relationship with that peer survives it intact: their trust
     * manifest still applies, their devices are still learned, and messages still flow.
     *
     * Reverting the manifest gate to a single "is this peer retired at all" flag fails
     * here and nowhere else — and the failure it models is a peer that one client refuses
     * while the other keeps talking to them, on nothing but an admin's say-so. */
    private void test_witnessed_manifest_applies() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);
            var peer = new PeerAccount();

            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);
            db.flag_peer_identity_retired(a, fp, RetirementStrength.WITNESSED);

            fail_if_not(module.verify_and_apply_manifest(new Jid(PEER), peer.manifest_bytes()),
                "a kind-2 retirement MUST NOT discard the peer's pairwise assertions");
            fail_if_not_eq_int((int) db.get_trust_manifest_version(a, PEER), 1,
                "the manifest was really applied, not merely 'not rejected'");
            fail_if_not_eq_int(db.get_remote_device_ids(a, PEER).size, 1,
                "and its folded device set reached the trust tables");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* The authoritative arm of the same input. §12.3 step 3: an identity the owner has
     * signed a statement against has stopped being live, so later assertions under it are
     * discarded — quietly, raising no fresh identity-change event, because a
     * never-re-paired device republishing under the dead AIK forever is the whole problem
     * §12.3 solves. */
    private void test_authoritative_manifest_discarded() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);
            var peer = new PeerAccount();

            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);

            // Control: without the retirement this exact manifest applies.
            fail_if_not(module.verify_and_apply_manifest(new Jid(PEER), peer.manifest_bytes()),
                "control: the manifest is valid and applies on its own");

            var db2 = new Dino.Plugins.X3dhpq.Database(db_path + "2");
            db2.ensure_local_identity(a);
            var module2 = new StreamModule(a, db2);
            db2.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp2 = (!) db2.get_peer_aik_fingerprint(a, PEER);
            db2.flag_peer_identity_retired(a, fp2, RetirementStrength.AUTHORITATIVE);

            int rotated = 0;
            db2.peer_identity_rotated.connect((acct, jid, f) => { rotated++; });
            fail_if(module2.verify_and_apply_manifest(new Jid(PEER), peer.manifest_bytes()),
                "§12.3 step 3: assertions under an authoritatively retired AIK are discarded");
            fail_if_not_eq_int((int) db2.get_trust_manifest_version(a, PEER), -1,
                "nothing may be persisted from a dead identity");
            fail_if_not_eq_int(rotated, 0,
                "and the discard is QUIET — re-raising the §12.2 alarm for a key we have "
                + "already established is dead is the re-prompt storm §12.3 exists to end");
            FileUtils.unlink(db_path + "2");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------- the sending ---

    /* §12.3 step 3: "The receiver MUST also stop sending to a pointer-retired identity
     * until a successor is verified out of band."
     *
     * This is the item the composer previously got wrong: it froze sending for "rotated"
     * only, and a retirement never passes through "rotated". After a compromise-driven
     * reset the retired key is precisely what the ATTACKER holds, so continuing to
     * encrypt to it delivers plaintext straight to them — the same pause §12.2 applies on
     * suspicion, here on the owner's own signed statement. */
    private void test_authoritative_blocks_send() {
        fail_if(EncryptionListEntry.pairwise_send_block_reason("retired") == null,
            "sending to an AUTHORITATIVELY retired identity MUST be blocked: the old key "
            + "is exactly what a compromise-driven reset leaves in the attacker's hands");
        fail_if(EncryptionListEntry.pairwise_send_block_reason("rotated") == null,
            "control: an unreviewed §12.2 identity change still blocks");
        fail_if_not(EncryptionListEntry.pairwise_send_block_reason("verified") == null,
            "control: a verified identity sends");
        fail_if_not(EncryptionListEntry.pairwise_send_block_reason("unverified") == null,
            "control: first contact is opportunistic, warned but not blocked");
    }

    /* And the kind-2 arm, which is the half that must NOT be blocked. Blocking here would
     * hand any single mistaken or malicious admin a permanent, room-wide denial of
     * service against a peer, with no signature anywhere to justify it — and the peer
     * would be unreachable to everyone who folded that entry while remaining reachable to
     * everyone who did not. */
    private void test_witnessed_allows_send() {
        fail_if_not(EncryptionListEntry.pairwise_send_block_reason("retired_witnessed") == null,
            "a kind-2 witnessed retirement MUST NOT block pairwise sending: it is an "
            + "admin's word about ROOM MEMBERSHIP, and no signature binds it");
    }

    // ----------------------------------------------------- no un-retire ---

    /* §12.3 step 3, normative: "A receiver MUST NOT 'un-retire' an identity because fresh
     * material appears under it — a pointer is signed by the retired key itself, so
     * material signed by that same key is not evidence against it, and treating it as
     * such lets whoever holds the stolen key cancel the owner's recovery simply by
     * continuing to publish."
     *
     * This arm is the literal case: the dead AIK keeps publishing bundles. It is a
     * REGRESSION LOCK rather than a new fix — the identity-update path already carried
     * trust_state forward when the AIK was unchanged, so it held before this work and
     * must keep holding. The arm that needed a new guard is the next test. */
    private void test_no_unretire_same_aik() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            var peer = new PeerAccount();
            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);
            db.flag_peer_identity_retired(a, fp, RetirementStrength.AUTHORITATIVE);

            int rotated = 0;
            db.peer_identity_rotated.connect((acct, jid, f) => { rotated++; });

            // The never-re-paired device, still online, still republishing.
            db.store_bundle_payload(a, PEER, 1001, bundle_node(peer.aik.pub_ed25519, peer.aik.pub_mldsa));

            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "retired",
                "a live bundle under the retired AIK is not evidence the key is alive");
            fail_if_not(db.is_peer_identity_retired_authoritative(a, PEER), "the gate still holds");
            fail_if_not_eq_int(rotated, 0, "and nothing is re-raised");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* The other shape of "fresh material", and the dangerous one: a DIFFERENT AIK turns up
     * in a bundle. The bundle node is exactly what a hostile relay controls, and silently
     * re-pinning over a retired identity would both discard the retirement and hand the
     * successor slot to whoever wrote the node. §12.3 step 4 is explicit that the
     * successor is adopted only by out-of-band re-verification — which still works,
     * because the user-driven accept flow forgets the peer first. */
    private void test_no_unretire_new_aik() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            var peer = new PeerAccount();
            var successor = new PeerAccount();
            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);
            db.flag_peer_identity_retired(a, fp, RetirementStrength.AUTHORITATIVE);

            int rotated = 0;
            db.peer_identity_rotated.connect((acct, jid, f) => { rotated++; });

            db.store_bundle_payload(a, PEER, 2002,
                bundle_node(successor.aik.pub_ed25519, successor.aik.pub_mldsa));

            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "retired",
                "a bundle naming some other AIK must not clear the retirement");
            fail_if_not_eq_int(rotated, 0, "nor raise a §12.2 review as if the pin had moved");
            Bytes pin_ed, pin_ml;
            fail_if_not(db.get_peer_aik_pubs(a, PEER, out pin_ed, out pin_ml), "a pin still exists");
            fail_if_not_eq_uint8_arr(bytes_to_arr(pin_ed), peer.aik.pub_ed25519,
                "and it is still the RETIRED key — the successor is never adopted here (§12.3 step 4)");

            // The out-of-band route is untouched: forget_peer (what accept_peer_aik calls
            // first) drops the row, and the peer is re-learned from scratch.
            db.forget_peer(a, PEER);
            db.store_bundle_payload(a, PEER, 2002,
                bundle_node(successor.aik.pub_ed25519, successor.aik.pub_mldsa));
            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "unverified",
                "an explicit user-driven re-verification must still be able to recover");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* The witnessed arm again: because a kind-2 retirement must not freeze the pairwise
     * relationship, a changed AIK under one is an ORDINARY §12.2 event and must still
     * reach the user as a reviewable identity change. Freezing it here would be the same
     * admin-driven denial of service by another route. */
    private void test_witnessed_still_rotates() {
        try {
            var db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            var peer = new PeerAccount();
            var successor = new PeerAccount();
            db.pin_peer_aik_first_use(a, PEER, peer.aik.pub_ed25519, peer.aik.pub_mldsa);
            string fp = (!) db.get_peer_aik_fingerprint(a, PEER);
            db.flag_peer_identity_retired(a, fp, RetirementStrength.WITNESSED);

            int rotated = 0;
            db.peer_identity_rotated.connect((acct, jid, f) => { rotated++; });
            db.store_bundle_payload(a, PEER, 2002,
                bundle_node(successor.aik.pub_ed25519, successor.aik.pub_mldsa));

            fail_if_not_eq_str(db.get_peer_trust_state(a, PEER), "rotated",
                "under a witnessed retirement a changed AIK is an ordinary §12.2 event");
            fail_if_not_eq_int(rotated, 1, "and the user is asked to review it");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // --------------------------------------------------------- helpers ---

    /* A peer account: an AIK, one device under it, and a minimal but genuinely valid
     * v2 Trust Manifest (genesis-only fold, head signed by that device's DIK). */
    private class PeerAccount {
        public AccountIdentityKey aik;
        public DeviceIdentityKey dik;
        public DeviceCertificate dc;
        private TrustManifest m;

        public PeerAccount() throws GLib.Error {
            aik = AccountIdentityKey.generate();
            dik = DeviceIdentityKey.generate();
            dc = DeviceCertificate.issue(1001,
                new Bytes(dik.pub_ed25519), new Bytes(dik.pub_x25519), new Bytes(dik.pub_mldsa),
                new Bytes(aik.priv_ed25519), new Bytes(aik.priv_mldsa), 0);

            var g = new TrustEntry();
            g.action = TrustEntry.ACTION_ADD;
            g.device_id = 1001;
            g.dc = dc;
            g.author_device_id = 1001;
            g.author_dc_hash = bytes_to_arr(Crypto.sha512(new Bytes(dc.marshal())));
            g.timestamp = 1000;
            uint8[] sp = g.signed_part();
            g.signature = bytes_to_arr(Crypto.ed25519_sign(new Bytes(aik.priv_ed25519), new Bytes(sp)));
            g.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(new Bytes(aik.priv_mldsa), new Bytes(sp)));

            m = new TrustManifest();
            m.aik = aik.public_key();
            m.version = 1;
            m.prev_hash = new uint8[64];
            m.entries = new Gee.ArrayList<TrustEntry>();
            m.entries.add(g);
            m.sign_head(new Bytes(dik.priv_ed25519), new Bytes(dik.priv_mldsa));
        }

        public uint8[] manifest_bytes() { return m.marshal(); }
    }

    // The two AIK halves are all store_bundle_payload needs to reach update_peer_identity,
    // which is the path §12.3 step 3's "fresh material" rule has to hold on.
    private StanzaNode bundle_node(uint8[] aik_ed, uint8[] aik_ml) {
        var node = new StanzaNode.build("bundle", Protocol.NS_BUNDLE).add_self_xmlns();
        node.put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_BUNDLE)
            .put_node(new StanzaNode.text(Base64.encode(aik_ed))));
        node.put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_BUNDLE)
            .put_node(new StanzaNode.text(Base64.encode(aik_ml))));
        return node;
    }

    private Account account() throws GLib.Error {
        Account a = new Account(new Jid("me@example.test"), "pw");
        a.id = 77;
        return a;
    }

    private static uint8[] bytes_to_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }
}

}
