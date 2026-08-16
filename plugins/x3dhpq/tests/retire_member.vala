namespace X3dhpq.Test {

using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;

/* §13.5c — genesis succession (`RetireMember`, action 12).
 *
 * The gap: room membership is a set of ACCOUNT AIKs, so when a member performs an
 * account reset (§12 — new AIK, fresh manifest genesis) the room kept listing their OLD
 * AIK as a member forever. That made §11.8's and §13.1a.0's claim — that a compromised
 * AIK_priv holder is left "only the loud path of minting a new genesis identity" — false
 * for groups: the thief's stolen AIK stayed a member and kept receiving every rotation.
 *
 * The design deliberately SPLITS retiring the old identity from admitting the new one,
 * and the split is the whole security argument. Bundled, whoever stole AIK_priv could
 * retire the victim and take their seat in the room. Split, that same attacker can only
 * retire a key they already control — no escalation — while admission still requires an
 * admin who performed the §12.2 out-of-band verification. test_attacker_can_retire_but_
 * not_be_admitted below is the assertion that keeps that true; if it ever passes with
 * the successor admitted, the mechanism has inverted into an eviction primitive for
 * whoever stole the key.
 */
class RetireMemberTest : Gee.TestCase {

    /* An ACCOUNT (AIK) plus one DEVICE of it (DIK + AIK-issued DC). Unlike
     * MembershipDagTest's Id, `fp` here is the REAL BLAKE2b-160 of the canonical AIK
     * encoding, because §13.5c requires fingerprint(pointer.old_aik) to equal
     * retired_aik_fp — a random stand-in fingerprint could never satisfy that. */
    private class Id {
        public Bytes ed_pub; public Bytes ed_priv;
        public Bytes ml_pub; public Bytes ml_priv;
        public uint8[] aik_marshaled;   // AccountIdentityPub.marshal()
        public uint8[] fp;              // 20 raw bytes = blake2b160(aik_marshaled)
        public string fp_hex;
        public uint32 device_id;
        public Bytes dik_ed_pub; public Bytes dik_ed_priv;
        public Bytes dik_ml_pub; public Bytes dik_ml_priv;
        public uint8[] dc;
    }

    private Gee.HashMap<string, Id> registry = new Gee.HashMap<string, Id>();
    private const string ROOM = "room@conference.example.org";

    public RetireMemberTest() {
        base("RetireMember");
        // W1/W2 — fold and authorization
        add_test("valid_kind1_pointer_retires_and_rotates", test_kind1_retires_and_rotates);
        add_test("pointer_signed_by_wrong_key_rejected", test_pointer_wrong_key);
        add_test("pointer_old_aik_mismatch_rejected", test_pointer_old_aik_mismatch);
        add_test("kind1_from_non_admin_member_accepted", test_kind1_non_admin_accepted);
        add_test("kind2_from_non_admin_rejected", test_kind2_non_admin_rejected);
        add_test("kind2_with_evidence_rejected", test_kind2_with_evidence_rejected);
        add_test("replayed_retire_accepted_but_does_not_rotate", test_replay_does_not_rotate);
        add_test("add_member_naming_retired_fp_is_noop", test_add_member_retired_noop);
        add_test("retiring_a_non_member_is_unauthorized", test_retire_non_member);
        // THE security property
        add_test("attacker_can_retire_but_not_be_admitted", test_attacker_can_retire_but_not_be_admitted);
        // W2 — traffic
        add_test("retired_member_refused_at_any_epoch", test_retired_refused_at_any_epoch);
        add_test("retired_recv_chains_dropped_in_every_room", test_retired_chains_dropped_all_rooms);
        // W3/persistence
        add_test("retired_survives_snapshot_roundtrip", test_retired_snapshot_roundtrip);
        add_test("retired_survives_session_restart", test_retired_survives_restart);
        // Byte-exactness (cross-client pinned vectors)
        add_test("retire_payload_pinned_vector", test_retire_payload_vector);
        add_test("snapshot_payload_with_retired_pinned_vector", test_snapshot_payload_vector);
        add_test("rotation_pointer_framing_vector", test_rotation_pointer_vector);
        add_test("rotation_pointer_roundtrip_and_strictness", test_rotation_pointer_roundtrip);
    }

    // ------------------------------------------------------------ W1/W2 ---

    /* A valid kind-1 pointer retires the AIK, and the entry IS rotation-causing: both
     * the epoch and fold_hash move, so epoch_id changes and chains rotate. The rotation
     * is what actually severs the retired identity — bookkeeping alone would leave it
     * holding a chain key that forward-ratchets into every future message key. */
    private void test_kind1_retires_and_rotates() {
        try {
            Id owner = make_id(); Id victim = make_id();
            var g = genesis(owner);
            var add = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(add.marshal());
            DagState before = dag.recompute(resolver());
            fail_if_not(before.members.contains(victim.fp_hex), "victim starts as a member");
            uint32 epoch_before = before.epoch;
            uint64 epoch_id_before = before.epoch_id(ROOM);

            Id successor = make_id();
            RotationPointer rp = make_pointer(victim, successor.aik_marshaled,
                victim.ed_priv, victim.ml_priv);
            var retire = sign(owner, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1002);
            dag.ingest(retire.marshal());

            DagState st = dag.recompute(resolver());
            fail_if(st.members.contains(victim.fp_hex), "a retired AIK must leave the member set");
            fail_if(st.admins.contains(victim.fp_hex), "a retired AIK must leave the admin set");
            fail_if_not(st.retired.contains(victim.fp_hex), "the AIK must enter the retired set");
            fail_if_not_eq_int((int) st.epoch, (int) epoch_before + 1,
                "RetireMember is rotation-causing");
            fail_if(st.epoch_id(ROOM) == epoch_id_before,
                "epoch_id must change so chains rotate (§13.5a)");

            // `retired` is DISTINCT from removed/banned: the successor must not later be
            // fighting removal-wins / fail-closed re-admission (§13.1a).
            fail_if(st.banned.contains(victim.fp_hex), "retired is not banned");

            // The successor named by the pointer is surfaced for DISPLAY only.
            RetiredEvidence? ev = st.retired_evidence.get(victim.fp_hex);
            fail_if(ev == null, "the fold must record how the retirement was evidenced");
            fail_if_not_eq_int((int) ((!) ev).kind, 1, "evidence kind 1");
            fail_if_not_eq_str(((!) ev).successor_fp_hex, successor.fp_hex,
                "the claimed successor is readable for display");
            fail_if(st.members.contains(successor.fp_hex),
                "displaying the successor must not admit it");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* A pointer signed by the wrong key is rejected and the AIK STAYS A MEMBER.
     *
     * This is what makes a kind-1 entry safe to accept from any member: the evidence is
     * re-verified locally against the AIK the ROOM holds for the target, so a member
     * relaying a pointer it forged retires nobody. Trusting the author's word here — the
     * shape this test exists to forbid — would hand every member the power to evict
     * every other. */
    private void test_pointer_wrong_key() {
        try {
            Id owner = make_id(); Id victim = make_id(); Id forger = make_id();
            var g = genesis(owner);
            var add = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            // old_aik correctly names the victim, but the signatures are the forger's.
            var rp = new RotationPointer();
            rp.version = 1;
            rp.old_aik = victim.aik_marshaled;
            rp.new_aik = make_id().aik_marshaled;
            rp.rotated_at = 1714500000;
            rp.reason = "";
            uint8[] sp = rp.signed_part();
            rp.sig_ed25519 = bytes_to_arr(Crypto.ed25519_sign(forger.ed_priv, new Bytes(sp)));
            rp.sig_mldsa = bytes_to_arr(Crypto.mldsa65_sign(forger.ml_priv, new Bytes(sp)));

            var retire = sign(owner, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1002);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, add, retire}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.retired.contains(victim.fp_hex),
                "a pointer signed by the wrong key must not retire anyone");
            fail_if_not(st.members.contains(victim.fp_hex),
                "the target must stay a member when the evidence does not verify");
            fail_if_not_eq_int((int) st.epoch, 1,
                "an unauthorized entry must not advance the epoch");

            /* Only one half of the pointer being wrong is still wrong: BOTH algorithms
             * must verify (§7.7), or the post-quantum half is decorative. */
            var half = new RotationPointer();
            half.version = 1;
            half.old_aik = victim.aik_marshaled;
            half.new_aik = rp.new_aik;
            half.rotated_at = rp.rotated_at;
            half.reason = "";
            uint8[] hsp = half.signed_part();
            half.sig_ed25519 = bytes_to_arr(Crypto.ed25519_sign(victim.ed_priv, new Bytes(hsp)));
            half.sig_mldsa = bytes_to_arr(Crypto.mldsa65_sign(forger.ml_priv, new Bytes(hsp)));
            var retire_half = sign(owner, 3, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, half.marshal()), 1003);
            dag.ingest(retire_half.marshal());
            fail_if(dag.recompute(resolver()).retired.contains(victim.fp_hex),
                "a pointer whose ML-DSA half is forged must be rejected too");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* fingerprint(pointer.old_aik) MUST equal retired_aik_fp.
     *
     * Constructed so the SIGNATURES verify against the retired member's AIK while
     * old_aik names somebody else — which is exactly what an implementation that
     * verified the pointer against the key the pointer itself carries would wave
     * through. Without this rule a pointer issued for one identity is replayable to
     * retire a different one. */
    private void test_pointer_old_aik_mismatch() {
        try {
            Id owner = make_id(); Id victim = make_id(); Id other = make_id();
            var g = genesis(owner);
            var add = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            var rp = new RotationPointer();
            rp.version = 1;
            rp.old_aik = other.aik_marshaled;             // names a DIFFERENT identity
            rp.new_aik = make_id().aik_marshaled;
            rp.rotated_at = 1714500000;
            rp.reason = "";
            uint8[] sp = rp.signed_part();
            // ...but is signed by the VICTIM, so it verifies against the victim's AIK.
            rp.sig_ed25519 = bytes_to_arr(Crypto.ed25519_sign(victim.ed_priv, new Bytes(sp)));
            rp.sig_mldsa = bytes_to_arr(Crypto.mldsa65_sign(victim.ml_priv, new Bytes(sp)));
            fail_if_not(rp.verify_with(victim.ed_pub, victim.ml_pub),
                "control: the signatures do verify against the retired member's AIK");

            var retire = sign(owner, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1002);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, add, retire}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.retired.contains(victim.fp_hex),
                "a pointer whose old_aik is not the retired fingerprint must be rejected");
            fail_if_not(st.members.contains(victim.fp_hex), "the target stays a member");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* kind 1 — ANY CURRENT MEMBER may author. The entry proves itself, so the author
     * vouches for nothing and is only a relay. Requiring adminship would mean a room
     * whose admins are all offline cannot act on evidence every member can check. */
    private void test_kind1_non_admin_accepted() {
        try {
            Id owner = make_id(); Id victim = make_id(); Id plain = make_id();
            var g = genesis(owner);
            var a1 = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);
            var a2 = sign(owner, 2, heads(a1.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(plain.fp), 1002);

            RotationPointer rp = make_pointer(victim, make_id().aik_marshaled,
                victim.ed_priv, victim.ml_priv);
            // `plain` is a member and NOT an admin.
            var retire = sign(plain, 3, heads(a2.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1003);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, a1, a2, retire}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.admins.contains(plain.fp_hex), "control: the author is not an admin");
            fail_if_not(st.retired.contains(victim.fp_hex),
                "a kind-1 entry from a plain member must be accepted");

            // A NON-member still may not: relay authority is membership, not nothing.
            Id outsider = make_id(); Id victim2 = make_id();
            var a3 = sign(owner, 4, heads(retire.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim2.fp), 1004);
            RotationPointer rp2 = make_pointer(victim2, make_id().aik_marshaled,
                victim2.ed_priv, victim2.ml_priv);
            var by_outsider = sign(outsider, 5, heads(a3.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim2.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp2.marshal()), 1005);
            dag.ingest(a3.marshal()); dag.ingest(by_outsider.marshal());
            fail_if(dag.recompute(resolver()).retired.contains(victim2.fp_hex),
                "a non-member must not be able to author a RetireMember");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* kind 2 — witnessed — is OWNER-OR-ADMIN only, because nothing is proved and the
     * entry IS the author's word that they re-verified the successor out of band. */
    private void test_kind2_non_admin_rejected() {
        try {
            Id owner = make_id(); Id victim = make_id(); Id plain = make_id();
            var g = genesis(owner);
            var a1 = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);
            var a2 = sign(owner, 2, heads(a1.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(plain.fp), 1002);

            uint8[] witnessed = JournalEntryV2.build_retire_payload(victim.fp,
                (uint8) RetireEvidenceKind.WITNESSED, new uint8[0]);
            var by_plain = sign(plain, 3, heads(a2.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER, witnessed, 1003);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, a1, a2, by_plain}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.retired.contains(victim.fp_hex),
                "a witnessed retirement from a non-admin must be rejected");
            fail_if_not(st.members.contains(victim.fp_hex), "the target stays a member");

            // The same entry from the owner IS accepted.
            var by_owner = sign(owner, 4, heads(a2.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER, witnessed, 1004);
            dag.ingest(by_owner.marshal());
            DagState st2 = dag.recompute(resolver());
            fail_if_not(st2.retired.contains(victim.fp_hex),
                "a witnessed retirement from an admin must be accepted");
            RetiredEvidence? ev = st2.retired_evidence.get(victim.fp_hex);
            fail_if(ev == null, "evidence recorded");
            fail_if_not_eq_int((int) ((!) ev).kind, 2, "evidence kind 2");
            fail_if_not_eq_str(((!) ev).author_fp_hex, owner.fp_hex,
                "kind 2 must name WHOSE word it is, so the UI can say so");
            fail_if_not_eq_str(((!) ev).successor_fp_hex, "",
                "a witnessed entry names no successor — nothing would bind one");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* kind 2 with a non-zero evidence_len is UNAUTHORIZED, not merely ignored: an
     * unconstrained blob in a slot with no verifier is a smuggling channel. */
    private void test_kind2_with_evidence_rejected() {
        try {
            Id owner = make_id(); Id victim = make_id();
            var g = genesis(owner);
            var a1 = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            uint8[] junk = { 0xDE, 0xAD, 0xBE, 0xEF };
            var bad = sign(owner, 2, heads(a1.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.WITNESSED, junk), 1002);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, a1, bad}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.retired.contains(victim.fp_hex),
                "a witnessed entry carrying evidence must be rejected outright");
            fail_if_not_eq_int((int) st.epoch, 1, "and must not advance the epoch");

            // An unknown evidence kind is unauthorized as well.
            var unknown = sign(owner, 3, heads(a1.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp, 9, new uint8[0]), 1003);
            dag.ingest(unknown.marshal());
            fail_if(dag.recompute(resolver()).retired.contains(victim.fp_hex),
                "an unknown evidence kind must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* Replay guard, same shape as §13.5b: a repeat naming an ALREADY-retired
     * fingerprint is ACCEPTED but is NOT rotation-causing. Letting a replay bump the
     * epoch would burn epoch numbers, and install-once (§13.4a.2) makes every burnt
     * number permanently unusable for a real chain. */
    private void test_replay_does_not_rotate() {
        try {
            Id owner = make_id(); Id victim = make_id();
            var g = genesis(owner);
            var a1 = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);
            RotationPointer rp = make_pointer(victim, make_id().aik_marshaled,
                victim.ed_priv, victim.ml_priv);
            uint8[] payload = JournalEntryV2.build_retire_payload(victim.fp,
                (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal());
            var r1 = sign(owner, 2, heads(a1.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER, payload, 1002);
            // A DISTINCT entry (different lamport/timestamp ⇒ different hash) carrying
            // the very same retirement — what re-observing the persistent PEP item and
            // relaying it again produces.
            var r2 = sign(owner, 3, heads(r1.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER, payload, 1003);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, a1, r1}) dag.ingest(e.marshal());
            DagState first = dag.recompute(resolver());
            uint32 epoch_after_first = first.epoch;
            uint64 id_after_first = first.epoch_id(ROOM);

            dag.ingest(r2.marshal());
            DagState after = dag.recompute(resolver());
            fail_if_not_eq_int((int) after.epoch, (int) epoch_after_first,
                "a replayed RetireMember must not rotate");
            fail_if_not(after.retired.contains(victim.fp_hex), "and the AIK stays retired");
            /* It is ACCEPTED, though — it folds and contributes to fold_hash — so
             * epoch_id moves even while the numeric epoch does not. */
            fail_if(after.epoch_id(ROOM) == id_after_first,
                "an accepted entry still contributes to the fold hash");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* An AddMember naming a retired fingerprint is a NO-OP. The key is retired
     * permanently; the successor joins under its OWN fingerprint. Resurrecting the dead
     * one would undo the rotation that severed it and hand the room straight back to
     * whoever holds it. */
    private void test_add_member_retired_noop() {
        try {
            Id owner = make_id(); Id victim = make_id();
            var g = genesis(owner);
            var a1 = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);
            RotationPointer rp = make_pointer(victim, make_id().aik_marshaled,
                victim.ed_priv, victim.ml_priv);
            var r1 = sign(owner, 2, heads(a1.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1002);
            // The owner (a genuine admin) tries to add the retired key back.
            var readd = sign(owner, 3, heads(r1.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1003);
            var readmin = sign(owner, 4, heads(readd.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_ADMIN, mp(victim.fp), 1004);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, a1, r1, readd, readmin}) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.members.contains(victim.fp_hex),
                "AddMember naming a retired fingerprint must be a no-op");
            fail_if(st.admins.contains(victim.fp_hex),
                "AddAdmin naming a retired fingerprint must be a no-op");
            fail_if_not(st.retired.contains(victim.fp_hex), "retirement is permanent");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* Retiring an fp that is not a current member is UNAUTHORIZED. Without this any
     * fingerprint at all could be pushed into the retired set, and — since retirement is
     * permanent and blocks AddMember — that is a durable denial of admission against
     * someone who was never in the room. */
    private void test_retire_non_member() {
        try {
            Id owner = make_id(); Id stranger = make_id();
            var g = genesis(owner);
            RotationPointer rp = make_pointer(stranger, make_id().aik_marshaled,
                stranger.ed_priv, stranger.ml_priv);
            var retire = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(stranger.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1001);

            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(retire.marshal());
            DagState st = dag.recompute(resolver());
            fail_if(st.retired.contains(stranger.fp_hex),
                "you cannot retire someone who is not in the room");
            fail_if_not_eq_int((int) st.epoch, 0, "and the entry must not rotate");

            // The same holds for a witnessed entry from the owner.
            var w = sign(owner, 2, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(stranger.fp,
                    (uint8) RetireEvidenceKind.WITNESSED, new uint8[0]), 1002);
            dag.ingest(w.marshal());
            fail_if(dag.recompute(resolver()).retired.contains(stranger.fp_hex),
                "a witnessed retirement of a non-member is unauthorized too");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------- THE security property ---

    /* An attacker holding AIK_priv can RETIRE but cannot GET ADMITTED.
     *
     * Construct: the thief holds the victim's AIK_priv. They mint a fresh AIK (a
     * perfectly valid new genesis identity under the same JID — §12.2 exists precisely
     * because nothing distinguishes that from a real reset), sign a valid §12.3
     * RotationPointer old→new under the stolen key, and author a kind-1 RetireMember as
     * the victim's own account (which the stolen root lets them do).
     *
     * Everything they did is cryptographically valid, and the fold accepts it: the old
     * AIK is retired. That is not an escalation — they could already impersonate that
     * key, so retiring it is at worst a denial of service against someone they could
     * already be. What MUST NOT happen is the second half: the new AIK must not become a
     * member. If this test ever passes with the successor admitted, the mechanism has
     * inverted — whoever steals a key can evict the owner and take their seat, and
     * §13.5c has become an attack instead of a recovery.
     */
    private void test_attacker_can_retire_but_not_be_admitted() {
        try {
            Id owner = make_id(); Id victim = make_id();
            var g = genesis(owner);
            var add = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);

            // The thief mints a fresh identity and publishes a genesis for it. Nothing
            // about it is malformed; it is a real, valid new account identity.
            Id attacker_new = make_id();

            // ...and, holding the STOLEN old AIK_priv, signs a valid pointer old→new.
            RotationPointer rp = make_pointer(victim, attacker_new.aik_marshaled,
                victim.ed_priv, victim.ml_priv);
            fail_if_not(rp.verify_with(victim.ed_pub, victim.ml_pub),
                "control: the thief's pointer is genuinely valid under the stolen key");

            // The thief authors the RetireMember AS THE VICTIM'S ACCOUNT — the stolen
            // root lets them mint a device certificate and sign as that account.
            var retire = sign(victim, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER,
                JournalEntryV2.build_retire_payload(victim.fp,
                    (uint8) RetireEvidenceKind.ROTATION_POINTER, rp.marshal()), 1002);

            // ...then immediately tries to seat the new identity, both as a member and
            // as an admin, still signing as the (now retired) victim account.
            var seat = sign(victim, 3, heads(retire.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(attacker_new.fp), 1003);
            var seat_admin = sign(victim, 4, heads(seat.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_ADMIN, mp(attacker_new.fp), 1004);

            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{g, add, retire, seat, seat_admin}) {
                dag.ingest(e.marshal());
            }
            DagState st = dag.recompute(resolver());

            // The retirement lands — the thief can always retire a key they control.
            fail_if_not(st.retired.contains(victim.fp_hex),
                "the stolen identity is retired (this half is expected and harmless)");
            fail_if(st.members.contains(victim.fp_hex), "and leaves the member set");

            // THE assertion. Admission is a separate step and requires an admin who
            // performed the §12.2 out-of-band verification. Nothing here is that.
            fail_if(st.members.contains(attacker_new.fp_hex),
                "RETIREMENT MUST NOT ADMIT THE SUCCESSOR — the mechanism has inverted "
                + "into an eviction primitive for whoever stole the key");
            fail_if(st.admins.contains(attacker_new.fp_hex),
                "nor may the successor become an admin");

            // Belt and braces: even a genuine ADMIN adding the successor is an ordinary
            // AddMember decision, never something the retirement performed for them.
            var by_owner = sign(owner, 5, heads(seat_admin.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(attacker_new.fp), 1005);
            dag.ingest(by_owner.marshal());
            fail_if_not(dag.recompute(resolver()).members.contains(attacker_new.fp_hex),
                "control: admission still works, but only as a deliberate admin action");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------- W2 traffic ---

    /* A retired member's messages are refused at ANY epoch — including one at which
     * they were still a member and for which we hold their chain.
     *
     * Two things are asserted at once. First, the refusal happens: §13.6's per-sender
     * check is what protects the room, since there is no global stale-epoch comparison
     * to fall back on (§13.7a). Second, it presents as REJECT_REMOVED_MEMBER: §13.5c
     * introduces NO new receive decision, so the §19.2.0 decision table is unchanged and
     * the v2 conformance corpus keeps passing untouched. */
    private void test_retired_refused_at_any_epoch() {
        try {
            uint8[] alice_aik = random_aik();
            uint8[] bob_aik = random_aik();

            GroupSession bob = GroupSession.new_session(ROOM, bob_aik, 2);
            bob.add_member(make_member(alice_aik, 1));
            GroupSession alice = GroupSession.new_session(ROOM, alice_aik, 1);
            alice.apply_fold_epoch(bob.epoch, 0x99);
            bob.apply_fold_epoch(bob.epoch, 0x99);

            SenderChainAnnouncement ann = alice.announce_sender_chain();
            bob.accept_sender_chain(ann);
            string alice_fp = ann.aik_fingerprint();

            // Readable while she is a member.
            GroupMessageHeader h0; uint8[] c0; uint8[] s0;
            alice.encrypt(string_to_bytes("before"), out h0, out c0, out s0);
            fail_if_not_eq_uint8_arr(string_to_bytes("before"),
                bob.decrypt(alice_fp, h0, c0, s0), "readable before retirement");

            // Alice's account identity is retired by the room's journal.
            bob.mark_retired(alice_fp);
            fail_if_not(bob.is_retired(alice_fp), "the session records her as retired");
            fail_if(bob.has_member(alice_fp), "and she leaves the member set");

            /* A message at the SAME epoch she was a member at — the one case a
             * stale-epoch comparison would never catch, and the reason §13.6's check is
             * per-sender rather than per-epoch. */
            GroupMessageHeader h1; uint8[] c1; uint8[] s1;
            alice.encrypt(string_to_bytes("after"), out h1, out c1, out s1);
            GroupReceiveOutcome o1 = bob.receive(alice_fp, h1, c1, null, s1,
                GroupDeviceAuthorization.AUTHORIZED);
            fail_if_not(o1.decision == GroupDecision.REJECT_REMOVED_MEMBER,
                "a retired sender must present as sender_removed — §13.5c adds NO new "
                + "receive decision, so the conformance table is unchanged");

            // Including at an epoch she never sent under before.
            alice.apply_fold_epoch(alice.epoch + 5, 0xAB);
            GroupMessageHeader h2; uint8[] c2; uint8[] s2;
            alice.encrypt(string_to_bytes("later epoch"), out h2, out c2, out s2);
            GroupReceiveOutcome o2 = bob.receive(alice_fp, h2, c2, null, s2,
                GroupDeviceAuthorization.AUTHORIZED);
            fail_if_not(o2.decision == GroupDecision.REJECT_REMOVED_MEMBER,
                "refused at a LATER epoch too");

            // A re-announcement from the retired identity is refused as well, so she
            // cannot simply reinstall herself.
            bool refused = false;
            try {
                bob.accept_sender_chain(alice.announce_sender_chain());
            } catch (GLib.Error e) { refused = true; }
            fail_if_not(refused, "a retired identity must not be able to install a new chain");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* Every recv chain held for the retired AIK is dropped — every device of that
     * account, every epoch, in every room.
     *
     * Refusing new messages is not on its own enough: a sender chain key
     * forward-ratchets deterministically (MK = HMAC(CK,0x01), CK' = HMAC(CK,0x02)), so a
     * chain we already installed keeps yielding future message keys regardless of what we
     * refuse at the door. Deleting the state is the operative half. */
    private void test_retired_chains_dropped_all_rooms() {
        try {
            uint8[] alice_aik = random_aik();
            uint8[] carol_aik = random_aik();
            uint8[] bob_aik = random_aik();
            string room_a = "a@conference.example.org";
            string room_b = "b@conference.example.org";

            var rooms = new string[] { room_a, room_b };
            foreach (string room in rooms) {
                GroupSession bob = GroupSession.new_session(room, bob_aik, 2);
                bob.add_member(make_member(alice_aik, 1));
                bob.add_member(make_member(carol_aik, 3));

                // Alice has two devices, each announcing at two different epochs, so the
                // drop has to cover the whole (device × epoch) space and not just the
                // tuple that happens to be current.
                string alice_fp = "";
                foreach (uint32 dev in new uint32[] { 1, 7 }) {
                    foreach (uint32 ep in new uint32[] { 4, 5 }) {
                        GroupSession a = GroupSession.new_session(room, alice_aik, dev);
                        a.apply_fold_epoch(ep, 0x1000 + ep);
                        SenderChainAnnouncement ann = a.announce_sender_chain();
                        bob.accept_sender_chain(ann);
                        alice_fp = ann.aik_fingerprint();
                    }
                }
                // Carol is an ordinary member whose chain must survive.
                GroupSession carol = GroupSession.new_session(room, carol_aik, 3);
                carol.apply_fold_epoch(4, 0x1004);
                SenderChainAnnouncement cann = carol.announce_sender_chain();
                bob.accept_sender_chain(cann);

                fail_if_not_eq_int(bob.recv_chain_count(), 5,
                    "control: four Alice chains plus one Carol chain in " + room);

                bob.mark_retired(alice_fp);
                fail_if_not_eq_int(bob.recv_chain_count(), 1,
                    "every recv chain for the retired AIK must be dropped in " + room);
                fail_if(bob.is_retired(cann.aik_fingerprint()),
                    "an unrelated member must be untouched in " + room);

                // Dropping again is a no-op, so the sweep is safe to run per room.
                fail_if_not_eq_int(bob.drop_recv_chains_for_aik(alice_fp), 0,
                    "the sweep is idempotent in " + room);
            }
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------ W3 / persistence ---

    /* The retired set survives a snapshot round-trip: it is carried in the §13.1c
     * payload, so a late joiner whose MAM history was pruned still converges on it
     * instead of folding a dead identity back into the room. */
    private void test_retired_snapshot_roundtrip() {
        try {
            Id owner = make_id(); Id m1 = make_id(); Id dead = make_id(); Id dead2 = make_id();
            var sp = new SnapshotPayload();
            sp.owner_fp = owner.fp;
            sp.epoch = 9;
            sp.member_fps.add(new Bytes(m1.fp)); sp.member_is_admin.add(false);
            sp.retired_fps.add(new Bytes(dead.fp));
            sp.retired_fps.add(new Bytes(dead2.fp));

            uint8[] payload = JournalEntryV2.build_snapshot_payload(sp);
            SnapshotPayload? back = JournalEntryV2.parse_snapshot_payload(payload);
            fail_if(back == null, "snapshot payload must parse");
            fail_if_not_eq_int(((!) back).retired_fps.size, 2, "both retired fps round-trip");

            // Canonical ordering: ascending by raw byte value, regardless of insert order.
            uint8[] first = ((!) back).retired_fps.get(0).get_data();
            uint8[] second = ((!) back).retired_fps.get(1).get_data();
            fail_if(Memory.cmp(first, second, 20) > 0,
                "retired fingerprints must be encoded ascending so the payload is canonical");

            // ...and it reaches the FOLD through a virtual-genesis snapshot, which is the
            // whole point: a late joiner must not re-admit the dead key.
            var snap = sign(owner, 1, heads(null),
                (uint8) MemberAuditActionV2.SNAPSHOT, payload, 2000);
            var readd = sign(owner, 2, heads(snap.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(dead.fp), 2001);
            var dag = new MembershipDag();
            dag.ingest(snap.marshal()); dag.ingest(readd.marshal());
            DagState st = dag.recompute(resolver());
            fail_if_not(st.retired.contains(dead.fp_hex),
                "a snapshot must import the retired set");
            fail_if(st.members.contains(dead.fp_hex),
                "and a retired fp imported from a snapshot still blocks AddMember");
            fail_if_not(st.members.contains(m1.fp_hex), "control: real members still import");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* The retired set survives a restart: it is persisted in the group session's member
     * state, distinctly from the removed set, so after a reload the identity is still
     * refused AND still shown as retired rather than merely removed. */
    private void test_retired_survives_restart() {
        try {
            uint8[] alice_aik = random_aik();
            uint8[] bob_aik = random_aik();
            GroupSession bob = GroupSession.new_session(ROOM, bob_aik, 2);
            bob.add_member(make_member(alice_aik, 1));
            GroupSession alice = GroupSession.new_session(ROOM, alice_aik, 1);
            alice.apply_fold_epoch(bob.epoch, 0x55);
            bob.apply_fold_epoch(bob.epoch, 0x55);
            SenderChainAnnouncement ann = alice.announce_sender_chain();
            bob.accept_sender_chain(ann);
            string alice_fp = ann.aik_fingerprint();
            bob.mark_retired(alice_fp);

            // Exactly the round-trip Database.store_group_session / load_group_session does.
            string send_state = bob.serialize_send_state();
            string member_state = bob.serialize_member_state() + bob.serialize_recv_chains();
            GroupSession? reloaded = GroupSession.deserialize(ROOM, bob_aik, 2, send_state, member_state);
            fail_if(reloaded == null, "session must reload");

            fail_if_not(((!) reloaded).is_retired(alice_fp),
                "the retired set must survive a restart, distinctly from removed");
            fail_if(((!) reloaded).has_member(alice_fp), "and she is not a member again");

            GroupMessageHeader h; uint8[] c; uint8[] s;
            alice.encrypt(string_to_bytes("after restart"), out h, out c, out s);
            GroupReceiveOutcome o = ((!) reloaded).receive(alice_fp, h, c, null, s,
                GroupDeviceAuthorization.AUTHORIZED);
            fail_if_not(o.decision == GroupDecision.REJECT_REMOVED_MEMBER,
                "a retired sender is still refused after a restart");

            // And an add cannot resurrect her after the reload either.
            ((!) reloaded).add_member(make_member(alice_aik, 1));
            fail_if(((!) reloaded).has_member(alice_fp),
                "retirement is permanent — an add must not resurrect the dead key");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ---------------------------------------- byte-exactness (pinned) ---

    /* Cross-client pinned vector for the §13.5c payload encoding. MUST stay
     * byte-for-byte in sync with PQonversations' RetireMember vector — the two clients
     * fold the same journal, so a one-byte disagreement here is a permanent membership
     * fork, not a cosmetic difference. */
    private const string RETIRE_PAYLOAD_KIND1_VECTOR =
        "abababababababababababababababababababab" +   // retired_aik_fp
        "01" +                                         // evidence_kind = RotationPointer
        "0004" +                                       // evidence_len
        "deadbeef";                                    // evidence
    private const string RETIRE_PAYLOAD_KIND2_VECTOR =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +   // retired_aik_fp
        "02" +                                         // evidence_kind = witnessed
        "0000";                                        // evidence_len MUST be 0

    private void test_retire_payload_vector() {
        try {
            uint8[] fp_ab = fill(20, 0xAB);
            uint8[] ev = { 0xDE, 0xAD, 0xBE, 0xEF };
            uint8[] k1 = JournalEntryV2.build_retire_payload(fp_ab, 1, ev);
            fail_if_not_eq_str(hex(k1), RETIRE_PAYLOAD_KIND1_VECTOR,
                "kind-1 payload must match the cross-client vector");

            uint8[] fp_cd = fill(20, 0xCD);
            uint8[] k2 = JournalEntryV2.build_retire_payload(fp_cd, 2, new uint8[0]);
            fail_if_not_eq_str(hex(k2), RETIRE_PAYLOAD_KIND2_VECTOR,
                "kind-2 payload must match the cross-client vector");
            fail_if_not_eq_int(k2.length, 23, "a witnessed payload is exactly 23 bytes");

            // Round-trip.
            uint8[] got_fp; uint8 got_kind; uint8[] got_ev;
            fail_if_not(JournalEntryV2.parse_retire_payload(k1, out got_fp, out got_kind, out got_ev),
                "kind-1 payload parses");
            fail_if_not_eq_str(hex(got_fp), hex(fp_ab), "fp round-trip");
            fail_if_not_eq_int((int) got_kind, 1, "kind round-trip");
            fail_if_not_eq_uint8_arr(got_ev, ev, "evidence round-trip");

            /* Strict framing: a declared evidence_len that does not match the remaining
             * bytes is a parse failure, so trailing junk cannot ride inside an otherwise
             * valid payload and produce a different link hash on different clients. */
            uint8[] padded = new uint8[k1.length + 1];
            Memory.copy(padded, k1, k1.length);
            fail_if(JournalEntryV2.parse_retire_payload(padded, out got_fp, out got_kind, out got_ev),
                "trailing bytes must not parse");
            fail_if(JournalEntryV2.parse_retire_payload(new uint8[22], out got_fp, out got_kind, out got_ev),
                "a short payload must not parse");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* Cross-client pinned vector for the §13.1c snapshot payload EXTENDED with the
     * retired block. Pins the field order, the uint32 count, and the ascending encoding
     * of the fingerprints (0xFF is inserted first below and must come out last). */
    private const string SNAPSHOT_WITH_RETIRED_VECTOR =
        "1111111111111111111111111111111111111111" +   // owner_fp
        "0000000000000007" +                           // epoch
        "00000002" +                                   // member_count
        "2222222222222222222222222222222222222222" + "01" +
        "3333333333333333333333333333333333333333" + "00" +
        "00000001" +                                   // banned_count
        "4444444444444444444444444444444444444444" + "00000003" +
        "00000002" +                                   // retired_count  (§13.5c)
        "0000000000000000000000000000000000000000" +   // sorted ascending...
        "ffffffffffffffffffffffffffffffffffffffff";

    private void test_snapshot_payload_vector() {
        try {
            var sp = new SnapshotPayload();
            sp.owner_fp = fill(20, 0x11);
            sp.epoch = 7;
            sp.member_fps.add(new Bytes(fill(20, 0x22))); sp.member_is_admin.add(true);
            sp.member_fps.add(new Bytes(fill(20, 0x33))); sp.member_is_admin.add(false);
            sp.banned_fps.add(new Bytes(fill(20, 0x44))); sp.banned_epochs.add(3);
            // Deliberately out of order: the encoder must canonicalise.
            sp.retired_fps.add(new Bytes(fill(20, 0xFF)));
            sp.retired_fps.add(new Bytes(fill(20, 0x00)));

            uint8[] payload = JournalEntryV2.build_snapshot_payload(sp);
            fail_if_not_eq_str(hex(payload), SNAPSHOT_WITH_RETIRED_VECTOR,
                "extended snapshot payload must match the cross-client vector");

            /* The retired block is REQUIRED, not optional: treating a missing one as
             * "nobody retired" would let a truncating relay resurrect a retired identity
             * in every late joiner. */
            uint8[] truncated = new uint8[payload.length - 4 - 40];
            Memory.copy(truncated, payload, truncated.length);
            fail_if(JournalEntryV2.parse_snapshot_payload(truncated) != null,
                "a snapshot payload without the retired block must be rejected");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* §12.3 RotationPointer framing vector. Dino gains this type with §13.5c and it is
     * carried verbatim inside the journal entry, so its framing must match
     * PQonversations' RotationPointer.java byte for byte or every kind-1 entry one client
     * authors is unverifiable on the other. Uses short stand-in fields to pin the
     * FRAMING (prefix, field order, lengths, endianness), not key contents. */
    private const string ROTATION_POINTER_VECTOR =
        "5833444850512d526f746174696f6e2d763100" +   // "X3DHPQ-Rotation-v1\0" (19)
        "0001" +                                     // version
        "0003" + "aaaaaa" +                          // old_aik
        "0004" + "bbbbbbbb" +                        // new_aik
        "00000000663131a0" +                         // rotated_at = 1714500000
        "0002" + "6869" +                            // reason = "hi"
        "0002" + "1111" +                            // sig_ed25519
        "0003" + "222222";                           // sig_mldsa65

    private void test_rotation_pointer_vector() {
        var rp = new RotationPointer();
        rp.version = 1;
        rp.old_aik = new uint8[] { 0xAA, 0xAA, 0xAA };
        rp.new_aik = new uint8[] { 0xBB, 0xBB, 0xBB, 0xBB };
        rp.rotated_at = 1714500000;
        rp.reason = "hi";
        rp.sig_ed25519 = new uint8[] { 0x11, 0x11 };
        rp.sig_mldsa = new uint8[] { 0x22, 0x22, 0x22 };
        fail_if_not_eq_str(hex(rp.marshal()), ROTATION_POINTER_VECTOR,
            "RotationPointer framing must match the cross-client vector");
        // The signed_part is the marshal minus the two trailing signature fields.
        fail_if_not_eq_int(rp.signed_part().length, rp.marshal().length - (2 + 2) - (2 + 3),
            "signed_part excludes both signatures");
    }

    private void test_rotation_pointer_roundtrip() {
        try {
            Id old_id = make_id(); Id new_id = make_id();
            RotationPointer rp = make_pointer(old_id, new_id.aik_marshaled,
                old_id.ed_priv, old_id.ml_priv);
            uint8[] wire = rp.marshal();
            RotationPointer? back = RotationPointer.unmarshal(wire);
            fail_if(back == null, "pointer must unmarshal");
            fail_if_not_eq_uint8_arr(((!) back).marshal(), wire, "marshal round-trips exactly");
            fail_if_not(((!) back).verify(), "a self-consistent pointer verifies");
            fail_if_not_eq_str(hex(((!) back).old_aik_fp_raw()), old_id.fp_hex,
                "old_aik_fp_raw is the canonical §5.4 fingerprint");
            fail_if_not_eq_str(hex(((!) back).new_aik_fp_raw()), new_id.fp_hex,
                "new_aik_fp_raw likewise (display only — it is never admitted)");

            // Malformed input is rejected rather than half-parsed.
            uint8[] bad_prefix = wire.copy();
            bad_prefix[0] = 'Y';
            fail_if(RotationPointer.unmarshal(bad_prefix) != null, "wrong prefix rejected");
            uint8[] truncated = new uint8[wire.length - 5];
            Memory.copy(truncated, wire, truncated.length);
            fail_if(RotationPointer.unmarshal(truncated) != null, "truncated input rejected");
            fail_if(RotationPointer.unmarshal(new uint8[3]) != null, "short input rejected");

            /* A tampered signed_part must not verify. wolfSSL raises SIG_VERIFY_E rather
             * than returning false, so this also pins that the exception is normalised to
             * a plain rejection instead of escaping into the fold. */
            uint8[] tampered = wire.copy();
            tampered[25] = (uint8) (tampered[25] ^ 0xFF);
            RotationPointer? t = RotationPointer.unmarshal(tampered);
            if (t != null) {
                fail_if(((!) t).verify_with(old_id.ed_pub, old_id.ml_pub),
                    "a tampered pointer must be rejected, not raise");
            }
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------------ helpers ---

    private Id make_id() throws GLib.Error {
        Id id = new Id();
        Crypto.generate_ed25519(out id.ed_pub, out id.ed_priv);
        Crypto.generate_mldsa65(out id.ml_pub, out id.ml_priv);
        var pub = new AccountIdentityPub();
        pub.pub_ed25519 = bytes_to_arr(id.ed_pub);
        pub.pub_mldsa = bytes_to_arr(id.ml_pub);
        id.aik_marshaled = pub.marshal();
        id.fp = bytes_to_arr(Crypto.blake2b160(new Bytes(id.aik_marshaled)));
        id.fp_hex = hex(id.fp);
        id.device_id = 1;
        Crypto.generate_ed25519(out id.dik_ed_pub, out id.dik_ed_priv);
        Crypto.generate_mldsa65(out id.dik_ml_pub, out id.dik_ml_priv);
        Bytes dik_x_pub; Bytes dik_x_priv;
        Crypto.generate_x25519(out dik_x_pub, out dik_x_priv);
        var cert = DeviceCertificate.issue(id.device_id, id.dik_ed_pub, dik_x_pub,
            id.dik_ml_pub, id.ed_priv, id.ml_priv, 0);
        id.dc = cert.marshal();
        registry.set(id.fp_hex, id);
        return id;
    }

    private AikResolver resolver() {
        return (fp_hex, out ed, out ml) => {
            Id? id = registry.get(fp_hex);
            if (id == null) { ed = new Bytes(new uint8[0]); ml = new Bytes(new uint8[0]); return false; }
            ed = id.ed_pub; ml = id.ml_pub; return true;
        };
    }

    private RotationPointer make_pointer(Id old_id, uint8[] new_aik_marshaled,
                                         Bytes sign_ed_priv, Bytes sign_ml_priv) throws GLib.Error {
        var rp = new RotationPointer();
        rp.version = 1;
        rp.old_aik = old_id.aik_marshaled;
        rp.new_aik = new_aik_marshaled;
        rp.rotated_at = 1714500000;
        rp.reason = "reset";
        uint8[] sp = rp.signed_part();
        rp.sig_ed25519 = bytes_to_arr(Crypto.ed25519_sign(sign_ed_priv, new Bytes(sp)));
        rp.sig_mldsa = bytes_to_arr(Crypto.mldsa65_sign(sign_ml_priv, new Bytes(sp)));
        return rp;
    }

    private JournalEntryV2 genesis(Id owner) throws GLib.Error {
        return sign(owner, 0, heads(null), (uint8) MemberAuditActionV2.ADD_ADMIN, mp(owner.fp), 1000);
    }

    private JournalEntryV2 sign(Id signer, uint64 lamport, Gee.ArrayList<Bytes> parents,
            uint8 action, uint8[] payload, int64 ts) throws GLib.Error {
        JournalEntryV2 e = new JournalEntryV2();
        e.lamport = lamport;
        e.signer_fp = signer.fp;
        e.issuer_device_id = signer.device_id;
        e.issuer_dc = signer.dc;
        e.parents = parents;
        e.action = action;
        e.payload = payload;
        e.timestamp = ts;
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_arr(Crypto.ed25519_sign(signer.dik_ed_priv, new Bytes(sp)));
        e.mldsa_signature = bytes_to_arr(Crypto.mldsa65_sign(signer.dik_ml_priv, new Bytes(sp)));
        return e;
    }

    private Gee.ArrayList<Bytes> heads(uint8[]? h) {
        var l = new Gee.ArrayList<Bytes>();
        if (h != null) l.add(new Bytes(h));
        return l;
    }

    private uint8[] mp(uint8[] fp) {
        return JournalEntryV2.build_member_payload(fp, 0);
    }

    private static uint8[] fill(int n, uint8 v) {
        uint8[] b = new uint8[n];
        for (int i = 0; i < n; i++) b[i] = v;
        return b;
    }

    private static uint8[] random_aik() throws GLib.Error {
        uint8[] ed = bytes_to_arr(Crypto.random_bytes(32));
        uint8[] ml = bytes_to_arr(Crypto.random_bytes(64));
        uint8[] buf = new uint8[3 + 32 + ml.length];
        buf[0] = 0; buf[1] = 1; buf[2] = 1;
        Memory.copy((uint8*) buf + 3, ed, 32);
        Memory.copy((uint8*) buf + 35, ml, ml.length);
        return buf;
    }

    private static GroupMember make_member(uint8[] aik_bytes, uint32 device_id) {
        GroupMember m = new GroupMember();
        m.aik_pub_bytes = aik_bytes.copy();
        m.device_ids.add(device_id);
        return m;
    }

    private static uint8[] string_to_bytes(string s) {
        return ((uint8[]) s.data).copy();
    }

    private static string hex(uint8[] b) {
        StringBuilder sb = new StringBuilder();
        foreach (uint8 x in b) sb.append_printf("%02x", x);
        return sb.str;
    }

    private static uint8[] bytes_to_arr(Bytes b) {
        unowned uint8[] d = b.get_data();
        uint8[] copy = new uint8[d.length];
        Memory.copy(copy, d, d.length);
        return copy;
    }
}

}
