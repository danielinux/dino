using Dino.Entities;
using Qlite;
using Dino.Plugins.X3dhpq;
using Dino.Plugins.X3dhpq.Protocol;
using Xmpp;

namespace X3dhpq.Test {

/* §12.3 AIK retirement pointer — TRANSPORT.
 *
 * The pointer type, its verification and the §13.5c fan-out all pre-date this suite;
 * what did not exist was anything that CALLED them. With no publish, no `+notify`
 * handler and no on-demand fetch, the automatic retirement path could never fire and
 * genesis succession only happened when an admin did it by hand — which left §11.8's
 * and §13.1a.0's claim (a compromised `AIK_priv` holder is reduced to "only the loud
 * path of minting a new genesis identity") true only under manual intervention.
 *
 * The load-bearing test here is accepting_pointer_never_pins_or_admits_successor. It
 * mirrors §13.5c's adversarial test but must be asserted INDEPENDENTLY, because this
 * path reaches RetireMember from the other direction: §13.5c's version proves the FOLD
 * refuses to seat the successor, and this one proves the PAIRWISE consumer refuses to
 * pin it — a client could get the fold right and still quietly re-pin the successor
 * locally, which is the same inversion (whoever steals a key evicts the owner and takes
 * their seat) arriving through the client instead of through the journal.
 */
class RotationTransportTest : Gee.TestCase {

    private string db_path;
    private const string PEER = "peer@example.test";

    /* An ACCOUNT (AIK) plus one DEVICE of it. `fp` is the REAL BLAKE2b-160 of the
     * canonical AIK encoding, because both the §12.3 pin comparison and the §13.5c
     * fingerprint(pointer.old_aik) == retired_aik_fp rule bind to it. */
    private class Id {
        public Bytes ed_pub; public Bytes ed_priv;
        public Bytes ml_pub; public Bytes ml_priv;
        public uint8[] aik_marshaled;
        public uint8[] fp;
        public string fp_hex;
        public uint32 device_id;
        public Bytes dik_ed_pub; public Bytes dik_ed_priv;
        public Bytes dik_ml_pub; public Bytes dik_ml_priv;
        public uint8[] dc;
    }

    private Gee.HashMap<string, Id> registry = new Gee.HashMap<string, Id>();

    public RotationTransportTest() {
        base("RotationTransport");
        // T1 — node + advertisement
        add_test("node_is_advertised_and_named_per_spec", test_node_advertised);
        add_test("rotation_element_pinned_vector", test_rotation_element_vector);
        // T2 — publishing
        add_test("reset_holding_old_aik_priv_mints_a_pointer", test_reset_mints_pointer);
        add_test("reset_without_old_aik_priv_publishes_no_pointer", test_reset_without_priv);
        // T3 — consuming
        add_test("valid_pointer_retires_pin_and_fans_out_retiremember", test_valid_pointer);
        add_test("pointer_with_either_signature_invalid_is_discarded", test_bad_signature);
        add_test("pointer_for_an_unpinned_aik_is_ignored", test_unpinned_aik);
        add_test("redelivered_pointer_is_a_noop", test_redelivery_noop);
        add_test("redelivered_pointer_still_fans_out_to_rooms", test_redelivery_still_fans_out);
        add_test("absence_of_a_pointer_marks_nothing_retired", test_absence_proves_nothing);
        // T4 — what must not happen
        add_test("accepting_pointer_never_pins_or_admits_successor", test_never_admits_successor);
        add_test("own_account_pointer_is_never_acted_on", test_no_self_retire);
    }

    public override void set_up() {
        registry = new Gee.HashMap<string, Id>();
        db_path = GLib.Path.build_filename(GLib.Environment.get_tmp_dir(),
            "x3dhpq-rotation-%u.db".printf(Random.next_int()));
    }

    public override void tear_down() {
        FileUtils.unlink(db_path);
        FileUtils.unlink(db_path + "-shm");
        FileUtils.unlink(db_path + "-wal");
    }

    // ------------------------------------------------------------- T1 ---

    /* The node name is normative and the `+notify` feature must be advertised, or a
     * pointer only ever reaches contacts who happen to poll. The `+notify` half rides
     * Pubsub.add_filtered_notification (→ ServiceDiscovery.add_feature_notify) in
     * StreamModule.attach, which needs a live stream; what is assertable offline — and
     * what a rename would break — is the namespace itself being in the disco set. */
    private void test_node_advertised() {
        fail_if_not_eq_str(Protocol.NS_ROTATION, "urn:xmppqr:x3dhpq:rotation:0",
            "the §12.3 node name is normative and shared with the other client");
        bool found = false;
        foreach (string f in Protocol.get_disco_features()) {
            if (f == Protocol.NS_ROTATION) found = true;
        }
        fail_if_not(found, "the rotation node must be advertised in disco#info");
    }

    /* Cross-client pinned vector for the ELEMENT encoding. Both reference clients must
     * publish a byte-identical `<rotation/>` for the same RotationPointer: the payload
     * is base64 of the wire blob and nothing else, so a stray wrapper, a different
     * element name or a different namespace makes a pointer authored on one client
     * invisible on the other — and invisible is indistinguishable from absent, which
     * §12.3 step 5 says must never be read as evidence of anything. */
    // The three things that must agree ACROSS clients: element name, namespace, and a
    // payload that is base64 of the wire blob and nothing else.
    private const string ROTATION_PAYLOAD_VECTOR =
        "WDNESFBRLVJvdGF0aW9uLXYxAAABAAOqqqoABLu7u7sAAAAAZjExoAACaGkAAhERAAMiIiI=";
    /* The full serialisation, pinned as a Dino-side regression only. Attribute-quote
     * style is a property of this client's StanzaNode writer, not of the protocol, so
     * the other client is NOT expected to emit a byte-identical string here — it is
     * expected to agree on the three assertions above, which is what a parser sees. */
    private const string ROTATION_ELEMENT_SERIALISED =
        "<rotation xmlns='urn:xmppqr:x3dhpq:rotation:0'>"
        + ROTATION_PAYLOAD_VECTOR
        + "</rotation>";

    private void test_rotation_element_vector() {
        try {
            // The same stand-in pointer the §13.5c framing vector pins, so the two
            // vectors are checkable against each other by hand.
            var rp = new RotationPointer();
            rp.version = 1;
            rp.old_aik = new uint8[] { 0xAA, 0xAA, 0xAA };
            rp.new_aik = new uint8[] { 0xBB, 0xBB, 0xBB, 0xBB };
            rp.rotated_at = 1714500000;
            rp.reason = "hi";
            rp.sig_ed25519 = new uint8[] { 0x11, 0x11 };
            rp.sig_mldsa = new uint8[] { 0x22, 0x22, 0x22 };

            StanzaNode node = StreamModule.build_rotation_node(rp.marshal());
            fail_if_not_eq_str(node.name, "rotation", "the element name is normative");
            fail_if_not_eq_str(node.ns_uri, "urn:xmppqr:x3dhpq:rotation:0",
                "the element namespace is normative");
            fail_if_not_eq_str(node.get_string_content() ?? "", ROTATION_PAYLOAD_VECTOR,
                "the payload must be BASE64(RotationPointer) and nothing else");
            fail_if_not_eq_str(node.to_xml(), ROTATION_ELEMENT_SERIALISED,
                "the published <rotation/> element must match the pinned serialisation");

            // ...and it round-trips back to the exact bytes, from the element itself and
            // from a wrapper holding it (the shape the +notify item hands us).
            uint8[]? back = StreamModule.parse_rotation_node(node);
            fail_if(back == null, "the element must parse back");
            fail_if_not_eq_uint8_arr((!) back, rp.marshal(), "and to the exact same bytes");

            StanzaNode wrapper = new StanzaNode.build("item", "http://jabber.org/protocol/pubsub")
                .add_self_xmlns().put_node(node);
            uint8[]? via_wrapper = StreamModule.parse_rotation_node(wrapper);
            fail_if(via_wrapper == null, "a wrapped element must parse too");

            // Absent / malformed input is "nothing", never "a retirement".
            fail_if(StreamModule.parse_rotation_node(null) != null, "null is not a pointer");
            fail_if(StreamModule.parse_rotation_node(
                    new StanzaNode.build("rotation", Protocol.NS_ROTATION).add_self_xmlns()) != null,
                "an empty element is not a pointer");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------------- T2 ---

    /* §12.1 step 4: a reset by a device that STILL HOLDS the old AIK_priv mints a
     * pointer naming old → new, signed by the OLD key under BOTH algorithms. */
    private void test_reset_mints_pointer() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            uint8[] old_ed, old_ml;
            local_aik_pubs(db, a, out old_ed, out old_ml);
            fail_if_not(db.has_local_aik_priv(a), "control: this device holds AIK_priv");

            module.reset_local_identity_for_genesis();

            string? pending = db.get_pending_rotation_pointer(a);
            fail_if(pending == null, "a reset by the AIK_priv holder MUST mint a pointer");
            RotationPointer? p = RotationPointer.unmarshal(Base64.decode((!) pending));
            fail_if(p == null, "the stored pointer must parse");

            // Signed by the OLD key, both halves (RotationPointer.verify checks both
            // against the AIK the pointer itself names).
            fail_if_not(((!) p).verify(),
                "the pointer must verify under BOTH algorithms against the old AIK");

            var old_pub = new AccountIdentityPub();
            old_pub.pub_ed25519 = old_ed; old_pub.pub_mldsa = old_ml;
            fail_if_not_eq_uint8_arr(((!) p).old_aik, old_pub.marshal(),
                "old_aik must be the AIK the account held before the reset");

            uint8[] new_ed, new_ml;
            local_aik_pubs(db, a, out new_ed, out new_ml);
            var new_pub = new AccountIdentityPub();
            new_pub.pub_ed25519 = new_ed; new_pub.pub_mldsa = new_ml;
            fail_if_not_eq_uint8_arr(((!) p).new_aik, new_pub.marshal(),
                "new_aik must be the freshly minted AIK");
            fail_if(hex(old_ed) == hex(new_ed), "control: the reset really did change the AIK");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* THE availability property: a reset by a device that no longer holds the old
     * AIK_priv still SUCCEEDS and simply publishes no pointer.
     *
     * Total device loss is the common reset case — §12.2 names it as the reason the
     * account starts fresh rather than reconstructing the old root — and a paired
     * secondary never holds AIK_priv at all (§E1). Making the pointer a precondition
     * would block the one recovery path §12 exists to provide, for the users who need it
     * most. It is a courtesy, never a requirement. */
    private void test_reset_without_priv() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            // Exactly the state Database.apply_paired_identity leaves a paired secondary
            // in, and the state a device that never held the root key is always in.
            db.account_identity.update()
                .with(db.account_identity.account_id, "=", a.id)
                .set(db.account_identity.aik_priv_ed25519_base64, "")
                .set(db.account_identity.aik_priv_mldsa_base64, "")
                .perform();
            fail_if(db.has_local_aik_priv(a), "control: the old private key is gone");
            uint8[] before_ed, before_ml;
            local_aik_pubs(db, a, out before_ed, out before_ml);

            module.reset_local_identity_for_genesis();

            // The reset itself COMPLETED — a fresh identity exists and is usable...
            fail_if_not(db.has_local_aik_priv(a),
                "the reset must still complete and mint a usable new identity");
            uint8[] after_ed, after_ml;
            local_aik_pubs(db, a, out after_ed, out after_ml);
            fail_if(hex(before_ed) == hex(after_ed), "the AIK must actually have changed");
            fail_if_not(db.is_authorized(a), "and the device must be authorized under it");

            // ...and NO pointer was produced, which is correct rather than an error.
            fail_if(db.get_pending_rotation_pointer(a) != null,
                "a device without the old AIK_priv cannot and MUST NOT publish a pointer");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------------- T3 ---

    /* A valid pointer for a PINNED AIK marks that pin retired and produces the §13.5c
     * kind-1 RetireMember that removes the identity from a room where it is a member.
     *
     * Manager.on_rotation_pointer_accepted needs a live Dino.Application, so the fan-out
     * is exercised in two halves that meet in the middle: the transport is asserted to
     * emit rotation_pointer_accepted carrying the pointer, and the entry the manager
     * builds from exactly that pointer is folded into a real journal. Accepting a
     * pointer pairwise while leaving the identity seated in every shared room is a
     * half-applied retirement — the state in which §11.8's recovery claim silently fails
     * to hold — so both halves have to be shown. */
    private void test_valid_pointer() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id peer = make_id();
            Id successor = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(peer.ed_pub), bytes_to_arr(peer.ml_pub));

            RotationPointer? captured = null;
            module.rotation_pointer_accepted.connect((p) => { captured = p; });

            RotationPointer rp = make_pointer(peer, successor.aik_marshaled, peer.ed_priv, peer.ml_priv);
            fail_if_not(module.consume_rotation_pointer(new Jid(PEER), rp.marshal()),
                "a valid pointer for the pinned AIK must be accepted");

            fail_if_not_eq_str(trust_state(db, a, PEER), "retired",
                "the pinned AIK must be marked RETIRED");
            fail_if(captured == null, "acceptance must reach the §13.5c fan-out");
            fail_if_not_eq_str(hex(((!) captured).old_aik_fp_raw()), peer.fp_hex,
                "the fan-out must name the retired fingerprint");

            /* Second half: the entry Manager.on_rotation_pointer_accepted builds from
             * that captured pointer, folded in a room where the old AIK is a member. */
            Id owner = make_id();
            var g = genesis(owner);
            var add = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(peer.fp), 1001);
            var dag = new MembershipDag();
            dag.ingest(g.marshal()); dag.ingest(add.marshal());
            fail_if_not(dag.recompute(resolver()).members.contains(peer.fp_hex),
                "control: the old AIK starts as a room member");

            uint8[] payload = JournalEntryV2.build_retire_payload(
                ((!) captured).old_aik_fp_raw(),
                (uint8) RetireEvidenceKind.ROTATION_POINTER, ((!) captured).marshal());
            var retire = sign(owner, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER, payload, 1002);
            dag.ingest(retire.marshal());

            DagState st = dag.recompute(resolver());
            fail_if_not(st.retired.contains(peer.fp_hex),
                "the pointer must reach the room and retire the identity there too");
            fail_if(st.members.contains(peer.fp_hex), "and it must leave the member set");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* A pointer with EITHER signature invalid is discarded and changes nothing. Both
     * halves are checked because a single-algorithm gate makes the post-quantum half
     * decorative (§7.7) — and a forged pointer that got through would retire a live
     * identity in every room the receiver shares with it. */
    private void test_bad_signature() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id peer = make_id(); Id forger = make_id(); Id successor = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(peer.ed_pub), bytes_to_arr(peer.ml_pub));

            int fanouts = 0;
            module.rotation_pointer_accepted.connect((p) => { fanouts++; });

            // Ed25519 half forged.
            RotationPointer bad_ed = make_pointer(peer, successor.aik_marshaled,
                forger.ed_priv, peer.ml_priv);
            fail_if(module.consume_rotation_pointer(new Jid(PEER), bad_ed.marshal()),
                "a pointer whose Ed25519 half does not verify must be discarded");

            // ML-DSA half forged — the case a classical-only check waves through.
            RotationPointer bad_ml = make_pointer(peer, successor.aik_marshaled,
                peer.ed_priv, forger.ml_priv);
            fail_if(module.consume_rotation_pointer(new Jid(PEER), bad_ml.marshal()),
                "a pointer whose ML-DSA half is forged must be discarded too");

            // A tampered signed_part under otherwise real signatures.
            RotationPointer good = make_pointer(peer, successor.aik_marshaled,
                peer.ed_priv, peer.ml_priv);
            uint8[] tampered = good.marshal();
            tampered[21] = (uint8) (tampered[21] ^ 0xFF);
            module.consume_rotation_pointer(new Jid(PEER), tampered);

            // Garbage that does not even parse.
            fail_if(module.consume_rotation_pointer(new Jid(PEER), new uint8[] { 1, 2, 3 }),
                "unparseable input must be discarded");

            fail_if_not_eq_str(trust_state(db, a, PEER), "unverified",
                "NOTHING may change on a pointer that fails verification");
            fail_if_not_eq_int(fanouts, 0, "and nothing may reach the §13.5c fan-out");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* §12.3 step 2: a pointer whose old_aik is not the AIK we have pinned is ignored. A
     * pointer naming an identity the receiver never trusted conveys nothing — and
     * honouring one would let any passer-by push arbitrary fingerprints into a state
     * that is permanent and blocks admission. */
    private void test_unpinned_aik() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id pinned = make_id(); Id stranger = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(pinned.ed_pub), bytes_to_arr(pinned.ml_pub));

            int fanouts = 0;
            module.rotation_pointer_accepted.connect((p) => { fanouts++; });

            // Perfectly valid — signed by the key it names — but that key is not ours.
            RotationPointer rp = make_pointer(stranger, make_id().aik_marshaled,
                stranger.ed_priv, stranger.ml_priv);
            fail_if_not(rp.verify(), "control: the pointer is genuinely well-signed");
            fail_if(module.consume_rotation_pointer(new Jid(PEER), rp.marshal()),
                "a pointer naming an AIK we never pinned must be ignored");
            fail_if_not_eq_str(trust_state(db, a, PEER), "unverified", "the pin is untouched");
            fail_if_not_eq_int(fanouts, 0, "and nothing reaches the fan-out");

            // Nor does an owner we have no pin for at all give it a foothold.
            fail_if(module.consume_rotation_pointer(new Jid("nobody@example.test"), rp.marshal()),
                "an owner with no pin at all cannot be retired");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* A re-delivered identical pointer is a NO-OP and raises no new identity-change
     * event. The pointer is a persistent PEP item, so it is re-observed on every single
     * reconnect and re-pushed by `+notify`; if each observation re-fired the prompt the
     * user would be trained to click through the one alarm that matters. */
    private void test_redelivery_noop() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id peer = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(peer.ed_pub), bytes_to_arr(peer.ml_pub));

            int retired_events = 0;
            int rotated_events = 0;
            db.peer_identity_retired.connect((acct, jid, fp) => { retired_events++; });
            db.peer_identity_rotated.connect((acct, jid, fp) => { rotated_events++; });

            RotationPointer rp = make_pointer(peer, make_id().aik_marshaled,
                peer.ed_priv, peer.ml_priv);
            uint8[] wire = rp.marshal();

            module.consume_rotation_pointer(new Jid(PEER), wire);
            module.consume_rotation_pointer(new Jid(PEER), wire);
            module.consume_rotation_pointer(new Jid(PEER), wire);

            fail_if_not_eq_int(retired_events, 1,
                "re-observing the same persistent pointer must notify exactly once");
            fail_if_not_eq_int(rotated_events, 0,
                "and must NEVER raise the §12.2 changed-identity alarm");
            fail_if_not_eq_str(trust_state(db, a, PEER), "retired", "the state is stable");

            /* And the retired pin has stopped being live: a later assertion under it is
             * discarded WITHOUT re-raising an identity-change event, which is exactly
             * the never-re-paired-device-republishing-forever loop §12.3 ends. */
            fail_if_not(db.is_peer_identity_retired(a, PEER),
                "the retired pin must be visible to the manifest/devicelist gates");
            db.flag_peer_devicelist_fork(a, PEER);
            fail_if_not_eq_str(trust_state(db, a, PEER), "retired",
                "a devicelist that no longer verifies under a RETIRED pin must not "
                + "resurrect it as a fresh 'rotated' takeover alarm");
            fail_if_not_eq_int(rotated_events, 0, "and must raise no new event");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* The other half of re-delivery, and the half that must NOT be suppressed.
     *
     * A re-delivered pointer suppresses the local retirement write and the user-visible
     * event — that is the test above — but it MUST STILL reach the §13.5c fan-out. The
     * tempting optimisation is to return early on "already retired" and skip the whole
     * call; it is wrong because ROOMS ARE DISCOVERED OVER TIME. Join a room tomorrow that
     * shares this contact and the fan-out is the only thing that authors the kind-1
     * RetireMember there; short-circuit it today and that room keeps the dead AIK in its
     * member set forever, receiving every rotation. That is the "half-applied retirement"
     * §12.3 names, and the state in which §11.8's recovery claim silently fails to hold.
     *
     * The per-room de-duplication that makes this cheap lives in the fan-out itself
     * (Manager.on_rotation_pointer_accepted skips rooms whose fold already retired the
     * fingerprint), which is where it can see the rooms — not here, where it cannot. */
    private void test_redelivery_still_fans_out() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id peer = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(peer.ed_pub), bytes_to_arr(peer.ml_pub));

            int fanouts = 0;
            int retired_events = 0;
            module.rotation_pointer_accepted.connect((p) => { fanouts++; });
            db.peer_identity_retired.connect((acct, jid, fp) => { retired_events++; });

            RotationPointer rp = make_pointer(peer, make_id().aik_marshaled,
                peer.ed_priv, peer.ml_priv);
            uint8[] wire = rp.marshal();

            // Reconnect, reconnect, reconnect: the pointer is a persistent PEP item.
            for (int i = 0; i < 3; i++) {
                fail_if_not(module.consume_rotation_pointer(new Jid(PEER), wire),
                    "a re-delivered valid pointer is still ACCEPTED, not rejected");
            }

            fail_if_not_eq_int(fanouts, 3,
                "every accepted pointer, re-delivered or not, MUST reach the §13.5c "
                + "fan-out — a room joined later has no other way to learn the retirement");
            fail_if_not_eq_int(retired_events, 1,
                "while the user-visible retirement is still raised exactly once");
            fail_if_not_eq_str(trust_state(db, a, PEER), "retired",
                "and the local state is written once and then stable");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* §12.3 step 5: absence of a pointer is evidence of NOTHING. It is not a liveness
     * signal, and an attacker able to suppress it is exactly the relay the rest of the
     * document already assumes. There must be no "no pointer ⇒ retire" and equally no
     * "no pointer ⇒ still live" branch. */
    private void test_absence_proves_nothing() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id peer = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(peer.ed_pub), bytes_to_arr(peer.ml_pub));

            int fanouts = 0;
            module.rotation_pointer_accepted.connect((p) => { fanouts++; });

            // What an empty node, an absent item and a lost fetch all reduce to.
            fail_if(StreamModule.parse_rotation_node(null) != null,
                "an absent item yields no pointer");
            fail_if(module.consume_rotation_pointer(new Jid(PEER), new uint8[0]),
                "an empty payload retires nobody");

            fail_if_not_eq_str(trust_state(db, a, PEER), "unverified",
                "with no pointer, nothing is retired");
            fail_if(db.is_peer_identity_retired(a, PEER), "and the pin stays live");
            fail_if_not_eq_int(fanouts, 0, "and nothing reaches the fan-out");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // ------------------------------------------------------------- T4 ---

    /* THE security property. Accepting a pointer must NEVER pin or admit `new_aik`.
     *
     * Construct: the thief holds the victim's AIK_priv, mints a fresh identity (a
     * perfectly valid new genesis under the same JID — §12.2 exists precisely because
     * nothing distinguishes that from a real reset) and signs a valid old → new pointer
     * under the stolen key. The retirement lands, and that half is expected and harmless
     * — they could already impersonate the key they retired, so it is at worst a denial
     * of service against someone they could already be.
     *
     * What MUST NOT happen is the second half, and it is asserted on BOTH surfaces:
     * the successor must not become the pairwise pin, and it must not become a room
     * member. §13.5c already asserts the fold half from the journal side; it is repeated
     * here because this path arrives from the other direction — a client could fold
     * correctly and still re-pin the successor locally, which is the same inversion
     * (steal a key, evict the owner, take their seat) reached through the client instead
     * of through the journal.
     */
    private void test_never_admits_successor() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            Id victim = make_id();
            Id attacker_new = make_id();
            db.pin_peer_aik_first_use(a, PEER, bytes_to_arr(victim.ed_pub), bytes_to_arr(victim.ml_pub));
            db.set_peer_aik_verified(a, PEER);   // the user had verified the old identity

            RotationPointer? captured = null;
            module.rotation_pointer_accepted.connect((p) => { captured = p; });

            RotationPointer rp = make_pointer(victim, attacker_new.aik_marshaled,
                victim.ed_priv, victim.ml_priv);
            fail_if_not(rp.verify(),
                "control: the thief's pointer is genuinely valid under the stolen key");
            fail_if_not(module.consume_rotation_pointer(new Jid(PEER), rp.marshal()),
                "the retirement half lands (expected: it retires a key they already hold)");
            fail_if_not_eq_str(trust_state(db, a, PEER), "retired", "the old identity is dead");

            // ── Half 1: the successor is NOT pinned pairwise. ──
            Bytes still_ed, still_ml;
            fail_if_not(db.get_peer_aik_pubs(a, PEER, out still_ed, out still_ml),
                "the owner still has a pin row");
            fail_if_not_eq_uint8_arr(bytes_to_arr(still_ed), bytes_to_arr(victim.ed_pub),
                "ACCEPTING A POINTER MUST NOT RE-PIN THE SUCCESSOR — the pin must still "
                + "be the OLD (now retired) AIK, never the one the pointer names");
            fail_if_not_eq_uint8_arr(bytes_to_arr(still_ml), bytes_to_arr(victim.ml_pub),
                "the ML-DSA half of the pin must be untouched as well");
            fail_if(any_jid_pinned_to(db, a, attacker_new),
                "the successor must not be pinned for ANY jid — §12.2 adoption is "
                + "out-of-band only, and a pointer grants it nothing");

            // ── Half 2: the successor is NOT a member of any room. ──
            Id owner = make_id();
            var g = genesis(owner);
            var add = sign(owner, 1, heads(g.compute_hash()),
                (uint8) MemberAuditActionV2.ADD_MEMBER, mp(victim.fp), 1001);
            uint8[] payload = JournalEntryV2.build_retire_payload(
                ((!) captured).old_aik_fp_raw(),
                (uint8) RetireEvidenceKind.ROTATION_POINTER, ((!) captured).marshal());
            // Authored by the thief, signing as the victim's account — the stolen root
            // lets them do that, and it must still not seat the successor.
            var retire = sign(victim, 2, heads(add.compute_hash()),
                (uint8) MemberAuditActionV2.RETIRE_MEMBER, payload, 1002);
            var dag = new MembershipDag();
            foreach (var e in new JournalEntryV2[]{ g, add, retire }) dag.ingest(e.marshal());
            DagState st = dag.recompute(resolver());

            fail_if_not(st.retired.contains(victim.fp_hex), "the old AIK is retired in the room");
            fail_if(st.members.contains(attacker_new.fp_hex),
                "RETIREMENT MUST NOT ADMIT THE SUCCESSOR — the mechanism has inverted "
                + "into an eviction primitive for whoever stole the key");
            fail_if(st.admins.contains(attacker_new.fp_hex),
                "nor may the successor become an admin");

            // The successor is readable for DISPLAY only, so the user compares the right
            // fingerprint — reading it must not be confusable with trusting it.
            fail_if_not_eq_str(hex(((!) captured).new_aik_fp_raw()), attacker_new.fp_hex,
                "the claimed successor is readable for display");
            fail_if(any_jid_pinned_to(db, a, attacker_new),
                "...and displaying it still pins nothing");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    /* T4 — no self-retire loop. Our own pointer is a persistent item on our own node and
     * comes straight back at us on every reconnect. Acting on it is meaningless in both
     * directions: under the new identity we are not the party being retired, and under
     * the old one we may no longer hold the key. Retirement is something other members
     * do for you. */
    private void test_no_self_retire() {
        try {
            Dino.Plugins.X3dhpq.Database db = new Dino.Plugins.X3dhpq.Database(db_path);
            Account a = account();
            db.ensure_local_identity(a);
            var module = new StreamModule(a, db);

            int fanouts = 0;
            module.rotation_pointer_accepted.connect((p) => { fanouts++; });

            // Our own reset's pointer, replayed back to us from our own node...
            module.reset_local_identity_for_genesis();
            string? pending = db.get_pending_rotation_pointer(a);
            fail_if(pending == null, "control: our reset minted a pointer");
            uint8[] mine = Base64.decode((!) pending);

            fail_if(module.consume_rotation_pointer(a.bare_jid, mine),
                "a pointer for our own account MUST NOT be acted on");

            /* ...and a pointer naming our CURRENT, LIVE AIK relayed under a THIRD
             * PARTY's jid, where we have deliberately pinned that same AIK, so the bare
             * "is this our own jid?" test cannot save us and only the explicit own-AIK
             * check can. Retiring our live identity would sever US from every shared
             * room, so this is the direction that would actually cost something. */
            Row? row = db.get_local_identity(a.id);
            fail_if(row == null, "control: we have a local identity");
            Bytes cur_ed_pub = new Bytes(Base64.decode(((!) row)[db.account_identity.aik_pub_ed25519_base64]));
            Bytes cur_ml_pub = new Bytes(Base64.decode(((!) row)[db.account_identity.aik_pub_mldsa_base64]));
            Bytes cur_ed_priv = new Bytes(Base64.decode(((!) row)[db.account_identity.aik_priv_ed25519_base64]));
            Bytes cur_ml_priv = new Bytes(Base64.decode(((!) row)[db.account_identity.aik_priv_mldsa_base64]));

            var self_pub = new AccountIdentityPub();
            self_pub.pub_ed25519 = bytes_to_arr(cur_ed_pub);
            self_pub.pub_mldsa = bytes_to_arr(cur_ml_pub);
            var self_rp = new RotationPointer();
            self_rp.version = 1;
            self_rp.old_aik = self_pub.marshal();
            self_rp.new_aik = make_id().aik_marshaled;
            self_rp.rotated_at = 1714500000;
            self_rp.reason = "reset";
            uint8[] ssp = self_rp.signed_part();
            self_rp.sig_ed25519 = bytes_to_arr(Crypto.ed25519_sign(cur_ed_priv, new Bytes(ssp)));
            self_rp.sig_mldsa = bytes_to_arr(Crypto.mldsa65_sign(cur_ml_priv, new Bytes(ssp)));
            fail_if_not(self_rp.verify(), "control: the relayed self-pointer is well-signed");

            db.pin_peer_aik_first_use(a, PEER, self_pub.pub_ed25519, self_pub.pub_mldsa);
            fail_if(module.consume_rotation_pointer(new Jid(PEER), self_rp.marshal()),
                "our own live AIK must not be retirable through a relayed third-party node");
            fail_if_not_eq_str(trust_state(db, a, PEER), "unverified",
                "and nothing about that relayed pin may change");

            fail_if_not_eq_int(fanouts, 0, "no self-retirement may reach the fan-out");
        } catch (Error e) { fail_if_reached(e.message); }
    }

    // --------------------------------------------------------- helpers ---

    private Account account() throws GLib.Error {
        Account a = new Account(new Jid("me@example.test"), "pw");
        a.id = 91;
        return a;
    }

    private void local_aik_pubs(Dino.Plugins.X3dhpq.Database db, Account a, out uint8[] ed, out uint8[] ml) {
        ed = new uint8[0]; ml = new uint8[0];
        Row? row = db.get_local_identity(a.id);
        if (row == null) return;
        ed = Base64.decode(((!) row)[db.account_identity.aik_pub_ed25519_base64]);
        ml = Base64.decode(((!) row)[db.account_identity.aik_pub_mldsa_base64]);
    }

    private string trust_state(Dino.Plugins.X3dhpq.Database db, Account a, string bare) {
        Row? r = db.peer_account_identity.select()
            .with(db.peer_account_identity.account_id, "=", a.id)
            .with(db.peer_account_identity.bare_jid, "=", bare)
            .single().row().inner;
        return r == null ? "<no row>" : ((!) r)[db.peer_account_identity.trust_state];
    }

    // Is this identity the pinned AIK of ANY peer row for the account? The security
    // assertion needs "nowhere", not merely "not for this jid".
    private bool any_jid_pinned_to(Dino.Plugins.X3dhpq.Database db, Account a, Id id) {
        string ed_b64 = Base64.encode(bytes_to_arr(id.ed_pub));
        string ml_b64 = Base64.encode(bytes_to_arr(id.ml_pub));
        var rows = db.peer_account_identity.select()
            .with(db.peer_account_identity.account_id, "=", a.id);
        foreach (Row r in rows) {
            if (r[db.peer_account_identity.aik_pub_ed25519_base64] == ed_b64) return true;
            if (r[db.peer_account_identity.aik_pub_mldsa_base64] == ml_b64) return true;
        }
        return false;
    }

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
