using Dino.Entities;
using Gee;
using Qlite;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Plugins.X3dhpq {

// Lightweight record that tracks an active pairing session registered by the UI dialogs.
private class PairSessionRecord {
    public Jid peer_bare;
    public int role;
    public PairSessionRecord(Jid peer_bare, int role) {
        this.peer_bare = peer_bare;
        this.role = role;
    }
}

public class StreamModule : XmppStreamModule {
    public static Xmpp.ModuleIdentity<StreamModule> IDENTITY = new Xmpp.ModuleIdentity<StreamModule>(Protocol.NS_X3DHPQ, "x3dhpq_stream_module");
    private static Pubsub.PublishOptions PUBLISH_OPTIONS = new Pubsub.PublishOptions()
        .set_persist_items(true)
        .set_access_model(Pubsub.ACCESS_MODEL_OPEN);
    // §11.8 canonical wire format: unlike the devicelist/bundle nodes (meant to
    // be publicly readable), the devtracker node is account-internal state,
    // never read by contacts — matches IqGenerator.generateX3dhpqPublishDevTracker's
    // whitelist (owner-only) access model. Self-fetch (interpret_device_tracker /
    // checkDeviceTrackerForRevocation's Iq addressed to our own bare JID) works
    // regardless: the item owner always has full access to its own PEP node.
    private static Pubsub.PublishOptions TRACKER_PUBLISH_OPTIONS = new Pubsub.PublishOptions()
        .set_persist_items(true)
        .set_max_items("1")
        .set_access_model(Pubsub.ACCESS_MODEL_WHITELIST);
    // Trust Manifest (Phase 2): identical publish semantics to the devicelist
    // node (persist, open access) but pinned to a single retained item
    // (max_items=1), matching §A.
    private static Pubsub.PublishOptions MANIFEST_PUBLISH_OPTIONS = new Pubsub.PublishOptions()
        .set_persist_items(true)
        .set_max_items("1")
        .set_access_model(Pubsub.ACCESS_MODEL_OPEN);
    private HashMap<Jid, Future<ArrayList<int>>> active_devicelist_requests = new HashMap<Jid, Future<ArrayList<int>>>(Jid.hash_func, Jid.equals_func);

    // pair stanza step counters keyed by base64(sid)
    private HashMap<string, uint> pair_step_counters = new HashMap<string, uint>();
    // active pairing sessions registered by the UI dialogs
    private HashMap<string, PairSessionRecord> pair_sessions = new HashMap<string, PairSessionRecord>();
    // per-account audit chain verifier (lazily initialised on first audit event)
    private Protocol.AccountAuditChain? audit_chain = null;

    // XmppStream reference stored at attach() for message-received connection
    private XmppStream? attached_stream = null;

    private Account account;
    private Database db;

    public signal void device_list_loaded(Jid jid, ArrayList<int> devices);
    public signal void bundle_fetched(Jid jid, int device_id, StanzaNode bundle);
    public signal void audit_entry_received(Jid from, string? id, string b64_payload);
    public signal void membership_entry_received(Jid room_jid, string? id, string b64_payload);

    // Emitted when a <pair> message arrives from a peer.
    public signal void pair_message_received(uint8[] sid, Jid from_jid, Protocol.PairingMsg msg);
    // Emitted when a <pair-hello> rendezvous item arrives via self-PEP +notify
    // on our own pair:0 node (XEP §10.1a method B). Carries the joining device's
    // full JID, its device-id, and the shared pairing sid (raw 32 bytes). The
    // existing device reacts by initiating the pairing FSM (PAKE1) toward the
    // full JID using this sid.
    public signal void pair_hello_received(Jid new_full_jid, uint device_id, uint8[] sid);

    // Most-recent <pair-hello> seen for this account (via live +notify OR an
    // explicit refresh_pair_hello fetch), cached so the "Confirm a device" dialog
    // can act on a hello that arrived BEFORE it opened / before the code was
    // typed. Without this, a hello delivered by +notify while no dialog is
    // listening is lost, and the confirm flow depends entirely on a re-fetch that
    // may stall — the exact failure seen in the pairing hang. See
    // replay_last_pair_hello().
    private Jid? last_pair_hello_jid = null;
    private uint last_pair_hello_device_id = 0;
    private uint8[]? last_pair_hello_sid = null;
    private int64 last_pair_hello_at = 0;   // GLib monotonic time (µs)
    // §11.8 queued enrollment request: a disabled/pending device's persisted
    // <enroll-request> item was seen (live +notify or an explicit
    // refresh_pair_hello fetch) and its DIK hybrid signature verified. Carries
    // the same addressing pair_hello_received does (full JID, device id, sid)
    // plus the requester's DIK public keys, so the pairing UI can surface it
    // without needing the human to already know a device is waiting.
    public signal void enrollment_request_received(Jid new_full_jid, uint device_id, uint8[] sid,
        uint8[] dik_ed25519, uint8[] dik_x25519, uint8[] dik_mldsa);
    // Emitted for each verified account audit entry (action code + human detail).
    public signal void account_audit_event(int action, string detail);

    public StreamModule(Account account, Database db) {
        this.account = account;
        this.db = db;
    }

    public override void attach(XmppStream stream) {
        ServiceDiscovery.Module? service_discovery = stream.get_module(ServiceDiscovery.Module.IDENTITY);
        if (service_discovery == null) {
            return;
        }

        foreach (string feature in Protocol.get_disco_features()) {
            service_discovery.add_feature(stream, feature);
        }

        Pubsub.Module pubsub = stream.get_module(Pubsub.Module.IDENTITY);
        pubsub.add_filtered_notification(stream, Protocol.NS_DEVICELIST, (stream, jid, id, node) => {
            parse_device_list(stream, jid, id, node);
        }, null, null);
        pubsub.add_filtered_notification(stream, Protocol.NS_BUNDLE, (stream, jid, id, node) => {
            if (id == null) {
                return;
            }
            parse_bundle(stream, jid, int.parse(id), node);
        }, null, null);
        pubsub.add_filtered_notification(stream, Protocol.NS_AUDIT, (stream, jid, id, node) => {
            handle_audit_event(stream, jid, id, node);
        }, null, null);
        pubsub.add_filtered_notification(stream, Protocol.NS_GROUP, (stream, jid, id, node) => {
            handle_group_event(stream, jid, id, node);
        }, null, null);
        // Self-PEP pairing rendezvous (XEP §10.1a method B). Registering the
        // filtered notification also advertises `urn:xmppqr:x3dhpq:pair:0+notify`
        // in our disco#info, so the server auto-subscribes the account's own
        // resources and delivers a joining device's <pair-hello> to us.
        pubsub.add_filtered_notification(stream, Protocol.NS_PAIR, (stream, jid, id, node) => {
            handle_pair_hello_event(stream, jid, id, node);
        }, null, null);
        // §11.8 sealed device-state tracker: a live +notify delivery of the
        // account's own devtracker:0 item (in addition to the explicit fetch in
        // interpret_device_tracker, used at login/resolve_pending_primary time).
        // Only self-PEP is meaningful; handle_devtracker_event ignores the rest.
        pubsub.add_filtered_notification(stream, Protocol.NS_DEVTRACKER, (stream, jid, id, node) => {
            handle_devtracker_event(stream, jid, node);
        }, null, null);
        // Trust Manifest (Phase 2 §A): live +notify of a manifest item (own or a
        // contact). Registering the filtered notification also advertises
        // `urn:xmppqr:x3dhpq:trustmanifest:0+notify` in disco#info.
        pubsub.add_filtered_notification(stream, Protocol.NS_TRUSTMANIFEST, (stream, jid, id, node) => {
            handle_manifest_event(stream, jid, id, node);
        }, null, null);

        attached_stream = stream;
        stream.get_module(Xmpp.MessageModule.IDENTITY).received_message.connect(on_received_message);
    }

    public override void detach(XmppStream stream) {
        ServiceDiscovery.Module? service_discovery = stream.get_module(ServiceDiscovery.Module.IDENTITY);
        if (service_discovery == null) {
            return;
        }

        foreach (string feature in Protocol.get_disco_features()) {
            service_discovery.remove_feature(stream, feature);
        }

        Pubsub.Module pubsub = stream.get_module(Pubsub.Module.IDENTITY);
        pubsub.remove_filtered_notification(stream, Protocol.NS_DEVICELIST);
        pubsub.remove_filtered_notification(stream, Protocol.NS_BUNDLE);
        pubsub.remove_filtered_notification(stream, Protocol.NS_AUDIT);
        pubsub.remove_filtered_notification(stream, Protocol.NS_GROUP);
        pubsub.remove_filtered_notification(stream, Protocol.NS_PAIR);
        pubsub.remove_filtered_notification(stream, Protocol.NS_DEVTRACKER);
        pubsub.remove_filtered_notification(stream, Protocol.NS_TRUSTMANIFEST);

        stream.get_module(Xmpp.MessageModule.IDENTITY).received_message.disconnect(on_received_message);
        attached_stream = null;
    }

    public async void publish_current_state(XmppStream stream) {
        db.ensure_local_identity(account);
        db.ensure_local_prekeys(account);
        // §10.6.6 device-authorization gating: a device that is not yet
        // authorized (not confirmed, or confirmed but without AIK_priv — see
        // Database.is_authorized) MUST NOT publish an authoritative devicelist.
        // Resolve pending state first; an already-authorized device's resolve
        // is a no-op and simply stays unpublished here, same as today's
        // (correct) behavior for that case. Any authorized device — not only
        // the one that minted the account — manages from here on (§10.6.6).
        if (!db.is_authorized(account)) {
            yield resolve_pending_primary(stream);
        }
        if (db.is_authorized(account)) {
            yield publish_device_list(stream);
            // Trust Manifest Phase 2 (§D1): once the devicelist cache is out, an
            // authorized device holding AIK_priv migrates the account to a genesis
            // manifest (idempotent — no-op if a `current` manifest already exists
            // or this device is not the AIK holder).
            yield ensure_trust_manifest(stream);
        }
        // publish_bundle is NOT gated: a confirmed non-primary device still needs
        // its own bundle published so peers can PQXDH directly to it. A still-
        // pending device's bundle is harmless-but-orphaned (nobody has a reason to
        // fetch a device_id no devicelist has ever announced).
        yield publish_bundle(stream);
        // §11.8: an authorized device (one able to complete pairing / append
        // AddDevice — same AIK_priv gate as publish_device_list) proactively
        // checks pair:0 for a queued enrollment request on every connect,
        // rather than only when the human happens to already have the
        // "Confirm a device" dialog open. Fire-and-forget: any outcome is
        // surfaced via enrollment_request_received / pair_hello_received.
        if (db.is_authorized(account)) {
            refresh_pair_hello.begin(stream);
        }
    }

    // §10.6.1: resolves a not-yet-authorized local identity by fetching the
    // account's own devicelist from the server. An EMPTY (or errored) response
    // means no AIK has ever been published for this account anywhere — genuinely
    // the first device — so it is promoted to primary. A NON-empty response means
    // an existing authorized device already owns this account's AIK; this device
    // remains pending/disabled and waits to be confirmed via CPace pairing
    // (§10.6.2), which calls apply_paired_identity and sets is_primary/confirmed
    // explicitly (true if share_primary, false otherwise — either way "resolved").
    private async void resolve_pending_primary(XmppStream stream) {
        // §11.8 sealed device-state tracker: try it FIRST. Unlike the devicelist
        // check below, it lets a device resolve while every other device is
        // offline (no reliance on a devicelist round-trip actually existing) and
        // additionally carries the offline revocation signal. It only ever
        // mutates state on a CONCLUSIVE outcome (authorized / not-authorized);
        // an absent tracker changes nothing and falls through unchanged to the
        // legacy devicelist-only check, so a fresh account or a legacy peer that
        // never published a tracker item bootstraps exactly as before.
        Protocol.TrackerOutcome tracker_outcome = yield interpret_device_tracker(stream, null);
        if (tracker_outcome != Protocol.TrackerOutcome.ABSENT) {
            // AUTHORIZED or NOT_AUTHORIZED both fully resolve this login attempt
            // (state already updated by interpret_device_tracker) — no need to
            // additionally consult the devicelist.
            return;
        }

        // Legacy fallback (§10.6.1, unchanged): the tracker node does not exist
        // for this account (e.g. it predates §11.8, or genuinely nobody has
        // published anything yet) — fall back to the devicelist-only check.
        Jid own_bare = account.bare_jid;
        ArrayList<int> own_devices = yield request_device_list(stream, own_bare);
        // Re-check: a concurrent pairing confirmation may have completed while
        // the fetch was in flight.
        if (db.is_authorized(account)) {
            return;
        }
        if (own_devices.size == 0) {
            db.promote_to_primary(account);
        }
        // else: stays pending — no publish, no state change.
    }

    // §11.8: fetch (or accept an already-delivered `node`, for the live +notify
    // path) the account's own devtracker:0 item and interpret it.
    //
    // Security note: a device that has NEVER been through human-verified
    // pairing (db.is_pending_enrollment true) has no pinned account AIK to
    // verify the outer hybrid signature against — accepting an "authorized"
    // verdict for such a device without that check would let anyone who can
    // read our (unauthenticated-by-design) public bundle forge a tracker item
    // decryptable by us and hand us an attacker-chosen AIK_priv. For that
    // population we therefore only ever look at ABSENT vs PRESENT (matching
    // spec case 3 — "an account identity already exists" — which is exactly
    // the existing pending-enrollment banner) and never attempt decryption.
    // Only a device that already holds a pinned AIK pub (confirmed via a prior
    // CPace pairing) verifies the signature and, on success, attempts to
    // decrypt its own recipient copy.
    private async Protocol.TrackerOutcome interpret_device_tracker(XmppStream stream, StanzaNode? node) {
        StanzaNode? item = node;
        if (item == null) {
            item = yield fetch_devtracker_item(stream);
        }
        if (item == null) {
            return Protocol.TrackerOutcome.ABSENT;
        }

        if (db.is_pending_enrollment(account)) {
            // Never paired: presence alone is the "an identity already exists"
            // signal (§11.8 case 3). Stay pending; the existing banner already
            // covers this. Never attempt to decrypt (see security note above).
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }

        Row? identity = db.get_local_identity(account.id);
        if (identity == null) {
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }
        string? aik_ed_b64 = ((!) identity)[db.account_identity.aik_pub_ed25519_base64];
        string? aik_ml_b64 = ((!) identity)[db.account_identity.aik_pub_mldsa_base64];
        if (aik_ed_b64 == null || aik_ml_b64 == null) {
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }

        Protocol.DevTrackerParsed? parsed = parse_devtracker_node((!) item);
        if (parsed == null) {
            return Protocol.TrackerOutcome.ABSENT;   // malformed: treat as if absent, never punish
        }
        try {
            Bytes aik_ed = bytes_from_base64((!) aik_ed_b64);
            Bytes aik_mldsa = bytes_from_base64((!) aik_ml_b64);
            var recipients_for_sp = new Gee.ArrayList<Protocol.DeviceTrackerRecipient>();
            foreach (Protocol.DevTrackerRecipientWire rw in parsed.recipients) {
                var rec = new Protocol.DeviceTrackerRecipient();
                rec.device_id = rw.device_id;
                rec.hdr_bytes = rw.hdr_bytes;
                rec.emk_bytes = rw.emk_bytes;
                recipients_for_sp.add(rec);
            }
            uint8[] sp = Protocol.DeviceTrackerSigned.signed_part(
                parsed.version, parsed.issued_at, parsed.ct, recipients_for_sp);
            bool sig_ok = global::X3dhpq.Crypto.ed25519_verify(aik_ed, new Bytes(sp), new Bytes(parsed.sig_ed))
                && global::X3dhpq.Crypto.mldsa65_verify(aik_mldsa, new Bytes(sp), new Bytes(parsed.sig_mldsa));
            if (!sig_ok) {
                warning("x3dhpq devtracker for %s failed AIK signature verification — ignoring",
                    account.bare_jid.to_string());
                return Protocol.TrackerOutcome.ABSENT;   // unverifiable: ignore, do not punish
            }
        } catch (GLib.Error e) {
            warning("interpret_device_tracker: signature decode/verify error: %s", e.message);
            return Protocol.TrackerOutcome.ABSENT;
        }

        int? local_device_id = db.get_local_device_id(account);
        if (local_device_id == null) {
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }
        Protocol.DevTrackerRecipientWire? mine = null;
        foreach (Protocol.DevTrackerRecipientWire r in parsed.recipients) {
            if (r.device_id == (uint32) (!) local_device_id) {
                mine = r;
                break;
            }
        }
        if (mine == null) {
            db.mark_tracker_not_authorized(account);
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }

        Bytes transport_key;
        try {
            transport_key = try_decrypt_tracker_recipient(account, (!) mine);
        } catch (GLib.Error e) {
            // Cannot decrypt our own copy: either just-revoked or a stale/
            // corrupt item — either way, not currently authorized.
            db.mark_tracker_not_authorized(account);
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }

        Protocol.DeviceTrackerPayload? payload;
        try {
            Bytes plaintext = Protocol.decrypt_payload_bytes(transport_key, new Bytes(parsed.ct));
            payload = Protocol.DeviceTrackerPayload.unmarshal(bytes_to_uint8_array(plaintext));
        } catch (GLib.Error e) {
            warning("interpret_device_tracker: payload AEAD-open failed: %s", e.message);
            db.mark_tracker_not_authorized(account);
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }
        if (payload == null) {
            db.mark_tracker_not_authorized(account);
            return Protocol.TrackerOutcome.NOT_AUTHORIZED;
        }

        // Adopt our own DC from the fold, if present, so publish_device_list /
        // bundle fetches can serve it without waiting on an inbound devicelist.
        foreach (Protocol.DeviceSnapshotDevice d in ((!) payload).devices) {
            if (d.device_id == (uint32) (!) local_device_id && d.cert_bytes.length > 0) {
                db.store_local_device_certificate(account, (int) d.device_id, Base64.encode(d.cert_bytes));
                break;
            }
        }

        Protocol.AccountIdentityKey? aik_priv = null;
        if (((!) payload).aik_priv_ed25519 != null && ((!) payload).aik_priv_mldsa != null) {
            var key = new Protocol.AccountIdentityKey();
            key.priv_ed25519 = bytes_to_uint8_array((!) ((!) payload).aik_priv_ed25519);
            key.priv_mldsa = bytes_to_uint8_array((!) ((!) payload).aik_priv_mldsa);
            aik_priv = key;
        }
        db.mark_tracker_authorized(account, aik_priv);
        return Protocol.TrackerOutcome.AUTHORIZED;
    }

    // Attempt to decrypt one tracker recipient copy addressed to THIS device,
    // reusing the exact 1:1 envelope decrypt primitives (Protocol.respond_session
    // / Protocol.decrypt_transport_key — the same call sequence Manager.
    // decrypt_message uses for an inbound prekey message). Deliberately
    // stateless: unlike ordinary 1:1 messaging, a tracker item is always a
    // fresh, full re-seal (§11.8: "re-publishes it on every device-set
    // change... adding/removing recipient copies"), so there is never a prior
    // session to continue and nothing is persisted via db.store_session — this
    // keeps tracker sealing/opening from ever interacting with real 1:1
    // conversation session state between the same device pair.
    private Bytes try_decrypt_tracker_recipient(Account account, Protocol.DevTrackerRecipientWire r) throws GLib.Error {
        if (r.prekey == null) {
            throw new IOError.FAILED("tracker recipient has no prekey block");
        }
        Protocol.DevTrackerPrekeyWire prekey = (!) r.prekey;
        Protocol.DeviceCertificate? peer_cert = Protocol.DeviceCertificate.unmarshal(new Bytes(prekey.dc));
        if (peer_cert == null) {
            throw new IOError.FAILED("tracker recipient prekey has undecodable DC");
        }
        // Defensive: db.get_required_local_bundle() would assert()-abort if no
        // bundle row exists yet. That should be unreachable here (ensure_local_
        // prekeys() always runs earlier in publish_current_state, and a device
        // that can reach this point is already confirmed, so its bundle row was
        // created at pairing time), but interpret_device_tracker's whole point
        // is to be resilient to unexpected/adversarial input — never crash the
        // login path — so use the nullable accessor and fail closed instead.
        Row? local_bundle = db.get_local_bundle(account);
        if (local_bundle == null) {
            throw new IOError.FAILED("no local bundle yet — cannot attempt tracker decrypt");
        }
        Row? local_spk = db.get_local_signed_pre_key(account, ((!) local_bundle)[db.bundle.signed_pre_key_id]);
        Row? local_kem = db.get_local_kem_pre_key(account, (int) prekey.kemkey_id);
        if (local_spk == null || local_kem == null) {
            throw new IOError.FAILED("no matching local SPK/KEM prekey for tracker recipient");
        }
        Row? local_opk = null;
        if (prekey.opk_id > 0) {
            local_opk = db.get_local_one_time_pre_key(account, (int) prekey.opk_id);
        }

        Protocol.SessionState state = Protocol.respond_session(
            db.get_local_identity_bytes(account, db.account_identity.dik_priv_x25519_base64),
            db.get_local_identity_bytes(account, db.account_identity.dik_pub_x25519_base64),
            bytes_from_base64(((!) local_spk)[db.signed_pre_key.private_base64]),
            bytes_from_base64(((!) local_spk)[db.signed_pre_key.public_base64]),
            local_opk != null ? bytes_from_base64(((!) local_opk)[db.one_time_pre_key.private_base64]) : null,
            bytes_from_base64(((!) local_kem)[db.kem_pre_key.private_base64]),
            peer_cert,
            new Bytes(prekey.aik_ed25519),
            new Bytes(prekey.aik_mldsa),
            new Bytes(prekey.ek),
            new Bytes(prekey.kem_ct)
        );
        if (local_opk != null) {
            db.mark_local_one_time_pre_key_consumed(account, (int) prekey.opk_id);
        }

        Protocol.MessageHeader? header = Protocol.MessageHeader.unmarshal(new Bytes(r.hdr_bytes));
        if (header == null) {
            throw new IOError.FAILED("tracker recipient has undecodable header");
        }
        return Protocol.decrypt_transport_key(state, header, new Bytes(r.emk_bytes));
    }

    // §11.8: fetch the current devtracker:0 item for our own account, or null
    // if the node does not exist / has no item / the fetch errors.
    private async StanzaNode? fetch_devtracker_item(XmppStream stream) {
        StanzaNode pubsub_node = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_DEVTRACKER));
        Iq.Stanza iq = new Iq.Stanza.get(pubsub_node) { to = account.bare_jid };
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            if (result.is_error()) return null;
            StanzaNode? item = result.stanza.get_deep_subnode(
                Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items", Pubsub.NS_URI + ":item");
            if (item != null && item.sub_nodes.size > 0) {
                return item.sub_nodes[0];
            }
        } catch (Error e) {
            // Node-does-not-exist (item-not-found / feature-not-implemented) is
            // the expected steady state for any account that has never
            // published a tracker item — not a warning-worthy condition.
        }
        return null;
    }

    // Live +notify delivery of our own devtracker:0 item. Only meaningful for a
    // device that is not (yet) authorized — an authorized device always holds
    // AIK_priv directly and is never subject to the tracker revocation signal.
    // Fire-and-forget: any outcome just updates local state via
    // interpret_device_tracker, exactly as the explicit login-time fetch would.
    private void handle_devtracker_event(XmppStream stream, Jid from, StanzaNode? item_node) {
        if (!from.bare_jid.equals(account.bare_jid) || item_node == null) {
            return;
        }
        if (db.is_authorized(account)) {
            return;
        }
        interpret_device_tracker.begin(stream, item_node);
    }

    // §11.8 canonical wire format: decode a <devtracker> item's XML shape
    // (reusing the 1:1 pairwise-envelope element shapes — <key rid=.. xmlns=
    // envelope:0>, <payload xmlns=envelope:0>, <sig>/<mldsa-sig> xmlns=
    // devicelist:0 — verbatim, mirroring PQonversations' DevTracker element,
    // which literally reuses the envelope/devicelist Key/Payload/Sig/MldsaSig
    // Java classes) into a Protocol.DevTrackerParsed. Kept here (rather than
    // in device_tracker.vala) so the Protocol namespace's byte-codec classes
    // stay free of an Xmpp/StanzaNode dependency, mirroring how devicelist/
    // bundle parsing lives in this file too.
    private Protocol.DevTrackerParsed? parse_devtracker_node(StanzaNode item) {
        if (item.name != "devtracker") {
            return null;
        }
        var parsed = new Protocol.DevTrackerParsed();
        parsed.sender_device = (uint32) (int64.parse(item.get_attribute("sender-device") ?? "0"));
        parsed.sender_jid = item.get_attribute("sender-jid") ?? "";
        parsed.ts = item.get_attribute("ts") ?? "";
        parsed.version = uint64.parse(item.get_attribute("version") ?? "0");
        parsed.issued_at = uint64.parse(item.get_attribute("issued-at") ?? "0");

        StanzaNode? payload_node = item.get_subnode("payload", Protocol.NS_ENVELOPE);
        string? ct_b64 = payload_node != null ? payload_node.get_string_content() : null;
        if (ct_b64 == null) return null;
        try {
            parsed.ct = bytes_to_uint8_array(bytes_from_base64(ct_b64));
        } catch (GLib.Error e) {
            return null;
        }

        foreach (StanzaNode kn in item.get_subnodes("key", Protocol.NS_ENVELOPE)) {
            string? rid_str = kn.get_attribute("rid");
            StanzaNode? hdr_node = kn.get_subnode("hdr", Protocol.NS_ENVELOPE);
            StanzaNode? emk_node = kn.get_subnode("emk", Protocol.NS_ENVELOPE);
            if (rid_str == null || hdr_node == null || emk_node == null) continue;
            string? hdr_b64 = hdr_node.get_string_content();
            string? emk_b64 = emk_node.get_string_content();
            if (hdr_b64 == null || emk_b64 == null) continue;

            var rec = new Protocol.DevTrackerRecipientWire();
            try {
                rec.device_id = (uint32) int64.parse(rid_str);
                rec.hdr_bytes = bytes_to_uint8_array(bytes_from_base64(hdr_b64));
                rec.emk_bytes = bytes_to_uint8_array(bytes_from_base64(emk_b64));
            } catch (GLib.Error e) {
                continue;
            }

            StanzaNode? prekey_node = kn.get_subnode("prekey", Protocol.NS_ENVELOPE);
            if (prekey_node != null) {
                try {
                    var pk = new Protocol.DevTrackerPrekeyWire();
                    pk.ek = bytes_to_uint8_array(bytes_from_base64(prekey_node.get_attribute("ek") ?? ""));
                    pk.opk_id = (uint32) prekey_node.get_attribute_int("opk-id");
                    pk.kemkey_id = (uint32) prekey_node.get_attribute_int("kemkey-id");
                    pk.kem_ct = bytes_to_uint8_array(bytes_from_base64(prekey_node.get_attribute("kem-ct") ?? ""));
                    pk.dc = bytes_to_uint8_array(bytes_from_base64(prekey_node.get_deep_string_content("dc") ?? ""));
                    pk.aik_ed25519 = bytes_to_uint8_array(bytes_from_base64(prekey_node.get_deep_string_content("aik-ed25519") ?? ""));
                    pk.aik_mldsa = bytes_to_uint8_array(bytes_from_base64(prekey_node.get_deep_string_content("aik-mldsa") ?? ""));
                    rec.prekey = pk;
                } catch (GLib.Error e) {
                    rec.prekey = null;
                }
            }
            parsed.recipients.add(rec);
        }

        StanzaNode? sig_node = item.get_subnode("sig", Protocol.NS_DEVICELIST);
        StanzaNode? mldsa_node = item.get_subnode("mldsa-sig", Protocol.NS_DEVICELIST);
        string? sig_b64 = sig_node != null ? sig_node.get_string_content() : null;
        string? mldsa_b64 = mldsa_node != null ? mldsa_node.get_string_content() : null;
        if (sig_b64 == null || mldsa_b64 == null) return null;
        try {
            parsed.sig_ed = bytes_to_uint8_array(bytes_from_base64(sig_b64));
            parsed.sig_mldsa = bytes_to_uint8_array(bytes_from_base64(mldsa_b64));
        } catch (GLib.Error e) {
            return null;
        }
        return parsed;
    }

    // §11.8: the DAG's current head hashes (Protocol.DeviceDag.current_heads()),
    // included in the tracker plaintext as a self-contained catch-up anchor.
    // Best-effort: an empty/unfoldable local DAG just yields an empty list, same
    // as try_derive_devices_from_dag's SAFETY FALLBACK philosophy elsewhere in
    // this file.
    private Gee.ArrayList<Bytes> compute_dag_current_heads() {
        var dag = new Protocol.DeviceDag();
        foreach (Protocol.DeviceAuditEntryV2 e in db.list_device_audit_entries(account)) {
            dag.ingest(e.marshal());
        }
        return dag.current_heads();
    }

    // §11.8: seal and publish the device-state tracker item to the given
    // authorized device set (the SAME fold `publish_device_list` just
    // published, passed in so it is computed exactly once). REUSES the exact
    // 1:1 hybrid envelope construction — Protocol.initiate_session (X3DH +
    // ML-KEM-768 bootstrap) and Protocol.encrypt_transport_key (AES-256-GCM
    // wrap of the random content key under the freshly-derived session) — once
    // per authorized device's currently-published bundle, exactly mirroring
    // Manager.build_encrypted_message's <key rid><hdr/><emk/><prekey/></key>
    // shape. Never persists a pairwise session (db.store_session): §11.8 has
    // "ANY authorized device re-publishes it on every device-set change", i.e.
    // every publish is a fresh, full re-seal, not a ratchet continuation, so
    // there is nothing to persist and no interaction with real 1:1 conversation
    // session state between the same device pair.
    //
    // Best-effort by design (§11.8 guardrail): ANY failure here — a bundle not
    // yet fetched for some device, a signing error, a publish IQ error — is
    // logged and swallowed. It must never block publish_device_list, which has
    // already succeeded by the time this is called, nor account bootstrap.
    public async void publish_device_tracker(XmppStream stream, Gee.List<Protocol.DeviceListDevice> authorized_devices) {
        try {
            int? local_device_id = db.get_local_device_id(account);
            if (local_device_id == null) return;
            string? aik_priv_ed_b64 = db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64);
            string? aik_priv_ml_b64 = db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64);
            if (aik_priv_ed_b64 == null || aik_priv_ed_b64 == "" || aik_priv_ml_b64 == null || aik_priv_ml_b64 == "") {
                // A confirmed-but-not-share_primary secondary has no AIK_priv and
                // cannot sign a tracker item; only an AIK_priv holder republishes it.
                return;
            }
            string? aik_pub_ed_b64 = db.get_local_identity_string(account, db.account_identity.aik_pub_ed25519_base64);
            string? aik_pub_ml_b64 = db.get_local_identity_string(account, db.account_identity.aik_pub_mldsa_base64);
            if (aik_pub_ed_b64 == null || aik_pub_ml_b64 == null) return;
            uint8[] aik_pub_ed = bytes_to_uint8_array(bytes_from_base64((!) aik_pub_ed_b64));
            uint8[] aik_pub_ml = bytes_to_uint8_array(bytes_from_base64((!) aik_pub_ml_b64));

            // §11.8 canonical inner payload: domain-separated §11.7 Snapshot (owner_
            // aik_fp | epoch=0 | authorized devices) + current DAG heads + optionally
            // the sealed AIK_priv, byte-for-byte matching
            // X3dhpqService.buildDeviceTrackerPlaintextPayload.
            var payload = new Protocol.DeviceTrackerPayload();
            payload.owner_aik_fp = bytes_to_uint8_array(
                global::X3dhpq.Crypto.blake2b160(new Bytes(Protocol.DeviceAuditEntryV2.aik_pub_marshal(aik_pub_ed, aik_pub_ml))));
            foreach (Protocol.DeviceListDevice d in authorized_devices) {
                var sd = new Protocol.DeviceSnapshotDevice();
                sd.device_id = d.device_id;
                sd.cert_bytes = d.cert_bytes;
                payload.devices.add(sd);
            }
            payload.dag_heads = compute_dag_current_heads();
            // §11.8: MAY carry the shared AIK_priv (self-refreshing, device-key-
            // sealed recovery) — this implementation always includes it, sealed
            // per-recipient exactly like the rest of the payload. Embedded using
            // the canonical AccountIdentityKey.marshal() layout (§11.8), not the
            // pairing-issuance format.
            payload.aik_priv_ed25519 = bytes_from_base64((!) aik_priv_ed_b64);
            payload.aik_priv_mldsa = bytes_from_base64((!) aik_priv_ml_b64);
            payload.aik_pub_ed25519 = aik_pub_ed;
            payload.aik_pub_mldsa = aik_pub_ml;
            uint8[] plaintext = payload.marshal();

            Bytes payload_key = global::X3dhpq.Crypto.random_bytes(32);
            Bytes payload_nonce = global::X3dhpq.Crypto.random_bytes(12);
            Bytes payload_transport_key = bytes_from_uint8_array(
                concat_byte_arrays(bytes_to_uint8_array(payload_key), bytes_to_uint8_array(payload_nonce)));
            Bytes ct = Protocol.encrypt_payload_bytes(new Bytes(plaintext), payload_transport_key);

            Bytes my_dik_priv_x = db.get_local_identity_bytes(account, db.account_identity.dik_priv_x25519_base64);
            Bytes my_dik_pub_x = db.get_local_identity_bytes(account, db.account_identity.dik_pub_x25519_base64);
            string own_jid = account.bare_jid.to_string();

            // §11.8 canonical outer element: one <key rid=.. xmlns=envelope:0> per
            // authorized device, reusing the exact 1:1 pairwise-envelope shape
            // (Manager.build_encrypted_message's <key>/<hdr>/<emk>/<prekey>),
            // instead of the old bespoke <recipient> wrapper.
            var recipients = new Gee.ArrayList<Protocol.DeviceTrackerRecipient>();
            var key_nodes = new Gee.ArrayList<StanzaNode>();
            foreach (Protocol.DeviceListDevice d in authorized_devices) {
                Protocol.PeerBundle? peer_bundle = db.get_remote_bundle(account, own_jid, (int) d.device_id);
                if (peer_bundle == null) {
                    continue;   // bundle not fetched yet — best-effort, seal what we can
                }
                bool verified;
                try {
                    verified = ((!) peer_bundle).verify();
                } catch (GLib.Error e) {
                    verified = false;
                }
                if (!verified) continue;

                try {
                    Protocol.SessionBootstrap bootstrap = Protocol.initiate_session(my_dik_priv_x, my_dik_pub_x, (!) peer_bundle);
                    Protocol.MessageHeader header;
                    Bytes emk;
                    Protocol.encrypt_transport_key(bootstrap.state, payload_transport_key, out header, out emk);

                    var rec = new Protocol.DeviceTrackerRecipient();
                    rec.device_id = d.device_id;
                    rec.hdr_bytes = bytes_to_uint8_array(header.marshal());
                    rec.emk_bytes = bytes_to_uint8_array(emk);
                    recipients.add(rec);

                    // isFirst=true always: every seal is a fresh, self-contained
                    // PQXDH "first message" (§11.8), so <prekey> is always present.
                    StanzaNode prekey_node = new StanzaNode.build("prekey", Protocol.NS_ENVELOPE)
                        .put_attribute("ek", bytes_to_base64((!) bootstrap.prekey_ephemeral_pub))
                        .put_attribute("opk-id", bootstrap.opk_id.to_string())
                        .put_attribute("kemkey-id", bootstrap.kem_key_id.to_string())
                        .put_attribute("kem-ct", bytes_to_base64((!) bootstrap.kem_ciphertext))
                        .put_node(new StanzaNode.build("dc", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.ensure_local_device_certificate(account))))
                        .put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text((!) aik_pub_ed_b64)))
                        .put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text((!) aik_pub_ml_b64)));

                    StanzaNode key_node = new StanzaNode.build("key", Protocol.NS_ENVELOPE)
                        .put_attribute("rid", d.device_id.to_string())
                        .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(new Bytes(rec.hdr_bytes)))))
                        .put_node(new StanzaNode.build("emk", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(emk))))
                        .put_node(prekey_node);
                    key_nodes.add(key_node);
                } catch (GLib.Error e) {
                    warning("publish_device_tracker: failed to seal to device %u: %s", d.device_id, e.message);
                    continue;
                }
            }

            if (recipients.size == 0) {
                // Nothing sealable yet (no bundles fetched for any authorized
                // device, not even our own) — try again on the next
                // republish/device-set change rather than publishing an item
                // nobody could ever decrypt.
                return;
            }

            long issued_at = (long) new DateTime.now_utc().to_unix();
            uint64 version = (uint64) db.next_tracker_version(account);
            uint8[] sp = Protocol.DeviceTrackerSigned.signed_part(
                version, (uint64) issued_at, bytes_to_uint8_array(ct), recipients);
            Bytes aik_priv_ed = bytes_from_base64((!) aik_priv_ed_b64);
            Bytes aik_priv_ml = bytes_from_base64((!) aik_priv_ml_b64);
            string sig_b64 = Base64.encode(bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(sp))));
            string mldsa_sig_b64 = Base64.encode(bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(aik_priv_ml, new Bytes(sp))));

            StanzaNode node = new StanzaNode.build("devtracker", Protocol.NS_DEVTRACKER)
                .add_self_xmlns()
                .put_attribute("sender-device", ((!) local_device_id).to_string())
                .put_attribute("sender-jid", own_jid)
                .put_attribute("ts", new DateTime.now_utc().format_iso8601())
                .put_attribute("version", version.to_string())
                .put_attribute("issued-at", issued_at.to_string());
            foreach (StanzaNode kn in key_nodes) {
                node.put_node(kn);
            }
            // type="devtracker" matches XmppX3dhpqMessage#toExtension's
            // payloadTypeOverride, set via setPayloadType("devtracker") on the PQ
            // publish path — purely descriptive (disambiguates this reused-envelope
            // payload from a "sender-chain"/"group-sync" one); not itself checked
            // by either side's tracker interpreter, but reproduced for byte-for-
            // byte outer-element fidelity with the canonical wire format.
            node.put_node(new StanzaNode.build("payload", Protocol.NS_ENVELOPE)
                    .put_attribute("type", "devtracker")
                    .put_node(new StanzaNode.text(bytes_to_base64(ct))))
                .put_node(new StanzaNode.build("sig", Protocol.NS_DEVICELIST).put_node(new StanzaNode.text(sig_b64)))
                .put_node(new StanzaNode.build("mldsa-sig", Protocol.NS_DEVICELIST).put_node(new StanzaNode.text(mldsa_sig_b64)));

            // §11.8: whitelist (owner-only) access — this node is never meant to
            // be public, unlike devicelist/bundle, so no try_make_node_public call.
            yield stream.get_module(Pubsub.Module.IDENTITY).publish(stream, null, Protocol.NS_DEVTRACKER, "current", node, TRACKER_PUBLISH_OPTIONS);
        } catch (GLib.Error e) {
            // §11.8 guardrail: failure to publish/seal the tracker must ONLY log
            // an error — it must never block the underlying devicelist publish
            // or account bind/bootstrap (this is always called AFTER
            // publish_device_list has already succeeded).
            warning("publish_device_tracker: failed for %s: %s", account.bare_jid.to_string(), e.message);
        }
    }

    public async ArrayList<int> request_device_list(XmppStream stream, Jid jid) {
        Future<ArrayList<int>>? future = active_devicelist_requests[jid];
        if (future == null) {
            Promise<ArrayList<int>?> promise = new Promise<ArrayList<int>?>();
            future = promise.future;
            active_devicelist_requests[jid] = future;
            stream.get_module(Pubsub.Module.IDENTITY).request(stream, jid, Protocol.NS_DEVICELIST, (stream, jid, id, node) => {
                promise.set_value(parse_device_list(stream, jid, id, node));
                active_devicelist_requests.unset(jid);
            });
        }

        try {
            return yield future.wait_async();
        } catch (FutureError e) {
            warning("Unable to request x3dhpq devicelist for %s: %s", jid.to_string(), e.message);
            return new ArrayList<int>();
        }
    }

    public async StanzaNode? request_bundle(XmppStream stream, Jid jid, int device_id) {
        StanzaNode pubsub = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_BUNDLE)
                .put_node(new StanzaNode.build("item", Pubsub.NS_URI).put_attribute("id", device_id.to_string())));
        Iq.Stanza iq = new Iq.Stanza.get(pubsub) { to = jid };
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            StanzaNode? item = result.stanza.get_deep_subnode(Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items", Pubsub.NS_URI + ":item");
            if (item != null && item.sub_nodes.size > 0) {
                parse_bundle(stream, jid, device_id, item.sub_nodes[0]);
                return item.sub_nodes[0];
            }
        } catch (Error e) {
            warning("Unable to request x3dhpq bundle for %s/%d: %s", jid.to_string(), device_id, e.message);
        }
        return null;
    }

    private async void publish_device_list(XmppStream stream, Gee.Set<uint32>? allow_removals = null) {
        int? device_id = db.get_local_device_id(account);
        if (device_id == null) {
            return;
        }

        string cert;
        try {
            cert = db.ensure_local_device_certificate(account);
        } catch (GLib.Error e) {
            warning("Skipping x3dhpq devicelist publish for %s: certificate not yet available (%s)",
                account.bare_jid.to_string(), e.message);
            return;
        }
        if (cert == "") {
            // Defensive: if the cert ever comes back empty we must not publish a
            // <cert/> empty element — peers would store an unverifiable bundle
            // and silently drop our messages.
            warning("Refusing to publish x3dhpq devicelist with empty certificate for %s",
                account.bare_jid.to_string());
            return;
        }
        long added_at = db.get_local_device_created_at(account);
        string own_jid = account.bare_jid.to_string();

        // The devicelist MUST list every device under this account's AIK, not
        // just this local device (§8.2/§8.4) — otherwise a second device on the
        // same account disappears from `current` and contacts stop encrypting
        // to it. Build the UNION of: this local device (canonical, freshly
        // loaded certificate) PLUS any other account devices already persisted
        // under our own bare JID. Those rows come from store_remote_device,
        // populated by parse_device_list's is_self branch whenever this device
        // has previously accepted a signed devicelist for the account that
        // listed co-account devices (e.g. a device enrolled via pairing that
        // later republished the full list itself).
        var by_id = new Gee.HashMap<uint32, Protocol.DeviceListDevice>();
        var local_dld = new Protocol.DeviceListDevice();
        local_dld.device_id = (uint32)(!) device_id;
        local_dld.added_at = added_at;
        try {
            local_dld.cert_bytes = bytes_to_uint8_array(bytes_from_base64(cert));
        } catch (GLib.Error e) {
            warning("publish_device_list: cert base64 decode failed: %s", e.message);
            return;
        }
        // The published flags MUST reflect this device's own DC (bit 0 = primary),
        // not be hardcoded — a non-primary paired device must not advertise itself
        // as primary. Derive from the freshly loaded certificate rather than the
        // (unrelated) union built below.
        Protocol.DeviceCertificate? local_dc = Protocol.DeviceCertificate.unmarshal(new Bytes(local_dld.cert_bytes));
        if (local_dc == null) {
            warning("publish_device_list: failed to unmarshal local device certificate for %s; falling back to flags=0",
                own_jid);
        }
        uint8 flags = local_dc != null ? local_dc.flags : 0;
        local_dld.flags = flags;
        by_id[local_dld.device_id] = local_dld;
        foreach (Protocol.DeviceListDevice other in db.get_device_list_devices(account, own_jid)) {
            if (by_id.has_key(other.device_id)) {
                continue;   // local device above is the canonical entry for our own id
            }
            if (other.cert_bytes.length == 0) {
                // No certificate persisted for this co-account device yet — it
                // cannot be safely re-emitted on a signed list. See follow-up
                // note at the end of this method.
                continue;
            }
            by_id[other.device_id] = other;
        }
        var devices = new Gee.ArrayList<Protocol.DeviceListDevice>();
        devices.add_all(by_id.values);
        devices.sort((a, b) => (a.device_id < b.device_id) ? -1 : (a.device_id > b.device_id ? 1 : 0));

        // §11.7: bootstrap the account's device-audit genesis Snapshot (idempotent,
        // once per account — no-op after the first successful call) asserting
        // TODAY'S device union as the DAG's initial authorized set. This is both
        // the v1->v2 bridge for pre-existing accounts and the genesis for brand
        // new ones. Then try to derive the published set from the persisted DAG
        // fold instead of the legacy `by_id` union built above. SAFETY FALLBACK:
        // any failure (no entries, fold verification rejects everything, an
        // authorized cert that won't round-trip) leaves `devices` untouched —
        // the legacy union computed above is still exactly what gets published.
        ensure_device_audit_genesis(devices);
        Gee.List<Protocol.DeviceListDevice>? dag_devices = try_derive_devices_from_dag(by_id);
        if (dag_devices != null && dag_devices.size > 0) {
            devices = new Gee.ArrayList<Protocol.DeviceListDevice>();
            devices.add_all(dag_devices);
            devices.sort((a, b) => (a.device_id < b.device_id) ? -1 : (a.device_id > b.device_id ? 1 : 0));
        }

        // Safety net ("no accidental/injected devicelist shrink"): a publish
        // that DROPS a previously-known account device must never happen by
        // accident (transient/buggy/injected partial state). Compare the union
        // we are about to sign against the ids in the LAST authoritative own
        // devicelist we committed — read from its stored XML payload, which is
        // independent of the peer_device union built above (so the comparison is
        // not circular). Any id present before but absent now, and not in the
        // explicitly allowed removal set (§8.6 revocation), aborts the publish
        // BEFORE signing/sending/persisting. First publish (empty prevIds),
        // identical republish and growth all pass through unchanged.
        var new_ids = new Gee.HashSet<uint32>();
        foreach (Protocol.DeviceListDevice d in devices) {
            new_ids.add(d.device_id);
        }
        Gee.Set<uint32> prev_ids = parse_own_devicelist_ids(db.get_device_list_content_key(account, own_jid));
        Gee.List<uint32> missing = Protocol.devicelist_shrink_drops(prev_ids, new_ids, allow_removals);
        if (missing.size > 0) {
            var missing_str = new StringBuilder();
            foreach (uint32 mid in missing) {
                if (missing_str.len > 0) missing_str.append(", ");
                missing_str.append(mid.to_string());
            }
            warning("x3dhpq: refusing to publish devicelist dropping known device(s) %s without revocation", missing_str.str);
            return;
        }

        // Version rule (§8.2): the version is a persisted, monotonic per-account
        // counter incremented ONLY when the list *content* changes. A routine
        // self-republish (same devices) MUST reuse the current version. The
        // content key is computed over the FULL union so a co-account device
        // appearing/disappearing counts as a content change, exactly mirroring
        // parse_device_list's inbound content-key computation.
        string content_key = build_device_content_key(devices);
        long prev_version = db.get_device_list_version(account, own_jid);
        string? prev_content_key = db.get_device_list_content_key(account, own_jid);
        long version;
        if (prev_content_key != null && prev_content_key == content_key) {
            version = prev_version > 0 ? prev_version : 1;
        } else {
            version = prev_version + 1;   // first publish: 0 + 1 = 1
        }
        long issued_at = (long) new DateTime.now_utc().to_unix();

        // Compute the SignedPart (layout A) over the full device union and
        // hybrid-sign it with the AIK.
        uint8[] sp = Protocol.DeviceListSigned.signed_part((uint64) version, issued_at, devices);
        string sig_b64;
        string mldsa_sig_b64;
        try {
            Bytes aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
            Bytes aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
            sig_b64 = Base64.encode(bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(sp))));
            mldsa_sig_b64 = Base64.encode(bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(aik_priv_mldsa, new Bytes(sp))));
        } catch (GLib.Error e) {
            warning("publish_device_list: hybrid signing failed for %s: %s", own_jid, e.message);
            return;
        }

        // The cert/sig strings MUST be added as text sub-nodes, not via the `val`
        // initialiser (which is ignored for element StanzaNodes on serialization).
        // <sig>/<mldsa-sig> are children of <devicelist> (siblings of <device>) so
        // they survive PEP item delivery, which hands the receiver only the first
        // item child (the <devicelist> element). One <device> element (with its
        // <cert>) is emitted per device in the union, sorted by id, followed by
        // the trailing <sig>/<mldsa-sig> — element ordering and the SignedPart
        // byte layout are unchanged.
        StanzaNode node = new StanzaNode.build("devicelist", Protocol.NS_DEVICELIST)
            .add_self_xmlns()
            .put_attribute("version", version.to_string())
            .put_attribute("issued-at", issued_at.to_string());
        foreach (Protocol.DeviceListDevice d in devices) {
            node.put_node(new StanzaNode.build("device", Protocol.NS_DEVICELIST)
                .put_attribute("id", d.device_id.to_string())
                .put_attribute("added-at", d.added_at.to_string())
                .put_attribute("flags", d.flags.to_string())
                .put_node(new StanzaNode.build("cert", Protocol.NS_DEVICELIST)
                    .put_node(new StanzaNode.text(Base64.encode(d.cert_bytes)))));
        }
        node.put_node(new StanzaNode.build("sig", Protocol.NS_DEVICELIST)
                .put_node(new StanzaNode.text(sig_b64)))
            .put_node(new StanzaNode.build("mldsa-sig", Protocol.NS_DEVICELIST)
                .put_node(new StanzaNode.text(mldsa_sig_b64)));

        if (yield stream.get_module(Pubsub.Module.IDENTITY).publish(stream, null, Protocol.NS_DEVICELIST, "current", node, PUBLISH_OPTIONS)) {
            yield try_make_node_public(stream, Protocol.NS_DEVICELIST);
            db.store_device_list_payload(account, own_jid, "current", node.to_string(), version, true, content_key);
            // §11.8: re-seal and republish the sealed device-state tracker to the
            // SAME device union just published, whenever a device is authorized
            // and the device set changes (and, harmlessly, on every idempotent
            // republish too). Best-effort — see publish_device_tracker's own
            // guardrail comment; a failure here can never undo or block the
            // devicelist publish that already succeeded above.
            yield publish_device_tracker(stream, devices);
        }
        // The primary already persists a newly-enrolled device's DC under our own
        // bare JID at pairing completion (encryption_preferences_entry.vala's
        // pairing_completed handler calls db.store_remote_device); other devices
        // pick up co-account siblings from the account's own inbound signed
        // devicelist via parse_device_list's is_self branch.
    }

    // ==================================================================
    // Trust Manifest (Phase 2): the LIVE trust source.
    // ==================================================================

    // Local raw-bytes SHA-256 helper (returns zeros on failure — callers treat a
    // zero hash as a non-match, which fails closed).
    private uint8[] manifest_sha256(uint8[] data) {
        try {
            return bytes_to_uint8_array(global::X3dhpq.Crypto.sha256(new Bytes(data)));
        } catch (GLib.Error e) {
            return new uint8[32];
        }
    }

    private static bool manifest_bytes_equal(uint8[] a, uint8[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    // Build + hybrid-sign a TrustEntry under the given signer private halves.
    private Protocol.TrustEntry build_signed_trust_entry(uint8 action, uint32 device_id,
            Protocol.DeviceCertificate dc, uint64 lamport, Gee.ArrayList<Bytes> parents,
            uint32 author_id, uint8[] author_dc_hash, Bytes signer_ed_priv, Bytes signer_ml_priv)
            throws GLib.Error {
        var e = new Protocol.TrustEntry();
        e.action = action;
        e.device_id = device_id;
        e.dc = dc;
        e.lamport = lamport;
        e.parents = parents;
        e.author_device_id = author_id;
        e.author_dc_hash = author_dc_hash;
        e.timestamp = (int64) new DateTime.now_utc().to_unix();
        uint8[] sp = e.signed_part();
        e.signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(signer_ed_priv, new Bytes(sp)));
        e.mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(signer_ml_priv, new Bytes(sp)));
        return e;
    }

    // §A: read a <trustmanifest> element's base64 text child and unmarshal it.
    private Protocol.TrustManifest? unmarshal_manifest_node(StanzaNode? node) {
        if (node == null) return null;
        StanzaNode tm = node;
        if (node.name != "trustmanifest") {
            StanzaNode? inner = node.get_subnode("trustmanifest", Protocol.NS_TRUSTMANIFEST);
            if (inner != null) tm = (!) inner;
        }
        string? b64 = tm.get_string_content();
        if (b64 == null || b64 == "") return null;
        try {
            uint8[] raw = bytes_to_uint8_array(bytes_from_base64((!) b64));
            return Protocol.TrustManifest.unmarshal(raw);
        } catch (GLib.Error e) {
            return null;
        }
    }

    // §A: publish a manifest blob to trustmanifest:0 item "current" (open access,
    // single retained item). Does NOT persist locally — the caller runs
    // verify_and_apply_manifest afterwards which persists + writes trust tables.
    private async bool publish_trust_manifest_blob(XmppStream stream, Protocol.TrustManifest m) {
        string b64 = Base64.encode(m.marshal());
        StanzaNode node = new StanzaNode.build("trustmanifest", Protocol.NS_TRUSTMANIFEST)
            .add_self_xmlns()
            .put_node(new StanzaNode.text(b64));
        bool ok = yield stream.get_module(Pubsub.Module.IDENTITY).publish(stream, null,
            Protocol.NS_TRUSTMANIFEST, "current", node, MANIFEST_PUBLISH_OPTIONS);
        if (ok) {
            yield try_make_node_public(stream, Protocol.NS_TRUSTMANIFEST);
        } else {
            warning("publish_trust_manifest_blob: publish failed for %s", account.bare_jid.to_string());
        }
        return ok;
    }

    // §A fetch helper: fetch owner `jid`'s current manifest (own or a contact).
    public async Protocol.TrustManifest? fetch_trust_manifest(XmppStream stream, Jid jid) {
        StanzaNode pubsub = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_TRUSTMANIFEST)
                .put_node(new StanzaNode.build("item", Pubsub.NS_URI).put_attribute("id", "current")));
        Iq.Stanza iq = new Iq.Stanza.get(pubsub) { to = jid };
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            StanzaNode? item = result.stanza.get_deep_subnode(Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items", Pubsub.NS_URI + ":item");
            if (item == null || item.sub_nodes.size == 0) return null;
            return unmarshal_manifest_node(item.sub_nodes[0]);
        } catch (Error e) {
            return null;
        }
    }

    // §A inbound +notify handler.
    private void handle_manifest_event(XmppStream stream, Jid jid, string? id, StanzaNode? node) {
        Protocol.TrustManifest? m = unmarshal_manifest_node(node);
        if (m == null) {
            // Absent / unmarshal failure: leave the devicelist fallback path in
            // charge (never hard-fail the owner). §C fallback.
            return;
        }
        verify_and_apply_manifest(jid, ((!) m).marshal());
    }

    // §C gate: verify (AIK pin + version/rollback/fork + fold + head-sig under a
    // folded device) then write the folded device set into the trust tables. On
    // any REJECT, keep the last good state (do not wipe trust). Returns true if
    // the manifest was accepted and applied.
    private bool verify_and_apply_manifest(Jid jid, uint8[] bytes) {
        string bare = jid.bare_jid.to_string();
        bool is_self = jid.bare_jid.equals(account.bare_jid);

        // 1.
        Protocol.TrustManifest? m_ = Protocol.TrustManifest.unmarshal(bytes);
        if (m_ == null) return false;
        Protocol.TrustManifest m = (!) m_;

        // 2. AIK pinning (TOFU).
        uint8[] m_aik_ed = m.aik.pub_ed25519;
        uint8[] m_aik_ml = m.aik.pub_mldsa;
        if (is_self) {
            Row? row = db.get_local_identity(account.id);
            if (row == null) return false;
            string? ed_b64 = ((!) row)[db.account_identity.aik_pub_ed25519_base64];
            string? ml_b64 = ((!) row)[db.account_identity.aik_pub_mldsa_base64];
            if (ed_b64 == null || ml_b64 == null || ed_b64 == "" || ml_b64 == "") return false;
            try {
                if (!manifest_bytes_equal(m_aik_ed, bytes_to_uint8_array(bytes_from_base64((!) ed_b64)))
                        || !manifest_bytes_equal(m_aik_ml, bytes_to_uint8_array(bytes_from_base64((!) ml_b64)))) {
                    warning("x3dhpq: OWN trust manifest rejected — account AIK mismatch (root swap)");
                    return false;
                }
            } catch (GLib.Error e) { return false; }
        } else {
            Bytes pin_ed, pin_ml;
            if (db.get_peer_aik_pubs(account, bare, out pin_ed, out pin_ml)) {
                if (!manifest_bytes_equal(m_aik_ed, bytes_to_uint8_array(pin_ed))
                        || !manifest_bytes_equal(m_aik_ml, bytes_to_uint8_array(pin_ml))) {
                    warning("x3dhpq: trust manifest from %s rejected — AIK != pinned AIK (root swap)", bare);
                    db.flag_peer_devicelist_fork(account, bare);
                    return false;
                }
            } else {
                // First sight: pin the manifest's AIK (TOFU).
                db.pin_peer_aik_first_use(account, bare, m_aik_ed, m_aik_ml);
            }
        }

        // 3. Version / rollback / fork guard.
        long last = db.get_trust_manifest_version(account, bare);
        long ver = (long) m.version;
        string blob_hash = m.hash_hex();
        if (last >= 0) {
            if (ver < last) {
                warning("x3dhpq: trust manifest from %s rejected — version %ld < last %ld (rollback)", bare, ver, last);
                return false;
            }
            if (ver == last) {
                string? stored_hash = db.get_trust_manifest_blob_hash(account, bare);
                if (stored_hash != null && stored_hash != blob_hash) {
                    warning("x3dhpq: trust manifest from %s rejected — same version %ld, different blob (fork)", bare, ver);
                    return false;
                }
            }
        }

        // 4. Fold. An invalid genesis ⇒ empty fold ⇒ REJECT (keep last good).
        var folded = m.fold();
        if (folded.size == 0) {
            warning("x3dhpq: trust manifest from %s rejected — empty fold (invalid genesis)", bare);
            return false;
        }

        // 5. Head signature must verify under some folded device's DIK.
        bool head_ok = false;
        foreach (var en in folded.entries) {
            Protocol.DeviceCertificate dc = en.value;
            if (m.verify_head(dc.dik_pub_ed25519, dc.dik_pub_mldsa)) {
                head_ok = true;
                break;
            }
        }
        if (!head_ok) {
            warning("x3dhpq: trust manifest from %s rejected — head signature not by a member device", bare);
            return false;
        }

        // 6. Accept: persist blob/version/hash and write the folded set into the
        // trust tables (the same rows the send-time fanout reads).
        db.store_trust_manifest(account, bare, "current", Base64.encode(bytes), ver, blob_hash);
        var folded_ids = new Gee.ArrayList<int>();
        foreach (var en in folded.entries) {
            Protocol.DeviceCertificate dc = en.value;
            int did = (int) dc.device_id;
            folded_ids.add(did);
            db.store_remote_device(account, bare, did, Base64.encode(dc.marshal()), (long) dc.created_at, dc.flags, true);
        }
        db.prune_remote_devices_not_in(account, bare, folded_ids);
        var loaded = new ArrayList<int>();
        loaded.add_all(folded_ids);
        device_list_loaded(jid, loaded);
        return true;
    }

    // §D1: migration / genesis. Idempotent. Only an authorized device holding the
    // account AIK_priv builds the genesis manifest; every other device adopts what
    // that device published (via fetch/+notify). Called after publish_device_list.
    public async void ensure_trust_manifest(XmppStream stream) {
        string own_bare = account.bare_jid.to_string();

        // Already migrated locally? (a `current` manifest is recorded) → extend by
        // events, never rebuild genesis.
        if (db.get_trust_manifest_version(account, own_bare) >= 0) {
            return;
        }
        // The server may already hold a manifest (published by a sibling): adopt it.
        Protocol.TrustManifest? existing = yield fetch_trust_manifest(stream, account.bare_jid);
        if (existing != null) {
            verify_and_apply_manifest(account.bare_jid, ((!) existing).marshal());
            return;
        }
        // Genesis requires AIK_priv (the primary/first authorized device).
        if (!db.has_local_aik_priv(account)) {
            return;
        }
        try {
            yield build_and_publish_genesis_manifest(stream);
        } catch (GLib.Error e) {
            warning("ensure_trust_manifest: genesis build failed for %s: %s", own_bare, e.message);
        }
    }

    private async void build_and_publish_genesis_manifest(XmppStream stream) throws GLib.Error {
        string own_bare = account.bare_jid.to_string();
        int? self_id_n = db.get_local_device_id(account);
        if (self_id_n == null) throw new IOError.FAILED("no local device id");
        uint32 self_id = (uint32) (!) self_id_n;

        Row? row = db.get_local_identity(account.id);
        if (row == null) throw new IOError.FAILED("no local identity");
        Bytes aik_priv_ed = bytes_from_base64(((!) row)[db.account_identity.aik_priv_ed25519_base64]);
        Bytes aik_priv_ml = bytes_from_base64(((!) row)[db.account_identity.aik_priv_mldsa_base64]);
        Bytes aik_pub_ed = bytes_from_base64(((!) row)[db.account_identity.aik_pub_ed25519_base64]);
        Bytes aik_pub_ml = bytes_from_base64(((!) row)[db.account_identity.aik_pub_mldsa_base64]);
        Bytes dik_priv_ed = bytes_from_base64(((!) row)[db.account_identity.dik_priv_ed25519_base64]);
        Bytes dik_priv_ml = bytes_from_base64(((!) row)[db.account_identity.dik_priv_mldsa_base64]);

        // Self genesis DC (AIK-signed) — this is the account's genesis certificate.
        string self_cert_b64 = db.ensure_local_device_certificate(account);
        Protocol.DeviceCertificate? self_dc = Protocol.DeviceCertificate.unmarshal(bytes_from_base64(self_cert_b64));
        if (self_dc == null) throw new IOError.FAILED("cannot decode self genesis DC");
        uint8[] self_dc_hash = manifest_sha256(((!) self_dc).marshal());

        var aik_pub = new Protocol.AccountIdentityPub();
        aik_pub.pub_ed25519 = bytes_to_uint8_array(aik_pub_ed);
        aik_pub.pub_mldsa = bytes_to_uint8_array(aik_pub_ml);

        var m = new Protocol.TrustManifest();
        m.aik = aik_pub;
        m.prev_hash = new uint8[32];
        m.entries = new Gee.ArrayList<Protocol.TrustEntry>();

        // Genesis entry (AIK-signed, the only AIK-signed edge).
        var genesis = build_signed_trust_entry(Protocol.TrustEntry.ACTION_ADD, self_id, (!) self_dc,
            0, new Gee.ArrayList<Bytes>(), self_id, self_dc_hash, aik_priv_ed, aik_priv_ml);
        m.entries.add(genesis);

        // Each OTHER authorized device: RE-ISSUE its DC under the primary's DIK and
        // append a DIK-signed ADD entry parented on the current heads.
        foreach (Protocol.DeviceListDevice other in db.get_device_list_devices(account, own_bare)) {
            if (other.device_id == self_id) continue;
            if (other.cert_bytes.length == 0) continue;
            Protocol.DeviceCertificate? odc = Protocol.DeviceCertificate.unmarshal(new Bytes(other.cert_bytes));
            if (odc == null) continue;
            Protocol.DeviceCertificate reissued = Protocol.DeviceCertificate.issue(
                other.device_id,
                ((!) odc).dik_pub_ed25519,
                ((!) odc).dik_pub_x25519,
                ((!) odc).dik_pub_mldsa,
                dik_priv_ed, dik_priv_ml,
                ((!) odc).flags);
            var add = build_signed_trust_entry(Protocol.TrustEntry.ACTION_ADD, other.device_id, reissued,
                m.next_lamport(), m.current_heads(), self_id, self_dc_hash, dik_priv_ed, dik_priv_ml);
            m.entries.add(add);
        }

        // version = (last devicelist version) + 1.
        m.version = (uint64) (db.get_device_list_version(account, own_bare) + 1);
        m.sign_head(dik_priv_ed, dik_priv_ml);

        if (yield publish_trust_manifest_blob(stream, m)) {
            verify_and_apply_manifest(account.bare_jid, m.marshal());
        }
    }

    // §D2: at pairing confirmation, append a DIK-signed ADD for the newcomer and
    // publish. Replaces the AddDevice audit-entry publish on the pairing path.
    public async bool append_device_add_to_manifest(XmppStream stream, Protocol.DeviceCertificate newcomer_dc) {
        string own_bare = account.bare_jid.to_string();

        // Load the current manifest: freshest from the server, else local cache.
        Protocol.TrustManifest? m = yield fetch_trust_manifest(stream, account.bare_jid);
        if (m == null) {
            string? cached = db.get_trust_manifest_payload(account, own_bare);
            if (cached != null) {
                try {
                    m = Protocol.TrustManifest.unmarshal(bytes_to_uint8_array(bytes_from_base64((!) cached)));
                } catch (GLib.Error e) { m = null; }
            }
        }
        if (m == null) {
            // Not migrated yet — build genesis first, then reload.
            yield ensure_trust_manifest(stream);
            m = yield fetch_trust_manifest(stream, account.bare_jid);
            if (m == null) {
                string? cached2 = db.get_trust_manifest_payload(account, own_bare);
                if (cached2 != null) {
                    try {
                        m = Protocol.TrustManifest.unmarshal(bytes_to_uint8_array(bytes_from_base64((!) cached2)));
                    } catch (GLib.Error e) { m = null; }
                }
            }
        }
        if (m == null) {
            warning("append_device_add_to_manifest: no manifest available for %s", own_bare);
            return false;
        }

        int? self_id_n = db.get_local_device_id(account);
        if (self_id_n == null) return false;
        uint32 self_id = (uint32) (!) self_id_n;

        var fold = ((!) m).fold();
        if (!fold.has_key(self_id.to_string())) {
            warning("append_device_add_to_manifest: this device (%u) is not in the manifest fold — cannot author", self_id);
            return false;
        }
        Protocol.DeviceCertificate self_dc = fold.get(self_id.to_string());
        uint8[] self_dc_hash = manifest_sha256(self_dc.marshal());

        Row? row = db.get_local_identity(account.id);
        if (row == null) return false;
        Bytes dik_priv_ed, dik_priv_ml;
        try {
            dik_priv_ed = bytes_from_base64(((!) row)[db.account_identity.dik_priv_ed25519_base64]);
            dik_priv_ml = bytes_from_base64(((!) row)[db.account_identity.dik_priv_mldsa_base64]);
        } catch (GLib.Error e) {
            warning("append_device_add_to_manifest: cannot load local DIK priv: %s", e.message);
            return false;
        }

        try {
            uint8[] prev_hash = manifest_sha256(((!) m).marshal());   // before mutation
            var entry = build_signed_trust_entry(Protocol.TrustEntry.ACTION_ADD, newcomer_dc.device_id,
                newcomer_dc, ((!) m).next_lamport(), ((!) m).current_heads(),
                self_id, self_dc_hash, dik_priv_ed, dik_priv_ml);
            ((!) m).entries.add(entry);
            ((!) m).version = ((!) m).version + 1;
            ((!) m).prev_hash = prev_hash;
            ((!) m).sign_head(dik_priv_ed, dik_priv_ml);
        } catch (GLib.Error e) {
            warning("append_device_add_to_manifest: sign failed: %s", e.message);
            return false;
        }

        if (yield publish_trust_manifest_blob(stream, (!) m)) {
            verify_and_apply_manifest(account.bare_jid, ((!) m).marshal());
            return true;
        }
        return false;
    }

    // §D4: revoke a device by appending a DIK-signed REMOVE entry (removal-wins in
    // fold()). Mirrors append_device_add_to_manifest. The self-revoke guard lives
    // at the manager call site (remove_own_device). Returns true on publish+apply.
    public async bool append_device_remove_to_manifest(XmppStream stream, uint32 target_device_id) {
        string own_bare = account.bare_jid.to_string();

        // Load the current manifest: freshest from the server, else local cache.
        Protocol.TrustManifest? m = yield fetch_trust_manifest(stream, account.bare_jid);
        if (m == null) {
            string? cached = db.get_trust_manifest_payload(account, own_bare);
            if (cached != null) {
                try {
                    m = Protocol.TrustManifest.unmarshal(bytes_to_uint8_array(bytes_from_base64((!) cached)));
                } catch (GLib.Error e) { m = null; }
            }
        }
        if (m == null) {
            warning("append_device_remove_to_manifest: no manifest available for %s", own_bare);
            return false;
        }

        int? self_id_n = db.get_local_device_id(account);
        if (self_id_n == null) return false;
        uint32 self_id = (uint32) (!) self_id_n;

        var fold = ((!) m).fold();
        if (!fold.has_key(self_id.to_string())) {
            warning("append_device_remove_to_manifest: this device (%u) is not in the manifest fold — cannot author", self_id);
            return false;
        }
        if (!fold.has_key(target_device_id.to_string())) {
            // Already absent from the fold — nothing to revoke (idempotent).
            warning("append_device_remove_to_manifest: target %u not in fold — nothing to remove", target_device_id);
            return true;
        }
        Protocol.DeviceCertificate self_dc = fold.get(self_id.to_string());
        Protocol.DeviceCertificate target_dc = fold.get(target_device_id.to_string());
        uint8[] self_dc_hash = manifest_sha256(self_dc.marshal());

        Row? row = db.get_local_identity(account.id);
        if (row == null) return false;
        Bytes dik_priv_ed, dik_priv_ml;
        try {
            dik_priv_ed = bytes_from_base64(((!) row)[db.account_identity.dik_priv_ed25519_base64]);
            dik_priv_ml = bytes_from_base64(((!) row)[db.account_identity.dik_priv_mldsa_base64]);
        } catch (GLib.Error e) {
            warning("append_device_remove_to_manifest: cannot load local DIK priv: %s", e.message);
            return false;
        }

        try {
            uint8[] prev_hash = manifest_sha256(((!) m).marshal());   // before mutation
            var entry = build_signed_trust_entry(Protocol.TrustEntry.ACTION_REMOVE, target_device_id,
                target_dc, ((!) m).next_lamport(), ((!) m).current_heads(),
                self_id, self_dc_hash, dik_priv_ed, dik_priv_ml);
            ((!) m).entries.add(entry);
            ((!) m).version = ((!) m).version + 1;
            ((!) m).prev_hash = prev_hash;
            ((!) m).sign_head(dik_priv_ed, dik_priv_ml);
        } catch (GLib.Error e) {
            warning("append_device_remove_to_manifest: sign failed: %s", e.message);
            return false;
        }

        if (yield publish_trust_manifest_blob(stream, (!) m)) {
            verify_and_apply_manifest(account.bare_jid, ((!) m).marshal());
            return true;
        }
        return false;
    }

    // §D3: a freshly paired newcomer fetches + verifies + folds the account's own
    // manifest so it sees itself + siblings (once the confirmer's ADD lands).
    public async void fetch_and_apply_own_manifest(XmppStream stream) {
        Protocol.TrustManifest? m = yield fetch_trust_manifest(stream, account.bare_jid);
        if (m != null) {
            verify_and_apply_manifest(account.bare_jid, ((!) m).marshal());
        }
    }

    // §11.7 v1->v2 bridge / genesis. Idempotent — no-op once ANY device-audit
    // row already exists for this account (has_device_audit_entries), so this
    // only ever fires once per account, on whichever publish first has a
    // non-empty device union to assert. Builds a Snapshot (action=10) entry
    // over `devices` (the same union publish_device_list would otherwise
    // publish verbatim), hybrid-signs it with the account AIK, and persists it.
    // Devices with no persisted certificate are skipped (mirrors the union-build
    // skip above) since an uncertified device cannot be safely asserted either.
    // Never throws: any failure just leaves has_device_audit_entries() false, so
    // the DAG-derive step below stays a no-op and publish_device_list keeps
    // using the legacy union unchanged — bootstrap failure can never block a
    // devicelist publish.
    private void ensure_device_audit_genesis(Gee.List<Protocol.DeviceListDevice> devices) {
        if (db.has_device_audit_entries(account)) {
            return;
        }
        try {
            Bytes aik_pub_ed = db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64);
            Bytes aik_pub_ml = db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64);
            Bytes aik_priv_ed = db.get_local_identity_bytes(account, db.account_identity.aik_priv_ed25519_base64);
            Bytes aik_priv_ml = db.get_local_identity_bytes(account, db.account_identity.aik_priv_mldsa_base64);

            uint8[] aik_marshalled = Protocol.DeviceAuditEntryV2.aik_pub_marshal(
                bytes_to_uint8_array(aik_pub_ed), bytes_to_uint8_array(aik_pub_ml));
            uint8[] signer_fp = bytes_to_uint8_array(global::X3dhpq.Crypto.blake2b160(new Bytes(aik_marshalled)));

            var sp = new Protocol.DeviceSnapshotPayload();
            sp.owner_aik_fp = signer_fp;
            sp.epoch = 0;
            foreach (Protocol.DeviceListDevice d in devices) {
                if (d.cert_bytes.length == 0) {
                    continue;
                }
                var sd = new Protocol.DeviceSnapshotDevice();
                sd.device_id = d.device_id;
                sd.cert_bytes = d.cert_bytes;
                sp.devices.add(sd);
            }
            if (sp.devices.size == 0) {
                // Nothing certifiable to assert yet (e.g. cert issuance still
                // pending) — try again on the next publish rather than persisting
                // an empty genesis.
                return;
            }

            int? local_device_id = db.get_local_device_id(account);
            var genesis = new Protocol.DeviceAuditEntryV2();
            genesis.lamport = 0;
            genesis.signer_fp = signer_fp;
            genesis.author_device_id = local_device_id != null ? (uint32) (!) local_device_id : 0;
            genesis.parents = new Gee.ArrayList<Bytes>();
            genesis.action = (uint8) Protocol.DeviceAuditActionV2.SNAPSHOT;
            genesis.payload = Protocol.DeviceAuditEntryV2.build_snapshot_payload(sp);
            genesis.timestamp = new DateTime.now_utc().to_unix();

            uint8[] signed_part = genesis.signed_part();
            genesis.signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(signed_part)));
            genesis.mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(aik_priv_ml, new Bytes(signed_part)));

            db.store_device_audit_entry(account, genesis);
        } catch (GLib.Error e) {
            warning("x3dhpq: unable to bootstrap device-audit genesis snapshot for %s: %s",
                account.bare_jid.to_string(), e.message);
        }
    }

    // §11.7: attempt to rebuild the published device union from the persisted
    // device-audit DAG fold instead of the legacy peer_device union. Returns
    // null on ANY reason to distrust the fold (no entries yet, the resolver
    // can't establish the local AIK, or the fold authorizes an empty set) so
    // the caller's SAFETY FALLBACK to the untouched legacy union is exact.
    // `legacy_by_id` supplies the wire metadata (added_at/flags) for any device
    // id the fold and the legacy union agree on, so switching the source set
    // does not change the published SignedPart bytes (§8.3) in the common case
    // where the fold has not yet diverged from the union it was seeded from.
    private Gee.List<Protocol.DeviceListDevice>? try_derive_devices_from_dag(
            Gee.HashMap<uint32, Protocol.DeviceListDevice> legacy_by_id) {
        Gee.List<Protocol.DeviceAuditEntryV2> entries = db.list_device_audit_entries(account);
        if (entries.size == 0) {
            return null;
        }

        Bytes aik_pub_ed;
        Bytes aik_pub_ml;
        string local_fp_hex;
        try {
            aik_pub_ed = db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64);
            aik_pub_ml = db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64);
            uint8[] aik_marshalled = Protocol.DeviceAuditEntryV2.aik_pub_marshal(
                bytes_to_uint8_array(aik_pub_ed), bytes_to_uint8_array(aik_pub_ml));
            local_fp_hex = Protocol.hex_of(bytes_to_uint8_array(global::X3dhpq.Crypto.blake2b160(new Bytes(aik_marshalled))));
        } catch (GLib.Error e) {
            return null;
        }

        var dag = new Protocol.DeviceDag();
        foreach (Protocol.DeviceAuditEntryV2 e in entries) {
            dag.ingest(e.marshal());
        }

        // Mirrors tests/device_dag.vala's resolver: a single-signer account, so
        // the resolver just confirms the requested fp is OUR pinned AIK fp and
        // hands back its public halves; anything else is an entry the DAG must
        // reject (a foreign signer could never legitimately appear here).
        Protocol.DeviceAikResolver resolver = (fp_hex, out ed, out ml) => {
            if (fp_hex != local_fp_hex) {
                ed = new Bytes(new uint8[0]);
                ml = new Bytes(new uint8[0]);
                return false;
            }
            ed = aik_pub_ed;
            ml = aik_pub_ml;
            return true;
        };

        Protocol.DeviceState st = dag.recompute(resolver);
        if (st.authorized.size == 0) {
            return null;
        }

        var result = new Gee.ArrayList<Protocol.DeviceListDevice>();
        foreach (var kv in st.authorized.entries) {
            Protocol.DeviceCertificate dc = kv.value;
            var d = new Protocol.DeviceListDevice();
            d.device_id = dc.device_id;
            d.cert_bytes = dc.marshal();
            if (legacy_by_id.has_key(dc.device_id)) {
                Protocol.DeviceListDevice legacy = legacy_by_id[dc.device_id];
                d.added_at = legacy.added_at;
                d.flags = legacy.flags;
            } else {
                // A device the fold authorizes that the legacy union never saw
                // (not reachable yet in this owner-only-genesis phase, but kept
                // safe for when Add/RemoveDevice entries start being appended).
                d.added_at = new DateTime.now_utc().to_unix();
                d.flags = dc.flags;
            }
            result.add(d);
        }
        return result;
    }

    // Republish the account's signed devicelist while explicitly permitting the
    // shrink guard in publish_device_list to drop exactly one device id (the
    // §8.6 revocation path). Callers MUST have already removed the id from the
    // account's own persisted device set (db.delete_own_device) so the rebuilt
    // union no longer lists it; the version bumps because the content changed.
    public async void republish_device_list_removing(XmppStream stream, uint32 removed_device_id) {
        var allow = new Gee.HashSet<uint32>();
        allow.add(removed_device_id);
        yield publish_device_list(stream, allow);
    }

    // Parse the <device id="..."> ids from a previously committed own-list XML
    // payload (Database.get_device_list_payload_xml). Returns an empty set for
    // null/empty input or on parse failure. Used only by the publish-time shrink
    // guard, whose reference set is the last authoritative own devicelist.
    // Device ids from the last committed own devicelist, read from the stored
    // content_key ("id|added_at|flags|cert" entries joined by ';'; see
    // build_device_content_key). This is the independent last-committed reference
    // for the shrink guard. NB: the stored payload is StanzaNode.to_string()'s
    // internal "{ns}:name" debug form, NOT real XML, so it cannot be re-parsed —
    // the content_key is the reparseable source.
    private Gee.Set<uint32> parse_own_devicelist_ids(string? content_key) {
        var ids = new Gee.HashSet<uint32>();
        if (content_key == null || ((!) content_key).length == 0) {
            return ids;
        }
        foreach (string entry in ((!) content_key).split(";")) {
            if (entry.length == 0) continue;
            string[] parts = entry.split("|", 2);
            int id = int.parse(parts[0]);
            if (id > 0) {
                ids.add((uint32) id);
            }
        }
        return ids;
    }

    // Canonical device-set key for one device: "id|added_at|flags|cert". Used to
    // decide own-version bumps (§8.2) and detect same-version forks (§8.5);
    // deliberately excludes version/issued_at.
    private static string build_device_content_key_single(uint32 device_id, int64 added_at, uint8 flags, string cert_b64) {
        return @"$device_id|$added_at|$flags|$cert_b64";
    }

    // Canonical content key for a device SET: per-device keys (sorted by
    // device_id ascending) joined with ';'. Shared by publish_device_list (own
    // account union) and parse_device_list (inbound lists) so both sides compare
    // on an identical representation — required for version-bump/fork detection
    // to agree regardless of which side computed it.
    private static string build_device_content_key(Gee.List<Protocol.DeviceListDevice> devices) {
        var sorted = new Gee.ArrayList<Protocol.DeviceListDevice>();
        sorted.add_all(devices);
        sorted.sort((a, b) => (a.device_id < b.device_id) ? -1 : (a.device_id > b.device_id ? 1 : 0));
        StringBuilder ck = new StringBuilder();
        foreach (Protocol.DeviceListDevice e in sorted) {
            if (ck.len > 0) ck.append(";");
            ck.append(build_device_content_key_single(e.device_id, e.added_at, e.flags, Base64.encode(e.cert_bytes)));
        }
        return ck.str;
    }

    private async void publish_bundle(XmppStream stream) {
        Row? bundle_row = db.get_local_bundle(account);
        int? device_id = db.get_local_device_id(account);
        if (bundle_row == null || device_id == null) {
            return;
        }

        string? dc_value = ((!) bundle_row)[db.bundle.device_certificate_base64];
        if (dc_value == null || dc_value == "") {
            warning("Refusing to publish x3dhpq bundle with empty device certificate for %s",
                account.bare_jid.to_string());
            return;
        }

        StanzaNode bundle_node = new StanzaNode.build("bundle", Protocol.NS_BUNDLE)
            .add_self_xmlns()
            .put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(get_local_identity_value(db.account_identity.aik_pub_ed25519_base64))))
            .put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(get_local_identity_value(db.account_identity.aik_pub_mldsa_base64))))
            .put_node(new StanzaNode.build("dc", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(((!) bundle_row)[db.bundle.device_certificate_base64])))
            .put_node(new StanzaNode.build("dik-ed25519", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(get_local_identity_value(db.account_identity.dik_pub_ed25519_base64))))
            .put_node(new StanzaNode.build("ik", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(get_local_identity_value(db.account_identity.dik_pub_x25519_base64))))
            .put_node(new StanzaNode.build("dik-mldsa", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(get_local_identity_value(db.account_identity.dik_pub_mldsa_base64))));

        int signed_pre_key_id = ((!) bundle_row)[db.bundle.signed_pre_key_id];
        string? signed_pre_key_public = ((!) bundle_row)[db.bundle.signed_pre_key_public_base64];
        string? signed_pre_key_sig = ((!) bundle_row)[db.bundle.signed_pre_key_signature_ed25519_base64];
        if (signed_pre_key_public != null && signed_pre_key_sig != null) {
            bundle_node.put_node(new StanzaNode.build("spk", Protocol.NS_BUNDLE)
                .put_attribute("id", signed_pre_key_id.to_string())
                .put_node(new StanzaNode.build("key", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(signed_pre_key_public)))
                .put_node(new StanzaNode.build("sig", Protocol.NS_BUNDLE).put_node(new StanzaNode.text(signed_pre_key_sig))));
        }

        StanzaNode kemkeys = new StanzaNode.build("kemkeys", Protocol.NS_BUNDLE);
        foreach (Row row in db.get_local_kem_pre_keys(account)) {
            kemkeys.put_node(new StanzaNode.build("kemkey", Protocol.NS_BUNDLE)
                .put_attribute("id", row[db.kem_pre_key.key_id].to_string())
                .put_node(new StanzaNode.text(row[db.kem_pre_key.public_base64])));
        }
        bundle_node.put_node(kemkeys);

        StanzaNode opks = new StanzaNode.build("opks", Protocol.NS_BUNDLE);
        foreach (Row row in db.get_local_one_time_pre_keys(account)) {
            opks.put_node(new StanzaNode.build("opk", Protocol.NS_BUNDLE)
                .put_attribute("id", row[db.one_time_pre_key.key_id].to_string())
                .put_node(new StanzaNode.text(row[db.one_time_pre_key.public_base64])));
        }
        bundle_node.put_node(opks);

        if (yield stream.get_module(Pubsub.Module.IDENTITY).publish(stream, null, Protocol.NS_BUNDLE, ((!) device_id).to_string(), bundle_node, PUBLISH_OPTIONS)) {
            yield try_make_node_public(stream, Protocol.NS_BUNDLE);
            db.store_bundle_payload(account, account.bare_jid.to_string(), (!) device_id, bundle_node);
            db.mark_local_bundle_published(account);
        }
    }

    private async void try_make_node_public(XmppStream stream, string node_id) {
        DataForms.DataForm? data_form = yield stream.get_module(Pubsub.Module.IDENTITY).request_node_config(stream, null, node_id);
        if (data_form == null) {
            return;
        }

        foreach (DataForms.DataForm.Field field in data_form.fields) {
            if (field.var == "pubsub#access_model" && field.get_value_string() != Pubsub.ACCESS_MODEL_OPEN) {
                field.set_value_string(Pubsub.ACCESS_MODEL_OPEN);
                yield stream.get_module(Pubsub.Module.IDENTITY).submit_node_config(stream, data_form, node_id);
                break;
            }
        }
    }

    private ArrayList<int> parse_device_list(XmppStream stream, Jid jid, string? id, StanzaNode? node_) {
        ArrayList<int> devices = new ArrayList<int>();
        StanzaNode node = node_ ?? new StanzaNode.build("devicelist", Protocol.NS_DEVICELIST).add_self_xmlns();
        string bare = jid.bare_jid.to_string();
        bool is_self = jid.bare_jid.equals(account.bare_jid);

        // Trust Manifest Phase 2 (§C): once a manifest exists for this owner it is
        // the LIVE trust source — the manifest gate (handle_manifest_event /
        // verify_and_apply_manifest) already wrote the authoritative folded set
        // into the trust tables. The devicelist is a derived cache only, so do NOT
        // let the legacy AIK-attested path re-decide trust here (its dc_attested
        // check would wrongly drop DIK-delegated siblings). Surface the current
        // known ids and return. When no manifest exists, fall through to the
        // legacy path unchanged (§C fallback).
        if (db.get_trust_manifest_version(account, bare) >= 0) {
            foreach (int existing_id in db.get_remote_device_ids(account, bare)) {
                devices.add(existing_id);
            }
            device_list_loaded(jid, devices);
            return devices;
        }

        // Collect device entries once; keep cert base64 + added_at for storage.
        var entries = new Gee.ArrayList<Protocol.DeviceListDevice>();
        var cert_by_id = new Gee.HashMap<int, string?>();
        var added_by_id = new Gee.HashMap<int, long?>();
        foreach (StanzaNode device_node in node.get_subnodes("device", Protocol.NS_DEVICELIST)) {
            int device_id = device_node.get_attribute_int("id");
            StanzaNode? cert_node = device_node.get_subnode("cert", Protocol.NS_DEVICELIST);
            string? cert_b64 = cert_node != null ? cert_node.get_string_content() : null;
            // XEP §8.4: added-at is part of the signed input (§8.3). Absent
            // (legacy peer) => 0.
            string? added_at_str = device_node.get_attribute("added-at");
            long added_at = added_at_str != null ? (long) int64.parse((!) added_at_str) : 0;
            int flags = device_node.get_attribute_int("flags");
            if (flags < 0) flags = 0;
            var e = new Protocol.DeviceListDevice();
            e.device_id = (uint32) device_id;
            e.added_at = added_at;
            e.flags = (uint8) flags;
            try {
                e.cert_bytes = cert_b64 != null ? bytes_to_uint8_array(bytes_from_base64(cert_b64)) : new uint8[0];
            } catch (GLib.Error err) {
                e.cert_bytes = new uint8[0];
            }
            entries.add(e);
            cert_by_id[device_id] = cert_b64;
            added_by_id[device_id] = added_at;
        }

        // Canonical content key (sorted by device_id), excluding version/issued_at.
        // Shared with publish_device_list's own-account union so both sides
        // agree on the same representation for version-bump/fork detection.
        string content_key = build_device_content_key(entries);

        // The account's own devicelist echo: version/content are maintained by
        // publish_device_list; just refresh the stored payload (sentinels keep
        // the version/signed/content columns intact) and surface the ids.
        if (!is_self) {
            long accepted_version;
            bool accepted_signed;
            bool accept = verify_inbound_devicelist(jid, node, entries, content_key,
                out accepted_version, out accepted_signed);
            if (!accept) {
                // Rejected (rollback/fork/bad-sig/downgrade). Keep the last good
                // state and surface the previously verified device ids.
                foreach (int existing_id in db.get_remote_device_ids(account, bare)) {
                    devices.add(existing_id);
                }
                return devices;
            }
            foreach (Protocol.DeviceListDevice e in entries) {
                int did = (int) e.device_id;
                devices.add(did);
                db.store_remote_device(account, bare, did, cert_by_id[did], added_by_id[did] ?? 0, e.flags);
            }
            db.store_device_list_payload(account, bare, id, node.to_string(),
                accepted_version, accepted_signed, content_key);
            // The published devicelist is authoritative — drop cached peer_device
            // / bundle / pairwise_session rows for ids no longer present (§8.6).
            db.prune_remote_devices_not_in(account, bare, devices);
            device_list_loaded(jid, devices);
            return devices;
        }

        // §10.6.3 trust gating for our OWN devicelist. Two independent checks,
        // both fail-closed:
        //  1. The list MUST verify against OUR OWN CURRENT AIK — never deferred.
        //     A stale pre-reset list (signed by an OLD AIK the server still
        //     happens to serve) must not resurrect its dead devices; unlike a
        //     peer list we never defer this to "first contact" since we always
        //     know our own AIK once ensure_local_identity has run.
        //  2. Within an otherwise-valid list, a sibling device_id (not this
        //     install's own local device_id) is only trusted as a co-account
        //     device if it is covered by a valid, chain-verified AddDevice audit
        //     entry (§11.4) — devicelist presence ALONE is never sufficient,
        //     closing the "rogue self-addition silently trusted" gap.
        int? local_device_id = db.get_local_device_id(account);
        if (!verify_own_device_list_signature(node, entries)) {
            warning("x3dhpq: OWN devicelist for %s failed AIK signature verification — " +
                "ignoring (stale/forked list, §10.6.3)", bare);
            foreach (int existing_id in db.get_remote_device_ids(account, bare)) {
                devices.add(existing_id);
            }
            return devices;
        }
        Gee.Set<int> revoked = db.get_revoked_device_ids(account);
        // §10.6.3 (trust-manifest model): trust = AIK-ATTESTED MEMBERSHIP. A
        // sibling is trusted iff its embedded DC verifies (both hybrid sigs)
        // under the CURRENT account AIK — no genesis-rooted audit chain, no
        // fail-closed on a missing genesis. The whole list was already
        // signature-verified above; here we drop any single entry whose DC is
        // NOT attested by the current AIK (a stale/phantom device signed by an
        // old AIK), tolerating one bad entry instead of rejecting the list.
        Bytes? aik_ed = null;
        Bytes? aik_mldsa = null;
        Row? aik_row = db.get_local_identity(account.id);
        if (aik_row != null) {
            string? ed_b64 = ((!) aik_row)[db.account_identity.aik_pub_ed25519_base64];
            string? ml_b64 = ((!) aik_row)[db.account_identity.aik_pub_mldsa_base64];
            if (ed_b64 != null && ed_b64 != "" && ml_b64 != null && ml_b64 != "") {
                aik_ed = bytes_from_base64((!) ed_b64);
                aik_mldsa = bytes_from_base64((!) ml_b64);
            }
        }
        var trusted_devices = new ArrayList<int>();
        foreach (Protocol.DeviceListDevice e in entries) {
            int did = (int) e.device_id;
            // §8.6 tombstone: a device we explicitly revoked must never be re-seeded.
            if (revoked.contains(did)) {
                warning("x3dhpq: dropping revoked device %d re-advertised in own devicelist (§8.6 tombstone)", did);
                continue;
            }
            bool is_own_local = local_device_id != null && did == (!) local_device_id;
            bool dc_attested = false;
            if (aik_ed != null && aik_mldsa != null && e.cert_bytes != null && e.cert_bytes.length > 0) {
                Protocol.DeviceCertificate? dc = Protocol.DeviceCertificate.unmarshal(new Bytes(e.cert_bytes));
                if (dc != null) {
                    try {
                        dc_attested = ((!) dc).verify((!) aik_ed, (!) aik_mldsa);
                    } catch (GLib.Error err) {
                        dc_attested = false;
                    }
                }
            }
            if (is_own_local || dc_attested) {
                devices.add(did);
                trusted_devices.add(did);
                db.store_remote_device(account, bare, did, cert_by_id[did], added_by_id[did] ?? 0, e.flags, true);
            } else {
                // DC not attested by the current AIK → not a member. Drop it
                // (do not trust, do not surface as pending, do not keep for
                // pruning) so a phantom/old-AIK entry cannot poison the list.
                warning("x3dhpq: dropping device %d from own devicelist — DC not attested by the current AIK (not a member)", did);
            }
        }
        db.store_device_list_payload(account, bare, id, node.to_string());
        // Prune against the FULL announced set (devices), not just the
        // chain-confirmed one — otherwise the inactive rows just stored above
        // for unconfirmed siblings would be deleted immediately by this same
        // pass. A device disappearing entirely from the signed list (confirmed
        // or not) is still torn down, per §8.6.
        db.prune_remote_devices_not_in(account, bare, devices);
        device_list_loaded(jid, trusted_devices);
        return trusted_devices;
    }

    // Verifies an inbound OWN-account devicelist against our CURRENT local AIK
    // (never deferred — see the §10.6.3 comment at the call site).
    private bool verify_own_device_list_signature(StanzaNode node, Gee.List<Protocol.DeviceListDevice> entries) {
        Row? identity = db.get_local_identity(account.id);
        if (identity == null) {
            return false; // no local AIK yet (still pending) — nothing to verify against
        }
        string? aik_ed_b64 = ((!) identity)[db.account_identity.aik_pub_ed25519_base64];
        string? aik_ml_b64 = ((!) identity)[db.account_identity.aik_pub_mldsa_base64];
        if (aik_ed_b64 == null || aik_ml_b64 == null) {
            return false;
        }
        long version = (long) int64.parse(node.get_attribute("version") ?? "0");
        long issued_at = (long) int64.parse(node.get_attribute("issued-at") ?? "0");
        StanzaNode? sig_node = node.get_subnode("sig", Protocol.NS_DEVICELIST);
        StanzaNode? mldsa_node = node.get_subnode("mldsa-sig", Protocol.NS_DEVICELIST);
        string? sig_b64 = sig_node != null ? sig_node.get_string_content() : null;
        string? mldsa_b64 = mldsa_node != null ? mldsa_node.get_string_content() : null;
        if (sig_b64 == null || sig_b64 == "" || mldsa_b64 == null || mldsa_b64 == "") {
            // Unsigned self-list: only acceptable before we ever bootstrapped an
            // AIK, which can't be the case here since get_local_identity succeeded.
            return false;
        }
        try {
            Bytes aik_ed = bytes_from_base64(aik_ed_b64);
            Bytes aik_mldsa = bytes_from_base64(aik_ml_b64);
            uint8[] sp = Protocol.DeviceListSigned.signed_part((uint64) version, issued_at, entries);
            Bytes ed_sig = bytes_from_base64((!) sig_b64);
            Bytes ml_sig = bytes_from_base64((!) mldsa_b64);
            return global::X3dhpq.Crypto.ed25519_verify(aik_ed, new Bytes(sp), ed_sig)
                && global::X3dhpq.Crypto.mldsa65_verify(aik_mldsa, new Bytes(sp), ml_sig);
        } catch (GLib.Error e) {
            warning("verify_own_device_list_signature: decode/verify error: %s", e.message);
            return false;
        }
    }

    // §10.6.3: the set of device ids covered by a chain-verified AddDevice entry
    // (minus any later chain-verified RemoveDevice) in OUR OWN account audit
    // chain. Presence in db.list_account_audit_entries is itself proof of prior
    // verification — store_account_audit_entry (database.vala) is only ever
    // called after Protocol.AccountAuditChain.verify_and_apply succeeds
    // (handle_audit_event, above), so this fails closed: an empty/unfetched
    // chain confirms nothing.
    private Gee.Set<int> audit_chain_confirmed_device_ids() {
        var ids = new Gee.HashSet<int>();
        foreach (Protocol.AuditEntry entry in db.list_account_audit_entries(account)) {
            if (entry.action == (uint8) Protocol.AccountAuditAction.ADD_DEVICE) {
                int? did = parse_device_id_from_audit_payload(entry.payload);
                if (did != null) ids.add((!) did);
            } else if (entry.action == (uint8) Protocol.AccountAuditAction.REMOVE_DEVICE) {
                int? did = parse_device_id_from_audit_payload(entry.payload);
                if (did != null) ids.remove((!) did);
            }
        }
        return ids;
    }

    // AddDevice/RemoveDevice payload (§11.4): uint32(device_id) [| uint32(cert_len) | cert],
    // big-endian. RemoveDevice payload is exactly the 4-byte device_id.
    private int? parse_device_id_from_audit_payload(uint8[] payload) {
        if (payload.length < 4) return null;
        uint32 did = ((uint32) payload[0] << 24) | ((uint32) payload[1] << 16)
                   | ((uint32) payload[2] << 8) | (uint32) payload[3];
        return (int) did;
    }

    // Apply the §8.5 verification/version gate for an inbound peer devicelist.
    // Returns true to ACCEPT (caller stores devices + version + content); false
    // to REJECT (caller keeps the last good state). On accept, out_version /
    // out_signed carry the version and the sticky signed flag to persist.
    private bool verify_inbound_devicelist(Jid jid, StanzaNode node,
            Gee.List<Protocol.DeviceListDevice> entries, string content_key,
            out long out_version, out bool out_signed) {
        string bare = jid.bare_jid.to_string();
        long version = (long) int64.parse(node.get_attribute("version") ?? "0");
        long issued_at = (long) int64.parse(node.get_attribute("issued-at") ?? "0");
        out_version = version;
        out_signed = false;

        StanzaNode? sig_node = node.get_subnode("sig", Protocol.NS_DEVICELIST);
        StanzaNode? mldsa_node = node.get_subnode("mldsa-sig", Protocol.NS_DEVICELIST);
        string? sig_b64 = sig_node != null ? sig_node.get_string_content() : null;
        string? mldsa_b64 = mldsa_node != null ? mldsa_node.get_string_content() : null;
        bool has_sig = sig_b64 != null && sig_b64 != "" && mldsa_b64 != null && mldsa_b64 != "";

        long last_version = db.get_device_list_version(account, bare);
        bool signed_before = db.get_device_list_signed_accepted(account, bare);
        string? last_content_key = db.get_device_list_content_key(account, bare);

        // Transitional rule (§8.5): an unsigned list is acceptable ONLY if we have
        // never yet accepted a signed list for this account. Once signed, an
        // unsigned list is a downgrade attempt and MUST be rejected.
        if (!has_sig) {
            if (signed_before) {
                warning("x3dhpq devicelist from %s rejected: unsigned after a signed list was accepted (downgrade)", bare);
                return false;
            }
            out_signed = false;
            return true;   // legacy unsigned peer, provisionally accepted
        }

        // Signed path: we need the peer AIK to verify. First contact (AIK unknown)
        // — defer the gate rather than hard-fail so we can still learn the peer.
        Bytes aik_ed;
        Bytes aik_mldsa;
        if (!db.get_peer_aik_pubs(account, bare, out aik_ed, out aik_mldsa)) {
            out_signed = false;   // do not arm the signed gate until AIK is known
            return true;
        }

        // Reconstruct the SignedPart (§8.3) and verify BOTH AIK signatures (§7.7).
        uint8[] sp = Protocol.DeviceListSigned.signed_part((uint64) version, issued_at, entries);
        try {
            Bytes ed_sig = bytes_from_base64((!) sig_b64);
            Bytes ml_sig = bytes_from_base64((!) mldsa_b64);
            bool ok = global::X3dhpq.Crypto.ed25519_verify(aik_ed, new Bytes(sp), ed_sig)
                   && global::X3dhpq.Crypto.mldsa65_verify(aik_mldsa, new Bytes(sp), ml_sig);
            if (!ok) {
                warning("x3dhpq devicelist from %s rejected: AIK signature does not verify", bare);
                // §10.6.5: a signed list that fails to verify against the AIK we
                // already have pinned for this peer looks like a silent identity
                // reconstruction (new AIK, same JID) — never auto-accept it, and
                // flag it for the existing "Review"/"Accept new identity" UX
                // (contact_details_provider.vala) instead of silently dropping it.
                db.flag_peer_devicelist_fork(account, bare);
                return false;
            }
        } catch (GLib.Error e) {
            warning("x3dhpq devicelist from %s rejected: signature decode/verify error: %s", bare, e.message);
            return false;
        }

        // Clock-skew guard (§8.5): issued_at more than 300s in the future.
        long now = (long) new DateTime.now_utc().to_unix();
        if (issued_at > now + 300) {
            warning("x3dhpq devicelist from %s rejected: issued_at too far in the future", bare);
            return false;
        }

        // Version rules (§8.5): reject rollback and same-version forks.
        if (version < last_version) {
            warning("x3dhpq devicelist from %s rejected: version %ld < last seen %ld (rollback)", bare, version, last_version);
            return false;
        }
        if (version == last_version) {
            if (signed_before && last_content_key != null && last_content_key != content_key) {
                warning("x3dhpq devicelist from %s rejected: same version %ld but different content (fork)", bare, version);
                return false;
            }
            out_signed = true;   // idempotent no-op / first signed at this version
            return true;
        }

        // version > last_version: verify each embedded DC against the AIK (§7.3).
        foreach (Protocol.DeviceListDevice e in entries) {
            Protocol.DeviceCertificate? dc = Protocol.DeviceCertificate.unmarshal(new Bytes(e.cert_bytes));
            if (dc == null) {
                warning("x3dhpq devicelist from %s rejected: undecodable DC for device %u", bare, e.device_id);
                return false;
            }
            try {
                if (!dc.verify(aik_ed, aik_mldsa)) {
                    warning("x3dhpq devicelist from %s rejected: DC for device %u fails AIK verification", bare, e.device_id);
                    return false;
                }
            } catch (GLib.Error err) {
                warning("x3dhpq devicelist from %s rejected: DC verify error for device %u: %s", bare, e.device_id, err.message);
                return false;
            }
        }
        out_signed = true;
        return true;
    }

    private void parse_bundle(XmppStream stream, Jid jid, int device_id, StanzaNode? node) {
        if (node == null) {
            return;
        }
        db.store_bundle_payload(account, jid.bare_jid.to_string(), device_id, node);
        bundle_fetched(jid, device_id, node);
    }

    private string get_local_identity_value(Column<string> column) {
        Row? identity = db.get_local_identity(account.id);
        assert(identity != null);
        return ((!) identity)[column];
    }

    private void handle_audit_event(XmppStream stream, Jid from, string? id, StanzaNode? item_node) {
        // X3DHPQ XEP §11. Server is transport-only; client verifies the chain.
        // Surface the opaque payload so higher layers can store and inspect it,
        // and also route through AccountAuditChain for verification.
        string? payload = item_node != null ? item_node.get_string_content() : null;
        if (payload == null) {
            return;
        }
        audit_entry_received(from, id, payload);

        // Route through AccountAuditChain if we have local AIK material.
        // The chain is lazily created the first time an audit event arrives.
        uint8[] raw = Base64.decode(payload);
        Protocol.AuditEntry? entry = Protocol.AuditEntry.unmarshal(raw);
        if (entry == null) {
            warning("handle_audit_event: failed to unmarshal AuditEntry from %s", from.to_string());
            return;
        }
        Row? identity_row = db.get_local_identity(account.id);
        if (identity_row == null) {
            return;
        }
        string? aik_ed_b64   = identity_row[db.account_identity.aik_pub_ed25519_base64];
        string? aik_ml_b64   = identity_row[db.account_identity.aik_pub_mldsa_base64];
        if (aik_ed_b64 == null || aik_ml_b64 == null) {
            return;
        }
        Bytes aik_ed  = bytes_from_base64(aik_ed_b64);
        Bytes aik_ml  = bytes_from_base64(aik_ml_b64);

        if (audit_chain == null) {
            audit_chain = new Protocol.AccountAuditChain(db);
            audit_chain.audit_entry_observed.connect((action, detail) => {
                account_audit_event(action, detail);
            });
            // Live PEP +notify only carries the single newest audit item, so seed the
            // verifier from the persisted tail — otherwise a legitimate seq=N entry is
            // rejected against a fresh next_seq=0 ("seq mismatch: expected 0 got N").
            audit_chain.seed_from_persisted(db.list_account_audit_entries(account));
        }

        // Already applied (e.g. our own PEP self-echo of an entry we just published,
        // or a duplicate notification): nothing to do.
        if (entry.seq < audit_chain.expected_next_seq()) {
            return;
        }

        // Gap: we missed one or more intermediate entries (this device was offline
        // across several audit events, which live +notify never backfills). Fetch the
        // full audit-node history and re-verify from genesis instead of rejecting the
        // newest item as out-of-order.
        if (entry.seq > audit_chain.expected_next_seq()) {
            fetch_audit_history.begin(stream);
            return;
        }

        var entries = new Gee.ArrayList<Protocol.AuditEntry>();
        entries.add(entry);
        try {
            audit_chain.verify_and_apply(account.id, aik_ed, aik_ml, entries);
            // Persist verified entries for OUR OWN account so the local audit-chain
            // tail (seq + prev_hash) is known when we later append a
            // locally-originated entry such as RemoveDevice (§8.6/§11.4).
            if (from.bare_jid.equals(account.bare_jid)) {
                db.store_account_audit_entry(account, entry);
            }
        } catch (Protocol.AccountAuditError e) {
            warning("handle_audit_event: chain verification failed: %s", e.message);
        }
    }

    // Fetch the FULL account audit-node history (all persisted items) and re-verify
    // the chain from genesis. Live PEP +notify only ever carries the single newest
    // item, so a device that was offline across several audit events cannot catch up
    // from notifications alone. Called on a detected seq gap in handle_audit_event.
    private bool audit_history_fetch_in_flight = false;
    public async void fetch_audit_history(XmppStream stream) {
        if (audit_history_fetch_in_flight) {
            return;   // coalesce concurrent gap triggers
        }
        audit_history_fetch_in_flight = true;
        try {
            StanzaNode pubsub_node = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
                .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                    .put_attribute("node", Protocol.NS_AUDIT));
            Iq.Stanza iq = new Iq.Stanza.get(pubsub_node);
            iq.to = account.bare_jid;
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            if (result.is_error()) {
                warning("fetch_audit_history: request failed");
                return;
            }
            StanzaNode? items_node = result.stanza.get_deep_subnode(
                Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items");
            if (items_node == null) {
                return;
            }

            var fetched = new Gee.ArrayList<Protocol.AuditEntry>();
            foreach (StanzaNode item in items_node.get_subnodes("item", Pubsub.NS_URI)) {
                StanzaNode? entry_node = item.get_subnode("audit-entry", Protocol.NS_AUDIT);
                string? b64 = entry_node != null ? entry_node.get_string_content() : null;
                if (b64 == null) continue;
                Protocol.AuditEntry? e = Protocol.AuditEntry.unmarshal(Base64.decode(b64));
                if (e != null) fetched.add(e);
            }
            if (fetched.size == 0) {
                return;
            }
            // Items may arrive in any order; verify_and_apply requires oldest→newest.
            fetched.sort((a, b) => {
                if (a.seq < b.seq) return -1;
                if (a.seq > b.seq) return 1;
                return 0;
            });

            Row? identity_row = db.get_local_identity(account.id);
            if (identity_row == null) return;
            string? aik_ed_b64 = identity_row[db.account_identity.aik_pub_ed25519_base64];
            string? aik_ml_b64 = identity_row[db.account_identity.aik_pub_mldsa_base64];
            if (aik_ed_b64 == null || aik_ml_b64 == null) return;
            Bytes aik_ed = bytes_from_base64(aik_ed_b64);
            Bytes aik_ml = bytes_from_base64(aik_ml_b64);

            // Verify the whole chain on a FRESH chain with no observer connected, so
            // catching up doesn't replay a "device added" notification for every
            // historical entry. verify_and_apply advances state for each valid entry
            // BEFORE throwing on a bad one, so on failure we adopt whatever
            // genesis-rooted PREFIX did verify and ignore the stale/forked tail
            // (e.g. items left on the node signed by a pre-reset AIK). If not even
            // the genesis verifies, adopt nothing.
            var rebuilt = new Protocol.AccountAuditChain(db);
            try {
                rebuilt.verify_and_apply(account.id, aik_ed, aik_ml, fetched);
            } catch (Protocol.AccountAuditError e) {
                if (rebuilt.expected_next_seq() == 0) {
                    warning("fetch_audit_history: no valid genesis prefix (%s); ignoring node state", e.message);
                    return;
                }
                warning("fetch_audit_history: adopting valid %llu-entry prefix, ignoring stale tail: %s",
                    rebuilt.expected_next_seq(), e.message);
            }
            rebuilt.audit_entry_observed.connect((action, detail) => {
                account_audit_event(action, detail);
            });
            audit_chain = rebuilt;
            // Persist only the entries that actually verified into the adopted prefix
            // (seq 0 .. next_seq-1); a stale tail beyond it must not be stored.
            uint64 applied = rebuilt.expected_next_seq();
            foreach (Protocol.AuditEntry e in fetched) {
                if (e.seq < applied) {
                    db.store_account_audit_entry(account, e);
                }
            }
        } catch (Error e) {
            warning("fetch_audit_history: %s", e.message);
        } finally {
            audit_history_fetch_in_flight = false;
        }
    }

    private void handle_group_event(XmppStream stream, Jid room_jid, string? id, StanzaNode? item_node) {
        // X3DHPQ XEP §13.8. Per-room PEP membership journal hosted on the room
        // JID via standard XEP-0060. Correctness does NOT depend on any server
        // affiliation/size enforcement: clients verify each entry's hybrid
        // signature against the room owner's AIK (see Manager.on_membership_entry_received).
        string? payload = item_node != null ? item_node.get_string_content() : null;
        if (payload == null) {
            return;
        }
        membership_entry_received(room_jid, id, payload);
    }

    private void handle_pair_hello_event(XmppStream stream, Jid from, string? id, StanzaNode? item_node) {
        // XEP §10.1a method B: a device on THIS account published a <pair-hello>
        // rendezvous item to our own pair:0 PEP node, delivered here via self-PEP
        // +notify. Only self-PEP is meaningful; ignore anything else.
        if (item_node == null) {
            return;
        }
        // §11.8 queued enrollment request: same node, distinct persisted item id
        // ("enroll-request") and element name — dispatch on the element rather
        // than the pubsub item id so live delivery and the explicit
        // refresh_pair_hello fetch (which also iterates by element name) agree.
        if (item_node.name == "enroll-request") {
            handle_enroll_request_node(stream, from, item_node);
            return;
        }
        handle_pair_hello_node(stream, from, item_node);
    }

    // Shared parse+guard+emit logic for the <pair-hello> rendezvous element
    // (XEP §10.1a), used by both self-PEP delivery (method B, via
    // handle_pair_hello_event) and directed <message> delivery (method A, via
    // on_received_message) so a directed <pair-hello> produces byte-identical
    // downstream behavior to a self-PEP one.
    private void handle_pair_hello_node(XmppStream stream, Jid from, StanzaNode item_node) {
        if (!from.bare_jid.equals(account.bare_jid)) {
            return;
        }
        if (item_node.name != "pair-hello") {
            return;
        }
        string? full_jid_str  = item_node.get_attribute("full-jid");
        string? device_id_str = item_node.get_attribute("device-id");
        string? sid_b64url    = item_node.get_attribute("sid");
        if (full_jid_str == null || device_id_str == null || sid_b64url == null) {
            warning("handle_pair_hello_node: missing full-jid, device-id or sid attribute");
            return;
        }
        Jid new_full_jid;
        try {
            new_full_jid = new Jid(full_jid_str);
        } catch (InvalidJidError e) {
            warning("handle_pair_hello_node: invalid full-jid '%s': %s", full_jid_str, e.message);
            return;
        }
        // Ignore our own echo: the publishing (new) device also receives its own
        // PEP event; only a different resource should act as the existing device.
        Bind.Flag? bind_flag = stream.get_flag(Bind.Flag.IDENTITY);
        Jid? my_jid = bind_flag != null ? bind_flag.my_jid : null;
        if (my_jid != null && my_jid.equals(new_full_jid)) {
            return;
        }
        uint device_id = (uint) int64.parse(device_id_str);
        uint8[] sid = base64url_decode(sid_b64url);
        // Cache before firing so a dialog opened later (or a confirm-time replay)
        // can still reach this hello even if no dialog was listening just now.
        last_pair_hello_jid = new_full_jid;
        last_pair_hello_device_id = device_id;
        last_pair_hello_sid = sid;
        last_pair_hello_at = GLib.get_monotonic_time();
        pair_hello_received(new_full_jid, device_id, sid);
    }

    // Re-fire the most-recent cached <pair-hello> so a "Confirm a device" dialog
    // that has just had its code confirmed can act on a hello which arrived (via
    // +notify) before it was ready — without depending on a fresh network fetch
    // that may stall. Bounded to a short freshness window so we never resurrect a
    // hello from a dead resource of a previous attempt.
    public void replay_last_pair_hello() {
        if (last_pair_hello_jid == null || last_pair_hello_sid == null) {
            return;
        }
        int64 age_s = (GLib.get_monotonic_time() - last_pair_hello_at) / 1000000;
        if (age_s > 180) {
            return;
        }
        pair_hello_received((!) last_pair_hello_jid, last_pair_hello_device_id, (!) last_pair_hello_sid);
    }

    // §11.8 queued enrollment request: parse+verify+surface the persisted
    // <enroll-request> item (see publish_enrollment_request), dispatched from
    // handle_pair_hello_event (live +notify) and refresh_pair_hello (explicit
    // fetch) by element name, mirroring handle_pair_hello_node's structure.
    // Verifies the DIK hybrid signature (proof the publisher holds the DIK
    // priv it advertised — NOT account authority; the manual code/QR handshake
    // is still what authorizes) before caching it and surfacing it.
    private void handle_enroll_request_node(XmppStream stream, Jid from, StanzaNode item_node) {
        if (!from.bare_jid.equals(account.bare_jid)) {
            return;
        }
        if (item_node.name != "enroll-request") {
            return;
        }
        string? full_jid_str  = item_node.get_attribute("full-jid");
        string? device_id_str = item_node.get_attribute("device-id");
        string? sid_b64url    = item_node.get_attribute("sid");
        if (full_jid_str == null || device_id_str == null || sid_b64url == null) {
            warning("handle_enroll_request_node: missing full-jid, device-id or sid attribute");
            return;
        }
        Jid new_full_jid;
        try {
            new_full_jid = new Jid(full_jid_str);
        } catch (InvalidJidError e) {
            warning("handle_enroll_request_node: invalid full-jid '%s': %s", full_jid_str, e.message);
            return;
        }
        // Ignore our own echo, exactly like handle_pair_hello_node.
        Bind.Flag? bind_flag = stream.get_flag(Bind.Flag.IDENTITY);
        Jid? my_jid = bind_flag != null ? bind_flag.my_jid : null;
        if (my_jid != null && my_jid.equals(new_full_jid)) {
            return;
        }

        string? dik_ed_b64 = item_node.get_deep_string_content("dik-ed25519");
        string? dik_x_b64 = item_node.get_deep_string_content("dik-x25519");
        string? dik_ml_b64 = item_node.get_deep_string_content("dik-mldsa");
        string? sig_b64 = item_node.get_deep_string_content("sig");
        string? mldsa_sig_b64 = item_node.get_deep_string_content("mldsa-sig");
        if (dik_ed_b64 == null || dik_x_b64 == null || dik_ml_b64 == null || sig_b64 == null || mldsa_sig_b64 == null) {
            warning("handle_enroll_request_node: missing key/signature material");
            return;
        }

        uint device_id = (uint) int64.parse(device_id_str);
        uint8[] sid = base64url_decode(sid_b64url);
        uint8[] dik_ed;
        uint8[] dik_x;
        uint8[] dik_ml;
        uint8[] sig;
        uint8[] mldsa_sig;
        try {
            dik_ed = bytes_to_uint8_array(bytes_from_base64(dik_ed_b64));
            dik_x = bytes_to_uint8_array(bytes_from_base64(dik_x_b64));
            dik_ml = bytes_to_uint8_array(bytes_from_base64(dik_ml_b64));
            sig = bytes_to_uint8_array(bytes_from_base64(sig_b64));
            mldsa_sig = bytes_to_uint8_array(bytes_from_base64(mldsa_sig_b64));
        } catch (GLib.Error e) {
            warning("handle_enroll_request_node: decode error: %s", e.message);
            return;
        }

        try {
            uint8[] sp = Protocol.EnrollRequestSigned.signed_part(
                device_id, string_to_bytes(full_jid_str), sid, dik_ed, dik_x, dik_ml);
            bool ok = global::X3dhpq.Crypto.ed25519_verify(new Bytes(dik_ed), new Bytes(sp), new Bytes(sig))
                && global::X3dhpq.Crypto.mldsa65_verify(new Bytes(dik_ml), new Bytes(sp), new Bytes(mldsa_sig));
            if (!ok) {
                warning("handle_enroll_request_node: DIK signature verification failed from %s", full_jid_str);
                return;
            }
        } catch (GLib.Error e) {
            warning("handle_enroll_request_node: verify error: %s", e.message);
            return;
        }

        // Persist so the pairing UI can surface "device X wants to join" even
        // without a "Confirm a device" dialog already open at delivery time,
        // and reuse the SAME rendezvous signal the live pair-hello path fires
        // so an already-open PairNewDeviceDialog (confirm mode) reacts to a
        // queued request identically to a live one.
        db.store_pending_enrollment_request(account, device_id, full_jid_str, sid_b64url, dik_ed_b64, dik_x_b64, dik_ml_b64);
        enrollment_request_received(new_full_jid, device_id, sid, dik_ed, dik_x, dik_ml);
        pair_hello_received(new_full_jid, device_id, sid);
    }

    // Owner-side helper: sign and publish an AddMember or RemoveMember audit entry
    // to the room's group:0 PEP node. seq and prev_hash must be tracked by the caller.
    public async bool publish_audit_entry_for_action(
        XmppStream stream,
        Jid room_jid,
        Protocol.MemberAuditAction action,
        uint8[] aik_fp_raw_20,
        uint32 epoch_after,
        uint64 seq,
        uint8[] prev_hash_32,
        Bytes owner_aik_priv_ed,
        Bytes owner_aik_priv_mldsa
    ) {
        uint8[] payload = Protocol.MemberAuditEntry.build_member_payload(aik_fp_raw_20, epoch_after);
        Protocol.MemberAuditEntry entry = new Protocol.MemberAuditEntry();
        entry.seq = seq;
        entry.prev_hash = prev_hash_32;
        entry.action = (uint8) action;
        entry.payload = payload;
        entry.timestamp = new DateTime.now_utc().to_unix();
        try {
            uint8[] sp = entry.signed_part();
            entry.signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.ed25519_sign(owner_aik_priv_ed, new Bytes(sp)));
            entry.mldsa_signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.mldsa65_sign(owner_aik_priv_mldsa, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("publish_audit_entry_for_action: signing failed: %s", e.message);
            return false;
        }
        string b64 = Base64.encode(entry.marshal());
        return yield publish_membership_entry(stream, room_jid, seq.to_string(), b64);
    }

    // Subscribe to a MUC room's group:0 PEP node with a standard XEP-0060
    // <subscribe> IQ. We subscribe explicitly (rather than relying on Entity
    // Caps +notify) because a room-hosted pubsub node is not the account's own
    // PEP service, so caps-based auto-notification does not cover it; this is
    // standard XEP-0060 and works against stock Prosody/ejabberd.
    public async bool subscribe_to_group_node(XmppStream stream, Jid room_jid) {
        string subscriber = account.bare_jid.to_string();
        StanzaNode pubsub_node = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("subscribe", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_GROUP)
                .put_attribute("jid", subscriber));
        Iq.Stanza iq = new Iq.Stanza.set(pubsub_node) { to = room_jid };
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            return !result.is_error();
        } catch (Error e) {
            warning("subscribe to group:0 on %s failed: %s", room_jid.to_string(), e.message);
            return false;
        }
    }

    // Fetch all current items from the per-room group:0 PEP node and emit
    // membership_entry_received for each. XEP-0060 subscribers do not get an
    // automatic backfill of items published before subscription, so we have
    // to ask explicitly after MUC join — otherwise late joiners see an empty
    // journal and refuse to encrypt.
    public async void fetch_group_items(XmppStream stream, Jid room_jid) {
        StanzaNode pubsub_node = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_GROUP));
        Iq.Stanza iq = new Iq.Stanza.get(pubsub_node) { to = room_jid };
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            if (result.is_error()) {
                return;
            }
            StanzaNode? items_node = result.stanza.get_deep_subnode(
                Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items");
            if (items_node == null) {
                return;
            }
            foreach (StanzaNode item in items_node.get_subnodes("item", Pubsub.NS_URI)) {
                string? id = item.get_attribute("id");
                StanzaNode? entry = item.get_subnode("membership-entry", Protocol.NS_GROUP);
                if (entry == null) {
                    continue;
                }
                string? payload = entry.get_string_content();
                if (payload != null) {
                    membership_entry_received(room_jid, id, payload);
                }
            }
        } catch (Error e) {
            warning("fetch group:0 items on %s failed: %s", room_jid.to_string(), e.message);
        }
    }

    // §10.6.3: builds, persists and publishes a hybrid-signed AddDevice audit
    // entry (§11.4) for a device that was just confirmed via CPace pairing.
    // Called by the existing/primary side (encryption_preferences_entry.vala's
    // pairing_completed handler for PairNewDeviceDialog) right after issuing the
    // device its DC. This is what lets audit_chain_confirmed_device_ids (above)
    // trust the sibling on every device — including this one — that later
    // observes the account's own devicelist.
    public async bool publish_add_device_audit_entry(XmppStream stream, Protocol.DeviceCertificate issued_cert) {
        Row? identity = db.get_local_identity(account.id);
        if (identity == null) {
            warning("publish_add_device_audit_entry: no local AIK — cannot sign");
            return false;
        }
        string? aik_priv_ed_b64 = ((!) identity)[db.account_identity.aik_priv_ed25519_base64];
        string? aik_priv_ml_b64 = ((!) identity)[db.account_identity.aik_priv_mldsa_base64];
        if (aik_priv_ed_b64 == null || aik_priv_ed_b64 == "" || aik_priv_ml_b64 == null || aik_priv_ml_b64 == "") {
            warning("publish_add_device_audit_entry: no local AIK private key material — " +
                "cannot sign (this device is not primary/shared-primary)");
            return false;
        }

        var chain = db.list_account_audit_entries(account);
        uint64 seq = 0;
        uint8[] prev_hash = new uint8[32];
        if (chain.size > 0) {
            Protocol.AuditEntry last = chain[chain.size - 1];
            seq = last.seq + 1;
            prev_hash = last.compute_hash();
        }

        uint8[] cert_bytes = issued_cert.marshal();
        uint8[] payload = new uint8[4 + 4 + cert_bytes.length];
        uint32 device_id = issued_cert.device_id;
        payload[0] = (uint8)(device_id >> 24);
        payload[1] = (uint8)(device_id >> 16);
        payload[2] = (uint8)(device_id >> 8);
        payload[3] = (uint8) device_id;
        uint32 cert_len = (uint32) cert_bytes.length;
        payload[4] = (uint8)(cert_len >> 24);
        payload[5] = (uint8)(cert_len >> 16);
        payload[6] = (uint8)(cert_len >> 8);
        payload[7] = (uint8) cert_len;
        Memory.copy((uint8*) payload + 8, cert_bytes, cert_bytes.length);

        Protocol.AuditEntry entry = new Protocol.AuditEntry();
        entry.seq = seq;
        entry.prev_hash = prev_hash;
        entry.action = (uint8) Protocol.AccountAuditAction.ADD_DEVICE;
        entry.payload = payload;
        entry.timestamp = (int64) new DateTime.now_utc().to_unix();

        try {
            Bytes aik_priv_ed = bytes_from_base64((!) aik_priv_ed_b64);
            Bytes aik_priv_ml = bytes_from_base64((!) aik_priv_ml_b64);
            uint8[] sp = entry.signed_part();
            entry.signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(sp)));
            entry.mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(aik_priv_ml, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("publish_add_device_audit_entry: signing failed: %s", e.message);
            return false;
        }

        db.store_account_audit_entry(account, entry);
        bool ok = yield publish_audit_entry(stream, seq.to_string(), Base64.encode(entry.marshal()));
        if (!ok) {
            warning("publish_add_device_audit_entry: publish failed for device %u", device_id);
        }
        return ok;
    }

    // §12.1/§11.4 account reset: append + publish a RotateAIK audit entry
    // (action=3, payload = uint16(new_aik_len)|AccountIdentityPub.marshal() —
    // unchanged wire format, reusing Protocol.DeviceAuditEntryV2's §11.4 codec
    // verbatim) to the OLD account's audit:0 chain, signed by the OLD AIK.
    // Called by encryption_preferences_entry.vala's account-reset flow BEFORE
    // the new identity has published anything, so any peer still watching the
    // old chain can chain-detect the reconstruction (§12.3) — though this is
    // NOT sufficient evidence of authenticity on its own; the receiving peer
    // still MUST re-verify out-of-band (§12.3 RotationTrustStrict). Only ever
    // called when the OLD AIK_priv is still held locally; the caller skips
    // this entirely otherwise (§12: "where the old AIK_priv is still held").
    // Best-effort: a failure here is logged and returned, never thrown —
    // the caller must not let this block the reset itself.
    public async bool publish_rotate_aik_audit_entry(XmppStream stream, Bytes old_aik_priv_ed, Bytes old_aik_priv_mldsa, uint8[] new_aik_marshalled) {
        var entries = db.list_account_audit_entries(account);
        uint64 next_seq = 0;
        uint8[] prev_hash = new uint8[32];
        if (entries.size > 0) {
            Protocol.AuditEntry last = entries[entries.size - 1];
            next_seq = last.seq + 1;
            prev_hash = last.compute_hash();
        }

        Protocol.AuditEntry entry = new Protocol.AuditEntry();
        entry.seq = next_seq;
        entry.prev_hash = prev_hash;
        entry.action = (uint8) Protocol.AccountAuditAction.ROTATE_AIK;
        entry.payload = Protocol.DeviceAuditEntryV2.build_rotate_aik_payload(new_aik_marshalled);
        entry.timestamp = (int64) new DateTime.now_utc().to_unix();
        try {
            uint8[] sp = entry.signed_part();
            entry.signature = bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(old_aik_priv_ed, new Bytes(sp)));
            entry.mldsa_signature = bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(old_aik_priv_mldsa, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("publish_rotate_aik_audit_entry: signing failed: %s", e.message);
            return false;
        }

        db.store_account_audit_entry(account, entry);
        bool ok = yield publish_audit_entry(stream, next_seq.to_string(), Base64.encode(entry.marshal()));
        if (!ok) {
            warning("publish_rotate_aik_audit_entry: publish failed");
        }
        return ok;
    }

    // §11 self-genesis: the account's PRIMARY records ITSELF as ADD_DEVICE(self)@0.
    // Without this the primary/genesis device is never the subject of any AddDevice
    // entry (AddDevice is only ever published BY the primary FOR new devices), so a
    // newly-paired sibling never audit-trusts the primary as a co-account device →
    // omits it from the encrypt fan-out and clobbers it out of the republished
    // devicelist. Recording the primary in the chain makes every device trust it,
    // fixing multi-device sync symmetrically.
    public async void ensure_account_audit_genesis(XmppStream stream) {
        Row? identity = db.get_local_identity(account.id);
        if (identity == null) return;
        bool is_primary = ((!) identity)[db.account_identity.is_primary];
        string? aik_ed = ((!) identity)[db.account_identity.aik_priv_ed25519_base64];
        // Only a PRIMARY that actually holds AIK_priv can (and should) self-add.
        if (!is_primary || aik_ed == null || aik_ed == "") return;
        // Reflect the server's authoritative chain FIRST: a share_primary secondary
        // also carries is_primary, so we must not mistake an as-yet-unfetched empty
        // local chain for a genuine genesis and self-add a conflicting seq-0 entry.
        yield fetch_audit_history(stream);
        if (db.list_account_audit_entries(account).size > 0) {
            return;   // chain already established (our genesis, or devices added)
        }
        string dc_b64;
        try {
            dc_b64 = db.ensure_local_device_certificate(account);
        } catch (GLib.Error e) {
            warning("ensure_account_audit_genesis: cannot obtain own DC: %s", e.message);
            return;
        }
        Protocol.DeviceCertificate? own_dc = Protocol.DeviceCertificate.unmarshal(new Bytes(Base64.decode(dc_b64)));
        if (own_dc == null) return;
        yield publish_add_device_audit_entry(stream, own_dc);
    }

    // Purge ALL items from one of our OWN PEP nodes (pubsub#owner <purge>). Used by
    // account reset so stale items signed by the now-revoked AIK don't linger on the
    // server and fail verification under the new one (the earlier item-overwrite
    // approach could not clear items the fresh chain no longer re-publishes).
    public async void purge_own_node(XmppStream stream, string node) {
        StanzaNode pubsub = new StanzaNode.build("pubsub", "http://jabber.org/protocol/pubsub#owner").add_self_xmlns()
            .put_node(new StanzaNode.build("purge", "http://jabber.org/protocol/pubsub#owner")
                .put_attribute("node", node));
        Iq.Stanza iq = new Iq.Stanza.set(pubsub);
        iq.to = account.bare_jid;
        try {
            yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
        } catch (Error e) {
            warning("purge_own_node(%s): %s", node, e.message);
        }
    }

    // Publish an opaque, client-signed audit entry to the per-account audit:0
    // PEP node. The server stores and notifies subscribed contacts; verification
    // is the recipient's responsibility per X3DHPQ XEP §11.5.
    public async bool publish_audit_entry(XmppStream stream, string item_id, string base64_payload) {
        StanzaNode entry = new StanzaNode.build("audit-entry", Protocol.NS_AUDIT)
            .add_self_xmlns()
            .put_node(new StanzaNode.text(base64_payload));
        return yield stream.get_module(Pubsub.Module.IDENTITY).publish(
            stream, null, Protocol.NS_AUDIT, item_id, entry, PUBLISH_OPTIONS);
    }

    // Distribute an opaque, owner/admin-signed membership entry to a room by
    // sending it as a <journal-entry> element inside an ordinary type='groupchat'
    // <message> to the room JID. This replaces the previous room-JID XEP-0060
    // PubSub node, which stock MUC services (e.g. ejabberd mod_muc) do not serve
    // to members: a joined member could never subscribe/fetch it. The MUC channel
    // is a single shared, server-archived (MAM) log every member already reads;
    // late joiners catch up via MUC MAM (see Manager.trigger_group_mam_catchup).
    // Authenticity is enforced entirely client-side via the entry's hybrid AIK
    // signature; the server sees only an opaque base64 blob. item_id is retained
    // for API compatibility but is no longer a PubSub item id (dedup is by the
    // entry's own seq/hash inside the signed bytes). A groupchat message carries
    // no IQ result, so this returns true optimistically once queued.
    public async bool publish_membership_entry(XmppStream stream, Jid room_jid, string item_id, string base64_payload) {
        StanzaNode entry = new StanzaNode.build("journal-entry", Protocol.NS_ENVELOPE)
            .add_self_xmlns()
            .put_node(new StanzaNode.text(base64_payload));
        Xmpp.MessageStanza msg = new Xmpp.MessageStanza();
        msg.to = room_jid;
        msg.type_ = Xmpp.MessageStanza.TYPE_GROUPCHAT;
        // A <body> is required for stock MUC services to archive the message in
        // MAM (many only archive messages carrying a body); receivers suppress it.
        msg.body = "[x3dhpq group membership update]";
        msg.stanza.put_node(entry);
        stream.get_module(Xmpp.MessageModule.IDENTITY).send_message.begin(stream, msg);
        return true;
    }

    // Publish an owner-generated (or server-generated) membership audit entry
    // to a room's group:0 PEP node. This is a thin wire-publisher that mirrors
    // the same path used by publish_audit_entry_for_action except it accepts a
    // fully built MemberAuditEntry so callers can persist the same object locally.
    public async bool publish_membership_audit_entry(XmppStream stream, Jid room_jid, Protocol.MemberAuditEntry entry) {
        string b64 = Base64.encode(entry.marshal());
        return yield publish_membership_entry(stream, room_jid, entry.seq.to_string(), b64);
    }

    // ── New public API ─────────────────────────────────────────────────────────

    // Register an active pairing session so the inbound message handler can
    // route <pair> messages to the correct dialog. The actual FSM lives in the
    // dialog; this just stores the mapping.
    public void register_pair_session(uint8[] sid, Jid peer_bare, int role) {
        string key = Base64.encode(sid);
        pair_sessions[key] = new PairSessionRecord(peer_bare, role);
    }

    // Send a <pair> chat message to peer carrying the marshalled PairingMsg.
    // Uses the currently attached XmppStream. The step counter per sid is
    // incremented on each call. This method is non-async (fire-and-forget)
    // so the UI dialogs can call it without yield.
    public void send_pair_stanza(Jid peer, uint8[] sid, Protocol.PairingMsg msg) {
        XmppStream? stream = attached_stream;
        if (stream == null) {
            warning("send_pair_stanza: no attached stream");
            return;
        }
        string sid_b64 = Base64.encode(sid);
        uint step = pair_step_counters.has_key(sid_b64) ? pair_step_counters[sid_b64] : 0;
        pair_step_counters[sid_b64] = step + 1;

        StanzaNode pair_node = new StanzaNode.build("pair", Protocol.NS_PAIR)
            .add_self_xmlns()
            .put_attribute("sid", sid_b64)
            .put_attribute("step", step.to_string())
            .put_node(new StanzaNode.text(Base64.encode(msg.marshal())));

        Xmpp.MessageStanza stanza = new Xmpp.MessageStanza();
        stanza.to = peer;
        stanza.type_ = Xmpp.MessageStanza.TYPE_CHAT;
        stanza.stanza.put_node(pair_node);
        Bind.Flag? _bf = stream.get_flag(Bind.Flag.IDENTITY);
        // Pairing stanzas are strictly point-to-point between two devices. Tell
        // the server NOT to carbon-copy them to the account's other resources
        // (XEP-0280 <private/> + XEP-0334 <no-copy/>). Carbon copies are also
        // dropped defensively on the receive side (see on_received_message).
        stanza.stanza.put_node(new StanzaNode.build("private", "urn:xmpp:carbons:2").add_self_xmlns());
        stanza.stanza.put_node(new StanzaNode.build("no-copy", "urn:xmpp:hints").add_self_xmlns());
        stream.get_module(Xmpp.MessageModule.IDENTITY).send_message.begin(stream, stanza);
    }

    // Publish a self-addressed <pair-hello> rendezvous item to the account's OWN
    // pair:0 PEP node (XEP §10.1a method B). It carries addressing only —
    // device-id, full-jid, sid — and NO secret material (the pairing code stays
    // out-of-band). Published to item 'current' with whitelist (owner-only)
    // access so only the account's own resources receive it via +notify; an
    // existing device on this account then initiates the pairing FSM toward us.
    public async bool publish_pair_hello(XmppStream stream, uint32 device_id, string full_jid, uint8[] sid) {
        StanzaNode hello = new StanzaNode.build("pair-hello", Protocol.NS_PAIR)
            .add_self_xmlns()
            .put_attribute("device-id", device_id.to_string())
            .put_attribute("full-jid", full_jid)
            .put_attribute("sid", base64url_encode(sid));
        Pubsub.PublishOptions options = new Pubsub.PublishOptions()
            .set_persist_items(true)
            .set_access_model(Pubsub.ACCESS_MODEL_WHITELIST);
        return yield stream.get_module(Pubsub.Module.IDENTITY).publish(
            stream, null, Protocol.NS_PAIR, "current", hello, options);
    }

    // §11.8 "Queued enrollment request": called when a disabled/pending
    // device's user clicks Associate. Publishes a DIK-hybrid-signed enrollment
    // request (this device's DIK public keys + a fresh pairing nonce) to ITS
    // OWN pair-hello rendezvous node as a SEPARATE, PERSISTED item (id
    // "enroll-request", distinct from the live "current" pair-hello item so
    // the two never clobber each other), so it survives until an authorized
    // device is next online to see it — rather than only firing while a
    // listener happens to already be attached. Uses the SAME publish options
    // (persist + whitelist) as publish_pair_hello. The nonce IS the rendezvous
    // `sid` (reused verbatim so an authorized device that later confirms this
    // request drives the exact same §10.3 FSM/sid convention as a live hello).
    public async bool publish_enrollment_request(XmppStream stream) {
        int? device_id = db.get_local_device_id(account);
        if (device_id == null) {
            warning("publish_enrollment_request: no local device id yet");
            return false;
        }
        string full_jid = account.bare_jid.to_string();
        XmppStream? s = attached_stream;
        if (s != null) {
            Bind.Flag? bind_flag = s.get_flag(Bind.Flag.IDENTITY);
            if (bind_flag != null && bind_flag.my_jid != null) {
                full_jid = ((!) bind_flag.my_jid).to_string();
            }
        }
        Bytes sid;
        Bytes dik_ed;
        Bytes dik_x;
        Bytes dik_ml;
        try {
            sid = global::X3dhpq.Crypto.random_bytes(32);
            dik_ed = db.get_local_identity_bytes(account, db.account_identity.dik_pub_ed25519_base64);
            dik_x = db.get_local_identity_bytes(account, db.account_identity.dik_pub_x25519_base64);
            dik_ml = db.get_local_identity_bytes(account, db.account_identity.dik_pub_mldsa_base64);
        } catch (GLib.Error e) {
            warning("publish_enrollment_request: unable to read local DIK: %s", e.message);
            return false;
        }

        uint8[] dik_ed_bytes = bytes_to_uint8_array(dik_ed);
        uint8[] dik_x_bytes = bytes_to_uint8_array(dik_x);
        uint8[] dik_ml_bytes = bytes_to_uint8_array(dik_ml);
        uint8[] sid_bytes = bytes_to_uint8_array(sid);
        string sig_b64;
        string mldsa_sig_b64;
        try {
            // A disabled/pending device holds no AIK_priv yet — sign with its
            // own DIK instead (both Ed25519 and ML-DSA-65), which it always has
            // from ensure_local_identity(). See EnrollRequestSigned's doc: this
            // only proves possession of the advertised DIK, not account
            // authority — the manual code/QR handshake still grants that.
            Bytes dik_priv_ed = db.get_local_identity_bytes(account, db.account_identity.dik_priv_ed25519_base64);
            Bytes dik_priv_ml = db.get_local_identity_bytes(account, db.account_identity.dik_priv_mldsa_base64);
            uint8[] sp = Protocol.EnrollRequestSigned.signed_part(
                (uint32) (!) device_id, string_to_bytes(full_jid), sid_bytes, dik_ed_bytes, dik_x_bytes, dik_ml_bytes);
            sig_b64 = Base64.encode(bytes_to_uint8_array(global::X3dhpq.Crypto.ed25519_sign(dik_priv_ed, new Bytes(sp))));
            mldsa_sig_b64 = Base64.encode(bytes_to_uint8_array(global::X3dhpq.Crypto.mldsa65_sign(dik_priv_ml, new Bytes(sp))));
        } catch (GLib.Error e) {
            warning("publish_enrollment_request: signing failed: %s", e.message);
            return false;
        }

        StanzaNode request = new StanzaNode.build("enroll-request", Protocol.NS_PAIR)
            .add_self_xmlns()
            .put_attribute("device-id", ((!) device_id).to_string())
            .put_attribute("full-jid", full_jid)
            .put_attribute("sid", base64url_encode(sid_bytes))
            .put_node(new StanzaNode.build("dik-ed25519", Protocol.NS_PAIR).put_node(new StanzaNode.text(Base64.encode(dik_ed_bytes))))
            .put_node(new StanzaNode.build("dik-x25519", Protocol.NS_PAIR).put_node(new StanzaNode.text(Base64.encode(dik_x_bytes))))
            .put_node(new StanzaNode.build("dik-mldsa", Protocol.NS_PAIR).put_node(new StanzaNode.text(Base64.encode(dik_ml_bytes))))
            .put_node(new StanzaNode.build("sig", Protocol.NS_PAIR).put_node(new StanzaNode.text(sig_b64)))
            .put_node(new StanzaNode.build("mldsa-sig", Protocol.NS_PAIR).put_node(new StanzaNode.text(mldsa_sig_b64)));

        Pubsub.PublishOptions options = new Pubsub.PublishOptions()
            .set_persist_items(true)
            .set_access_model(Pubsub.ACCESS_MODEL_WHITELIST);
        return yield stream.get_module(Pubsub.Module.IDENTITY).publish(
            stream, null, Protocol.NS_PAIR, "enroll-request", request, options);
    }

    // §11.8: called by the authorizing device once it has completed the manual
    // code/QR handshake for a queued request, so the request does not linger
    // and get re-surfaced after it has already been fulfilled. Best-effort —
    // a retract failure just leaves a stale (harmless) item behind.
    public async void retract_enrollment_request(XmppStream stream) {
        try {
            yield stream.get_module(Pubsub.Module.IDENTITY).retract_item(stream, null, Protocol.NS_PAIR, "enroll-request");
        } catch (Error e) {
            warning("retract_enrollment_request: failed: %s", e.message);
        }
        db.clear_pending_enrollment_request(account);
    }

    // §10.6.2 "Confirm a device" entry point: the existing/primary device's
    // "confirm a waiting device" dialog is opened by the human AFTER (or
    // before) the pending device has already published its <pair-hello>. The
    // live +notify path (handle_pair_hello_event) only fires for a dialog that
    // was already listening at delivery time, so a hello published first would
    // otherwise be missed. This proactively fetches ALL current pair:0 items —
    // the same ones +notify would have delivered — and routes each through the
    // identical handle_pair_hello_node / handle_enroll_request_node path (by
    // element name) so the outcome, and the pair_hello_received /
    // enrollment_request_received signals a listening dialog reacts to, are
    // byte-identical regardless of ordering. This is also how a §11.8 queued
    // enrollment request (persisted, not just live) is discovered on next
    // connect — see publish_enrollment_request.
    public async void refresh_pair_hello(XmppStream stream) {
        StanzaNode pubsub_node = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_PAIR));
        Iq.Stanza iq = new Iq.Stanza.get(pubsub_node);
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            if (result.is_error()) return;
            StanzaNode? items_node = result.stanza.get_deep_subnode(
                Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items");
            if (items_node == null) {
                return;
            }
            var item_list = items_node.get_subnodes("item", Pubsub.NS_URI);
            foreach (StanzaNode item in item_list) {
                if (item.sub_nodes.size == 0) continue;
                StanzaNode child = item.sub_nodes[0];
                if (child.name == "enroll-request") {
                    handle_enroll_request_node(stream, account.bare_jid, child);
                } else {
                    handle_pair_hello_node(stream, account.bare_jid, child);
                }
            }
        } catch (Error e) {
            warning("refresh_pair_hello: request failed: %s", e.message);
        }
    }

    // ── Inbound message handler ────────────────────────────────────────────────

    private void on_received_message(XmppStream stream, Xmpp.MessageStanza message) {
        bool is_carbon = Xmpp.Xep.MessageCarbons.MessageFlag.get_flag(message) != null;
        bool has_pair = message.stanza.get_subnode("pair", Protocol.NS_PAIR) != null;
        bool has_hello = message.stanza.get_subnode("pair-hello", Protocol.NS_PAIR) != null;
        if (has_pair || has_hello) {
            Bind.Flag? bf = stream.get_flag(Bind.Flag.IDENTITY);
            string me = bf != null && bf.my_jid != null ? ((!) bf.my_jid).to_string() : "?";
        }
        // Pairing is strictly point-to-point between two devices; the genuine
        // handshake is delivered DIRECTLY to our full JID (never a carbon). A
        // carbon copy is a duplicate of traffic between two OTHER resources of
        // this account — the Carbons module rewrites message.stanza to the inner
        // forwarded copy, so without this guard a <pair>/<pair-hello> nested in a
        // carbon would drive our FSM with a foreign/duplicate stanza (or an
        // OMEMO-only resource's echoed envelope). Ignore carboned copies.
        if (is_carbon) {
            if (has_pair || has_hello) {
            }
            return;
        }
        // Handle inbound <pair xmlns='urn:xmppqr:x3dhpq:pair:0'> in chat messages.
        // Pairing rendezvous no longer depends on a server-pushed <verify-device>
        // headline: the existing device is triggered by a self-PEP <pair-hello>
        // (see handle_pair_hello_event / pair_hello_received, XEP §10.1a).
        StanzaNode? pair_node = message.stanza.get_subnode("pair", Protocol.NS_PAIR);
        if (pair_node != null && message.type_ == Xmpp.MessageStanza.TYPE_CHAT) {
            handle_pair_message(message.from, pair_node);
            return;
        }
        if (pair_node != null) {
        }
        // XEP §10.1a method A: <pair-hello> delivered as a directed message when
        // this device displayed the QR and a peer device scanned it, rather than
        // via self-PEP (method B). Shares handle_pair_hello_node so the outcome
        // is identical regardless of transport.
        StanzaNode? pair_hello_node = message.stanza.get_subnode("pair-hello", Protocol.NS_PAIR);
        if (pair_hello_node != null) {
            handle_pair_hello_node(stream, message.from, pair_hello_node);
            return;
        }
    }

    private void handle_pair_message(Jid from, StanzaNode pair_node) {
        string? sid_b64  = pair_node.get_attribute("sid");
        string? body_b64 = pair_node.get_string_content();
        if (sid_b64 == null || body_b64 == null) {
            warning("handle_pair_message: missing sid or body from %s", from.to_string());
            return;
        }

        uint8[] sid = Base64.decode(sid_b64);
        uint8[] raw = Base64.decode(body_b64);

        Protocol.PairingMsg msg;
        try {
            msg = Protocol.PairingMsg.unmarshal(raw);
        } catch (Protocol.PairingMsgError e) {
            warning("handle_pair_message: unmarshal failed from %s: %s", from.to_string(), e.message);
            return;
        }

        pair_message_received(sid, from, msg);
    }

    public override string get_ns() {
        return Protocol.NS_X3DHPQ;
    }

    public override string get_id() {
        return IDENTITY.id;
    }
}

}
