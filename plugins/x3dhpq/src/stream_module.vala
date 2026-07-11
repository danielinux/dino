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

        stream.get_module(Xmpp.MessageModule.IDENTITY).received_message.disconnect(on_received_message);
        attached_stream = null;
    }

    public async void publish_current_state(XmppStream stream) {
        db.ensure_local_identity(account);
        db.ensure_local_prekeys(account);
        // §10.6.1 fresh-device gating: a device that is not yet confirmed primary
        // (is_primary=false — either still-pending, §10.6.1, or a legitimately
        // confirmed non-primary/non-shared secondary from pairing) MUST NOT
        // publish an authoritative devicelist. Resolve pending state first; a
        // confirmed non-primary secondary's resolve is a no-op (already resolved
        // via apply_paired_identity) and simply stays unpublished here, same as
        // today's (correct) behavior for that case.
        if (!db.is_local_primary(account)) {
            yield resolve_pending_primary(stream);
        }
        if (db.is_local_primary(account)) {
            yield publish_device_list(stream);
        }
        // publish_bundle is NOT gated: a confirmed non-primary device still needs
        // its own bundle published so peers can PQXDH directly to it. A still-
        // pending device's bundle is harmless-but-orphaned (nobody has a reason to
        // fetch a device_id no devicelist has ever announced).
        yield publish_bundle(stream);
    }

    // §10.6.1: resolves a not-yet-primary local identity by fetching the
    // account's own devicelist from the server. An EMPTY (or errored) response
    // means no AIK has ever been published for this account anywhere — genuinely
    // the first device — so it is promoted to primary. A NON-empty response means
    // an existing primary already owns this account's AIK; this device remains
    // pending (is_primary stays false) and waits to be confirmed via CPace
    // pairing (§10.6.2), which calls apply_paired_identity and sets is_primary
    // explicitly (true if share_primary, false otherwise — either way "resolved").
    private async void resolve_pending_primary(XmppStream stream) {
        Jid own_bare = account.bare_jid;
        ArrayList<int> own_devices = yield request_device_list(stream, own_bare);
        // Re-check: a concurrent pairing confirmation may have completed while
        // the fetch was in flight.
        if (db.is_local_primary(account)) {
            return;
        }
        if (own_devices.size == 0) {
            db.promote_to_primary(account);
        }
        // else: stays pending — no publish, no state change.
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
        }
        // The primary already persists a newly-enrolled device's DC under our own
        // bare JID at pairing completion (encryption_preferences_entry.vala's
        // pairing_completed handler calls db.store_remote_device); other devices
        // pick up co-account siblings from the account's own inbound signed
        // devicelist via parse_device_list's is_self branch.
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
        Gee.Set<int> chain_confirmed = audit_chain_confirmed_device_ids();
        var trusted_devices = new ArrayList<int>();
        foreach (Protocol.DeviceListDevice e in entries) {
            int did = (int) e.device_id;
            devices.add(did);
            bool is_own_local = local_device_id != null && did == (!) local_device_id;
            if (is_own_local || chain_confirmed.contains(did)) {
                trusted_devices.add(did);
                db.store_remote_device(account, bare, did, cert_by_id[did], added_by_id[did] ?? 0, e.flags, true);
            } else {
                // §10.6.3: persist the row anyway, but INACTIVE — this keeps it
                // out of get_remote_device_ids / get_device_list_devices (both
                // filter active=true, so nothing here changes trust or what we
                // republish), while making it queryable via
                // db.get_pending_own_device_ids so the devices-list UI can
                // surface it as a pending/unconfirmed security event instead of
                // silently dropping it.
                warning("x3dhpq: sibling device %d appears in own devicelist but has NO " +
                    "valid AddDevice audit entry — NOT auto-trusting (§10.6.3)", did);
                db.store_remote_device(account, bare, did, cert_by_id[did], added_by_id[did] ?? 0, e.flags, false);
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

    // §10.6.2 "Confirm a device" entry point: the existing/primary device's
    // "confirm a waiting device" dialog is opened by the human AFTER (or
    // before) the pending device has already published its <pair-hello>. The
    // live +notify path (handle_pair_hello_event) only fires for a dialog that
    // was already listening at delivery time, so a hello published first would
    // otherwise be missed. This proactively fetches the current pair:0 item —
    // the same one +notify would have delivered — and, if present, routes it
    // through the identical handle_pair_hello_node path (so the outcome, and
    // the pair_hello_received signal any listening dialog reacts to, is
    // byte-identical regardless of ordering).
    public async void refresh_pair_hello(XmppStream stream) {
        StanzaNode pubsub_node = new StanzaNode.build("pubsub", Pubsub.NS_URI).add_self_xmlns()
            .put_node(new StanzaNode.build("items", Pubsub.NS_URI)
                .put_attribute("node", Protocol.NS_PAIR));
        Iq.Stanza iq = new Iq.Stanza.get(pubsub_node);
        try {
            Iq.Stanza result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
            if (result.is_error()) return;
            StanzaNode? item = result.stanza.get_deep_subnode(
                Pubsub.NS_URI + ":pubsub", Pubsub.NS_URI + ":items", Pubsub.NS_URI + ":item");
            if (item != null && item.sub_nodes.size > 0) {
                handle_pair_hello_node(stream, account.bare_jid, item.sub_nodes[0]);
            }
        } catch (Error e) {
            warning("refresh_pair_hello: request failed: %s", e.message);
        }
    }

    // ── Inbound message handler ────────────────────────────────────────────────

    private void on_received_message(XmppStream stream, Xmpp.MessageStanza message) {
        // Handle inbound <pair xmlns='urn:xmppqr:x3dhpq:pair:0'> in chat messages.
        // Pairing rendezvous no longer depends on a server-pushed <verify-device>
        // headline: the existing device is triggered by a self-PEP <pair-hello>
        // (see handle_pair_hello_event / pair_hello_received, XEP §10.1a).
        StanzaNode? pair_node = message.stanza.get_subnode("pair", Protocol.NS_PAIR);
        if (pair_node != null && message.type_ == Xmpp.MessageStanza.TYPE_CHAT) {
            handle_pair_message(message.from, pair_node);
            return;
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
