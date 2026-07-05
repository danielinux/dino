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
    // Emitted when a headline <verify-device> push arrives from the server.
    public signal void verify_device_received(Jid new_resource, uint device_id);
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

        stream.get_module(Xmpp.MessageModule.IDENTITY).received_message.disconnect(on_received_message);
        attached_stream = null;
    }

    public async void publish_current_state(XmppStream stream) {
        db.ensure_local_identity(account);
        db.ensure_local_prekeys(account);
        yield publish_device_list(stream);
        yield publish_bundle(stream);
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

    private async void publish_device_list(XmppStream stream) {
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
        uint8 flags = 1;
        string own_jid = account.bare_jid.to_string();

        // Version rule (§8.2): the version is a persisted, monotonic per-account
        // counter incremented ONLY when the list *content* changes. A routine
        // self-republish (same devices) MUST reuse the current version.
        string content_key = build_device_content_key_single((uint32)(!) device_id, (int64) added_at, flags, cert);
        long prev_version = db.get_device_list_version(account, own_jid);
        string? prev_content_key = db.get_device_list_content_key(account, own_jid);
        long version;
        if (prev_content_key != null && prev_content_key == content_key) {
            version = prev_version > 0 ? prev_version : 1;
        } else {
            version = prev_version + 1;   // first publish: 0 + 1 = 1
        }
        long issued_at = (long) new DateTime.now_utc().to_unix();

        // Compute the SignedPart (layout A) and hybrid-sign it with the AIK.
        var devices = new Gee.ArrayList<Protocol.DeviceListDevice>();
        var dld = new Protocol.DeviceListDevice();
        dld.device_id = (uint32)(!) device_id;
        dld.added_at = added_at;
        dld.flags = flags;
        try {
            dld.cert_bytes = bytes_to_uint8_array(bytes_from_base64(cert));
        } catch (GLib.Error e) {
            warning("publish_device_list: cert base64 decode failed: %s", e.message);
            return;
        }
        devices.add(dld);
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
        // item child (the <devicelist> element).
        StanzaNode node = new StanzaNode.build("devicelist", Protocol.NS_DEVICELIST)
            .add_self_xmlns()
            .put_attribute("version", version.to_string())
            .put_attribute("issued-at", issued_at.to_string())
            .put_node(new StanzaNode.build("device", Protocol.NS_DEVICELIST)
                .put_attribute("id", ((!) device_id).to_string())
                .put_attribute("added-at", added_at.to_string())
                .put_attribute("flags", flags.to_string())
                .put_node(new StanzaNode.build("cert", Protocol.NS_DEVICELIST)
                    .put_node(new StanzaNode.text(cert))))
            .put_node(new StanzaNode.build("sig", Protocol.NS_DEVICELIST)
                .put_node(new StanzaNode.text(sig_b64)))
            .put_node(new StanzaNode.build("mldsa-sig", Protocol.NS_DEVICELIST)
                .put_node(new StanzaNode.text(mldsa_sig_b64)));

        if (yield stream.get_module(Pubsub.Module.IDENTITY).publish(stream, null, Protocol.NS_DEVICELIST, "current", node, PUBLISH_OPTIONS)) {
            yield try_make_node_public(stream, Protocol.NS_DEVICELIST);
            db.store_device_list_payload(account, own_jid, "current", node.to_string(), version, true, content_key);
        }
    }

    // Canonical device-set key for one device: "id|added_at|flags|cert". For a
    // multi-device list the caller joins the per-device keys sorted by id with
    // ';'. Used to decide own-version bumps (§8.2) and detect same-version forks
    // (§8.5); deliberately excludes version/issued_at.
    private static string build_device_content_key_single(uint32 device_id, int64 added_at, uint8 flags, string cert_b64) {
        return @"$device_id|$added_at|$flags|$cert_b64";
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
        entries.sort((a, b) => (a.device_id < b.device_id) ? -1 : (a.device_id > b.device_id ? 1 : 0));
        StringBuilder ck = new StringBuilder();
        foreach (Protocol.DeviceListDevice e in entries) {
            if (ck.len > 0) ck.append(";");
            ck.append(build_device_content_key_single(e.device_id, e.added_at, e.flags, Base64.encode(e.cert_bytes)));
        }
        string content_key = ck.str;

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
                db.store_remote_device(account, bare, did, cert_by_id[did], added_by_id[did] ?? 0);
            }
            db.store_device_list_payload(account, bare, id, node.to_string(),
                accepted_version, accepted_signed, content_key);
            // The published devicelist is authoritative — drop cached peer_device
            // / bundle / pairwise_session rows for ids no longer present (§8.6).
            db.prune_remote_devices_not_in(account, bare, devices);
            device_list_loaded(jid, devices);
            return devices;
        }

        foreach (Protocol.DeviceListDevice e in entries) {
            int did = (int) e.device_id;
            devices.add(did);
            db.store_remote_device(account, bare, did, cert_by_id[did], added_by_id[did] ?? 0);
        }
        db.store_device_list_payload(account, bare, id, node.to_string());
        device_list_loaded(jid, devices);
        return devices;
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

    // Publish an opaque, owner-signed membership entry to a room's group:0 PEP
    // node using standard XEP-0060 publish. Authenticity is enforced entirely
    // client-side via the entry's hybrid AIK signature; we do not rely on the
    // server restricting who may publish or on any item-size cap.
    public async bool publish_membership_entry(XmppStream stream, Jid room_jid, string item_id, string base64_payload) {
        StanzaNode entry = new StanzaNode.build("membership-entry", Protocol.NS_GROUP)
            .add_self_xmlns()
            .put_node(new StanzaNode.text(base64_payload));
        return yield stream.get_module(Pubsub.Module.IDENTITY).publish(
            stream, room_jid, Protocol.NS_GROUP, item_id, entry, PUBLISH_OPTIONS);
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

    // Send a verify-device IQ-set to the server using the currently attached stream.
    // Returns the peers count from <peers count='N'/> in the result,
    // or -1 on <not-acceptable/> or other errors.
    public async int send_verify_device_iq(uint device_id) {
        XmppStream? stream = attached_stream;
        if (stream == null) {
            warning("send_verify_device_iq: no attached stream");
            return -1;
        }

        StanzaNode verify_node = new StanzaNode.build("verify-device", Protocol.NS_PAIR)
            .add_self_xmlns()
            .put_attribute("device-id", device_id.to_string())
            .put_attribute("transport", "message");

        Iq.Stanza iq = new Iq.Stanza.set(verify_node);
        // No `to` set — server fills in (own account).

        Iq.Stanza result;
        try {
            result = yield stream.get_module(Iq.Module.IDENTITY).send_iq_async(stream, iq);
        } catch (Error e) {
            warning("send_verify_device_iq: IQ send failed: %s", e.message);
            return -1;
        }

        if (result.is_error()) {
            ErrorStanza? err = result.get_error();
            if (err != null && err.condition == ErrorStanza.CONDITION_NOT_ACCEPTABLE) {
                return -1;
            }
            warning("send_verify_device_iq: unexpected IQ error: %s",
                err != null ? err.condition : "unknown");
            return -1;
        }

        StanzaNode? peers_node = result.stanza.get_subnode("peers", Protocol.NS_PAIR);
        if (peers_node == null) {
            warning("send_verify_device_iq: result has no <peers/> child");
            return -1;
        }
        return int.parse(peers_node.get_attribute("count") ?? "-1");
    }

    // ── Inbound message handler ────────────────────────────────────────────────

    private void on_received_message(XmppStream stream, Xmpp.MessageStanza message) {
        // Handle inbound <pair xmlns='urn:xmppqr:x3dhpq:pair:0'> in chat messages.
        StanzaNode? pair_node = message.stanza.get_subnode("pair", Protocol.NS_PAIR);
        if (pair_node != null && message.type_ == Xmpp.MessageStanza.TYPE_CHAT) {
            handle_pair_message(message.from, pair_node);
            return;
        }

        // Handle inbound <verify-device/> in headline messages.
        if (message.type_ == Xmpp.MessageStanza.TYPE_HEADLINE) {
            StanzaNode? vd_node = message.stanza.get_subnode("verify-device", Protocol.NS_PAIR);
            if (vd_node != null) {
                handle_verify_device_headline(vd_node);
                return;
            }
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

    private void handle_verify_device_headline(StanzaNode vd_node) {
        string? new_resource_str = vd_node.get_attribute("new-resource");
        string? device_id_str   = vd_node.get_attribute("device-id");
        if (new_resource_str == null || device_id_str == null) {
            warning("handle_verify_device_headline: missing new-resource or device-id attribute");
            return;
        }
        Jid? new_resource = null;
        try {
            new_resource = new Jid(new_resource_str);
        } catch (InvalidJidError e) {
            warning("handle_verify_device_headline: invalid JID '%s': %s", new_resource_str, e.message);
            return;
        }
        uint device_id = (uint) int.parse(device_id_str);
        verify_device_received((!) new_resource, device_id);
    }

    public override string get_ns() {
        return Protocol.NS_X3DHPQ;
    }

    public override string get_id() {
        return IDENTITY.id;
    }
}

}
