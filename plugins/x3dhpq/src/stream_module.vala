using Dino.Entities;
using Gee;
using Qlite;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Plugins.X3dhpq {

public class StreamModule : XmppStreamModule {
    public static Xmpp.ModuleIdentity<StreamModule> IDENTITY = new Xmpp.ModuleIdentity<StreamModule>(Protocol.NS_X3DHPQ, "x3dhpq_stream_module");
    private static Pubsub.PublishOptions PUBLISH_OPTIONS = new Pubsub.PublishOptions()
        .set_persist_items(true)
        .set_access_model(Pubsub.ACCESS_MODEL_OPEN);
    private HashMap<Jid, Future<ArrayList<int>>> active_devicelist_requests = new HashMap<Jid, Future<ArrayList<int>>>(Jid.hash_func, Jid.equals_func);

    private Account account;
    private Database db;

    public signal void device_list_loaded(Jid jid, ArrayList<int> devices);
    public signal void bundle_fetched(Jid jid, int device_id, StanzaNode bundle);
    public signal void audit_entry_received(Jid from, string? id, string b64_payload);
    public signal void membership_entry_received(Jid room_jid, string? id, string b64_payload);

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
        // The cert string MUST be added as a text sub-node, not via the `val`
        // initialiser. For an element StanzaNode (built via .build()), `val`
        // is ignored during serialization — only sub_nodes are rendered, so
        // `{ val = cert }` produces `<cert/>` empty on the wire. publish_bundle
        // below already does the right thing for <dc>; we mirror that pattern.
        StanzaNode node = new StanzaNode.build("devicelist", Protocol.NS_DEVICELIST)
            .add_self_xmlns()
            .put_attribute("version", "1")
            .put_attribute("issued-at", ((long) new DateTime.now_utc().to_unix()).to_string())
            .put_node(new StanzaNode.build("device", Protocol.NS_DEVICELIST)
                .put_attribute("id", ((!) device_id).to_string())
                .put_attribute("flags", "1")
                .put_node(new StanzaNode.build("cert", Protocol.NS_DEVICELIST)
                    .put_node(new StanzaNode.text(cert))));

        if (yield stream.get_module(Pubsub.Module.IDENTITY).publish(stream, null, Protocol.NS_DEVICELIST, "current", node, PUBLISH_OPTIONS)) {
            yield try_make_node_public(stream, Protocol.NS_DEVICELIST);
            db.store_device_list_payload(account, account.bare_jid.to_string(), "current", node.to_string());
        }
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
        foreach (StanzaNode device_node in node.get_subnodes("device", Protocol.NS_DEVICELIST)) {
            int device_id = device_node.get_attribute_int("id");
            devices.add(device_id);
            StanzaNode? cert_node = device_node.get_subnode("cert", Protocol.NS_DEVICELIST);
            db.store_remote_device(account, jid.bare_jid.to_string(), device_id, cert_node != null ? cert_node.get_string_content() : null);
        }
        db.store_device_list_payload(account, jid.bare_jid.to_string(), id, node.to_string());
        device_list_loaded(jid, devices);
        return devices;
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
        // Until full audit-chain verification lands, surface the opaque payload
        // so higher layers (manager / UI) can store and inspect it.
        string? payload = item_node != null ? item_node.get_string_content() : null;
        if (payload == null) {
            return;
        }
        audit_entry_received(from, id, payload);
    }

    private void handle_group_event(XmppStream stream, Jid room_jid, string? id, StanzaNode? item_node) {
        // X3DHPQ XEP §13.8. Per-room PEP membership journal hosted on the room JID.
        // Server enforces 16 KiB / 200-item caps and owner-only publish; clients
        // verify the entry's signature against the room owner's AIK.
        string? payload = item_node != null ? item_node.get_string_content() : null;
        if (payload == null) {
            return;
        }
        membership_entry_received(room_jid, id, payload);
    }

    // Subscribe to a MUC room's group:0 PEP node. Per Wave 5a of the server,
    // per-room pubsub hosts track explicit subscriptions in pep_subscriptions
    // rather than relying on caps +notify filtering, so an explicit subscribe
    // IQ is required after MUC join.
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
    // node. The server enforces affiliation >= owner; admins/members get
    // <forbidden/>. Items > 16 KiB are rejected with <not-acceptable/>.
    public async bool publish_membership_entry(XmppStream stream, Jid room_jid, string item_id, string base64_payload) {
        StanzaNode entry = new StanzaNode.build("membership-entry", Protocol.NS_GROUP)
            .add_self_xmlns()
            .put_node(new StanzaNode.text(base64_payload));
        return yield stream.get_module(Pubsub.Module.IDENTITY).publish(
            stream, room_jid, Protocol.NS_GROUP, item_id, entry, PUBLISH_OPTIONS);
    }

    public override string get_ns() {
        return Protocol.NS_X3DHPQ;
    }

    public override string get_id() {
        return IDENTITY.id;
    }
}

}
