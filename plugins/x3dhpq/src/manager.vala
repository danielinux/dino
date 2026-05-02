using Dino.Entities;
using Gee;
using Qlite;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Plugins.X3dhpq {

public class Manager : Object {
    private Dino.Application app;
    private Database db;
    private HashMap<Entities.Message, Conversation> pending_messages = new HashMap<Entities.Message, Conversation>(Entities.Message.hash_func, Entities.Message.equals_func);

    public Manager(Dino.Application app, Database db) {
        this.app = app;
        this.db = db;

        app.stream_interactor.account_added.connect(on_account_added);
        app.stream_interactor.stream_negotiated.connect(on_stream_negotiated);
        app.stream_interactor.get_module(MessageProcessor.IDENTITY).pre_message_send.connect(on_pre_message_send);
        app.stream_interactor.get_module(MessageProcessor.IDENTITY).received_pipeline.connect(new DecryptMessageListener(this));
    }

    public async bool ensure_get_keys_for_jid(Account account, Jid jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        if (stream == null) {
            return false;
        }
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            return false;
        }

        ArrayList<int> devices = yield module.request_device_list((!) stream, jid);
        if (devices.size == 0) {
            return false;
        }
        foreach (int device_id in devices) {
            if (db.get_remote_bundle(account, jid.bare_jid.to_string(), device_id) == null) {
                StanzaNode? bundle = yield module.request_bundle((!) stream, jid, device_id);
                if (bundle == null) {
                    return false;
                }
            }
        }
        return true;
    }

    private void on_account_added(Account account) {
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            return;
        }
        module.device_list_loaded.connect((jid, devices) => {
            retry_pending(account);
        });
        module.bundle_fetched.connect((jid, device_id, bundle) => {
            retry_pending(account);
        });
    }

    private void on_stream_negotiated(Account account, XmppStream stream) {
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module != null) {
            module.request_device_list.begin(stream, account.bare_jid);
        }
    }

    private Gee.List<Jid> get_recipients(Conversation conversation, Xmpp.MessageStanza message_stanza) {
        ArrayList<Jid> recipients = new ArrayList<Jid>(Jid.equals_bare_func);
        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            Gee.List<Jid>? occupants = app.stream_interactor.get_module(MucManager.IDENTITY).get_offline_members(conversation.counterpart, conversation.account);
            if (occupants == null) {
                return recipients;
            }
            foreach (Jid occupant in occupants) {
                if (!occupant.equals(conversation.account.bare_jid)) {
                    recipients.add(occupant.bare_jid);
                }
            }
        } else {
            recipients.add(message_stanza.to.bare_jid);
        }
        // Include our own bare JID so sent carbons / archived copies contain a
        // decryptable key for this account's devices too.
        recipients.add(conversation.account.bare_jid);
        return recipients;
    }

    private void mark_pending(Entities.Message message, Conversation conversation) {
        pending_messages[message] = conversation;
        message.marked = Entities.Message.Marked.UNSENT;
    }

    private void retry_pending(Account account) {
        ArrayList<Entities.Message> retry_list = new ArrayList<Entities.Message>();
        foreach (Entities.Message message in pending_messages.keys) {
            if (message.account.equals(account) && message.marked == Entities.Message.Marked.UNSENT) {
                retry_list.add(message);
            }
        }
        foreach (Entities.Message message in retry_list) {
            Conversation? conversation = pending_messages[message];
            if (conversation == null) {
                pending_messages.unset(message);
                continue;
            }
            app.stream_interactor.get_module(MessageProcessor.IDENTITY).send_xmpp_message(message, conversation, true);
        }
    }

    private void on_pre_message_send(Entities.Message message, Xmpp.MessageStanza message_stanza, Conversation conversation) {
        if (message.encryption != Encryption.X3DHPQ) {
            return;
        }
        if (conversation.type_ == Conversation.Type.GROUPCHAT_PM) {
            message.marked = Message.Marked.WONTSEND;
            return;
        }

        XmppStream? stream = app.stream_interactor.get_stream(conversation.account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(conversation.account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            message.marked = Message.Marked.UNSENT;
            return;
        }

        Gee.List<Jid> recipients = get_recipients(conversation, message_stanza);
        if (recipients.size == 0) {
            message.marked = Message.Marked.WONTSEND;
            return;
        }

        bool waiting = false;
        foreach (Jid recipient in recipients) {
            string bare = recipient.bare_jid.to_string();
            if (!db.has_remote_device_list(conversation.account, bare)) {
                module.request_device_list.begin((!) stream, recipient);
                waiting = true;
                continue;
            }
            Gee.List<int> device_ids = db.get_remote_device_ids(conversation.account, bare);
            if (device_ids.size == 0) {
                module.request_device_list.begin((!) stream, recipient);
                waiting = true;
                continue;
            }
            foreach (int device_id in device_ids) {
                if (db.get_remote_bundle(conversation.account, bare, device_id) == null) {
                    module.request_bundle.begin((!) stream, recipient, device_id);
                    waiting = true;
                }
            }
        }
        if (waiting) {
            mark_pending(message, conversation);
            return;
        }

        try {
            build_encrypted_message(message, message_stanza, conversation, recipients);
            pending_messages.unset(message);
        } catch (Error e) {
            warning("Unable to encrypt x3dhpq message for %s: %s", conversation.counterpart.to_string(), e.message);
            mark_pending(message, conversation);
        }
    }

    private void build_encrypted_message(Entities.Message message, Xmpp.MessageStanza message_stanza, Conversation conversation, Gee.List<Jid> recipients) throws Error {
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null || message_stanza.body == null) {
            throw new IOError.FAILED("Missing local device or body");
        }

        Bytes payload_key = global::X3dhpq.Crypto.random_bytes(32);
        Bytes payload_nonce = global::X3dhpq.Crypto.random_bytes(12);
        Bytes payload_transport_key = bytes_from_uint8_array(concat_byte_arrays(bytes_to_uint8_array(payload_key), bytes_to_uint8_array(payload_nonce)));
        Bytes payload_ciphertext = global::X3dhpq.Crypto.aes256gcm_encrypt(payload_key, payload_nonce, new Bytes((uint8[]) message_stanza.body.data));
        StanzaNode envelope = new StanzaNode.build("x3dhpq", Protocol.NS_ENVELOPE)
            .add_self_xmlns()
            .put_attribute("sender-device", ((!) local_device_id).to_string())
            .put_attribute("sender-jid", conversation.account.bare_jid.to_string())
            .put_attribute("ts", new DateTime.now_utc().format_iso8601());

        foreach (Jid recipient in recipients) {
            foreach (int device_id in db.get_remote_device_ids(conversation.account, recipient.bare_jid.to_string())) {
                Protocol.PeerBundle? bundle = db.get_remote_bundle(conversation.account, recipient.bare_jid.to_string(), device_id);
                if (bundle == null || !bundle.verify()) {
                    continue;
                }

                Protocol.SessionState? state = db.get_session(conversation.account, recipient.bare_jid.to_string(), device_id);
                if (state != null && (state.chain_send_key == null || bytes_to_uint8_array((!) state.chain_send_key).length == 0)) {
                    warning("x3dhpq dropping corrupt local session for %s/%d: empty send chain key",
                        recipient.to_string(),
                        device_id);
                    db.delete_session(conversation.account, recipient.bare_jid.to_string(), device_id);
                    state = null;
                }
                Protocol.SessionBootstrap? bootstrap = null;
                if (state == null) {
                    bootstrap = Protocol.initiate_session(
                        db.get_local_identity_bytes(conversation.account, db.account_identity.dik_priv_x25519_base64),
                        db.get_local_identity_bytes(conversation.account, db.account_identity.dik_pub_x25519_base64),
                        bundle
                    );
                    state = bootstrap.state;
                }

                Protocol.MessageHeader header;
                Bytes encrypted_transport_key;
                Protocol.encrypt_transport_key((!) state, payload_transport_key, out header, out encrypted_transport_key);
                db.store_session(conversation.account, recipient.bare_jid.to_string(), device_id, (!) state);

                StanzaNode key_node = new StanzaNode.build("key", Protocol.NS_ENVELOPE)
                    .put_attribute("rid", device_id.to_string())
                    .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(header.marshal()))))
                    .put_node(new StanzaNode.build("emk", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(encrypted_transport_key))));

                if (bootstrap != null) {
                    StanzaNode prekey_node = new StanzaNode.build("prekey", Protocol.NS_ENVELOPE)
                        .put_attribute("ek", bytes_to_base64((!) bootstrap.prekey_ephemeral_pub))
                        .put_attribute("opk-id", bootstrap.opk_id.to_string())
                        .put_attribute("kemkey-id", bootstrap.kem_key_id.to_string())
                        .put_attribute("kem-ct", bytes_to_base64((!) bootstrap.kem_ciphertext))
                        .put_node(new StanzaNode.build("dc", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.ensure_local_device_certificate(conversation.account))))
                        .put_node(new StanzaNode.build("aik-ed25519", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(conversation.account, db.account_identity.aik_pub_ed25519_base64))))
                        .put_node(new StanzaNode.build("aik-mldsa", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(db.get_local_identity_string(conversation.account, db.account_identity.aik_pub_mldsa_base64))));
                    key_node.put_node(prekey_node);
                }
                envelope.put_node(key_node);
            }
        }

        envelope.put_node(new StanzaNode.build("payload", Protocol.NS_ENVELOPE).put_node(new StanzaNode.text(bytes_to_base64(payload_ciphertext))));
        message_stanza.stanza.put_node(envelope);
        ExplicitEncryption.add_encryption_tag_to_message(message_stanza, Protocol.NS_X3DHPQ, "x3dhpq");
        message_stanza.body = "[This message is x3dhpq encrypted]";
    }

    private class DecryptMessageListener : MessageListener {
        private Manager manager;
        public string[] after_actions_const = new string[]{ };
        public override string action_group { get { return "DECRYPT"; } }
        public override string[] after_actions { get { return after_actions_const; } }

        public DecryptMessageListener(Manager manager) {
            this.manager = manager;
        }

        public override async bool run(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation) {
            manager.decrypt_message(message, stanza, conversation);
            return false;
        }
    }

    private bool decrypt_message(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation) {
        StanzaNode? envelope = stanza.stanza.get_subnode("x3dhpq", Protocol.NS_ENVELOPE);
        if (envelope == null) {
            return false;
        }

        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null) {
            return false;
        }

        string? sender_jid_value = envelope.get_attribute("sender-jid", Protocol.NS_ENVELOPE) ?? envelope.get_attribute("sender-jid");
        if (sender_jid_value == null && stanza.from != null) {
            sender_jid_value = stanza.from.bare_jid.to_string();
        }
        if (sender_jid_value == null) {
            return false;
        }

        int sender_device_id = envelope.get_attribute_int("sender-device");
        StanzaNode? payload_node = envelope.get_subnode("payload", Protocol.NS_ENVELOPE);
        if (payload_node == null || payload_node.get_string_content() == null) {
            return false;
        }

        StanzaNode? key_node = null;
        foreach (StanzaNode node in envelope.get_subnodes("key", Protocol.NS_ENVELOPE)) {
            if (node.get_attribute_int("rid") == (!) local_device_id) {
                key_node = node;
                break;
            }
        }
        if (key_node == null) {
            return false;
        }

        Protocol.SessionState? state = db.get_session(conversation.account, sender_jid_value, sender_device_id);
        if (state == null) {
            StanzaNode? prekey_node = ((!) key_node).get_subnode("prekey", Protocol.NS_ENVELOPE);
            if (prekey_node == null) {
                return false;
            }

            Protocol.DeviceCertificate? peer_cert = Protocol.DeviceCertificate.unmarshal(bytes_from_base64(prekey_node.get_deep_string_content("dc")));
            if (peer_cert == null) {
                return false;
            }
            Row local_bundle = db.get_required_local_bundle(conversation.account);
            Row? local_spk = db.get_local_signed_pre_key(conversation.account, local_bundle[db.bundle.signed_pre_key_id]);
            Row? local_kem = db.get_local_kem_pre_key(conversation.account, prekey_node.get_attribute_int("kemkey-id"));
            if (local_spk == null || local_kem == null) {
                return false;
            }
            Row? local_opk = null;
            int opk_id = prekey_node.get_attribute_int("opk-id");
            if (opk_id > 0) {
                local_opk = db.get_local_one_time_pre_key(conversation.account, opk_id);
            }

            try {
                state = Protocol.respond_session(
                    db.get_local_identity_bytes(conversation.account, db.account_identity.dik_priv_x25519_base64),
                    db.get_local_identity_bytes(conversation.account, db.account_identity.dik_pub_x25519_base64),
                    bytes_from_base64(((!) local_spk)[db.signed_pre_key.private_base64]),
                    bytes_from_base64(((!) local_spk)[db.signed_pre_key.public_base64]),
                    local_opk != null ? bytes_from_base64(((!) local_opk)[db.one_time_pre_key.private_base64]) : null,
                    bytes_from_base64(((!) local_kem)[db.kem_pre_key.private_base64]),
                    peer_cert,
                    bytes_from_base64(prekey_node.get_deep_string_content("aik-ed25519")),
                    bytes_from_base64(prekey_node.get_deep_string_content("aik-mldsa")),
                    bytes_from_base64(prekey_node.get_attribute("ek")),
                    bytes_from_base64(prekey_node.get_attribute("kem-ct"))
                );
                db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state);
                if (local_opk != null) {
                    db.mark_local_one_time_pre_key_consumed(conversation.account, opk_id);
                }
            } catch (Error e) {
                warning("Unable to respond to x3dhpq prekey message from %s/%d: %s", sender_jid_value, sender_device_id, e.message);
                return false;
            }
        }

        try {
            StanzaNode? hdr_node = ((!) key_node).get_subnode("hdr", Protocol.NS_ENVELOPE);
            StanzaNode? emk_node = ((!) key_node).get_subnode("emk", Protocol.NS_ENVELOPE);
            if (hdr_node == null || emk_node == null || hdr_node.get_string_content() == null || emk_node.get_string_content() == null) {
                return false;
            }
            Protocol.MessageHeader? header = Protocol.MessageHeader.unmarshal(bytes_from_base64(hdr_node.get_string_content()));
            if (header == null) {
                return false;
            }
            Bytes transport_key = Protocol.decrypt_transport_key((!) state, header, bytes_from_base64(emk_node.get_string_content()));
            db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state);

            string plaintext;
            Protocol.decrypt_payload(transport_key, bytes_from_base64((!) payload_node.get_string_content()), out plaintext);
            message.body = plaintext;
            message.encryption = Encryption.X3DHPQ;
            if (conversation.type_ == Conversation.Type.GROUPCHAT) {
                try {
                    message.real_jid = new Jid(sender_jid_value);
                } catch (InvalidJidError e) {
                    warning("Invalid x3dhpq sender jid in group message: %s", e.message);
                }
            }
            return true;
        } catch (Error e) {
            warning("Unable to decrypt x3dhpq message from %s/%d: %s", sender_jid_value, sender_device_id, e.message);
            return false;
        }
    }
}

}
