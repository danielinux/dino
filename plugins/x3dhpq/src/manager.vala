using Dino.Entities;
using Gee;
using Qlite;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Plugins.X3dhpq {

public class Manager : Object, global::Dino.Plugins.X3dhpqGroupManager {
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
        app.stream_interactor.get_module(MucManager.IDENTITY).room_info_updated.connect(on_room_info_updated);
    }

    // Subscribe to the room's X3DHPQ membership-journal PEP node when MUC info
    // is settled. Per Wave 5a server policy, per-room pubsub hosts require an
    // explicit subscribe IQ; caps-based +notify filtering does not apply.
    private void on_room_info_updated(Account account, Jid muc_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return;
        }
        // Subscribe first, then explicitly catch up on already-published
        // items. XEP-0060 subscribers do NOT get a backfill of items
        // published before they subscribed, so without the second step a
        // late joiner sees an empty journal even if the owner published
        // hours earlier.
        module.subscribe_to_group_node.begin((!) stream, muc_jid, (obj, res) => {
            module.subscribe_to_group_node.end(res);
            module.fetch_group_items.begin((!) stream, muc_jid);
        });
    }

    private void wipe_sessions_once(Account account) {
        try {
            string flag_dir = GLib.Path.build_filename(
                GLib.Environment.get_user_cache_dir(), "dino", "x3dhpq");
            DirUtils.create_with_parents(flag_dir, 0700);
            string flag_path = GLib.Path.build_filename(
                flag_dir, "session_wipe_v1_%d.flag".printf(account.id));
            if (FileUtils.test(flag_path, FileTest.EXISTS)) {
                return;
            }
            db.wipe_all_sessions(account);
            FileUtils.set_contents(flag_path, "done\n");
        } catch (Error e) {
            warning("x3dhpq session wipe-v1 failed: %s", e.message);
        }
    }

    // Replay every persisted journal entry into the supplied GroupSession's
    // members map without rotating the epoch. Without this, the in-memory
    // session has zero members, so accept_sender_chain rejects every
    // incoming announcement with ANNOUNCEMENT_UNKNOWN_SENDER and decrypts
    // surface as "no recv chain".
    private void rebuild_group_session_from_journal(Account account, string room_jid_str,
            Protocol.GroupSession gs) {
        var entries = db.list_membership_journal_entries(account, room_jid_str);
        int added = 0;
        int skipped_not_found = 0;
        foreach (Protocol.MemberAuditEntry e in entries) {
            uint8[] aik_fp_raw;
            uint32 epoch_after;
            if (!Protocol.MemberAuditEntry.parse_member_payload(e.payload, out aik_fp_raw, out epoch_after)) {
                continue;
            }
            uint8[] aik_ed;
            uint8[] aik_mldsa;
            if (!db.find_peer_account_identity_by_aik_fp(account, aik_fp_raw, out aik_ed, out aik_mldsa)) {
                // Could be ourselves (we are the owner). Build canonical AIK
                // from the local account identity if the fp matches.
                uint8[] my_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
                uint8[] my_ml = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
                int total = 3 + my_ed.length + my_ml.length;
                uint8[] enc = new uint8[total];
                enc[0] = 0; enc[1] = 1; enc[2] = 1;
                Memory.copy((uint8*) enc + 3, my_ed, my_ed.length);
                Memory.copy((uint8*) enc + 3 + my_ed.length, my_ml, my_ml.length);
                bool is_self = false;
                try {
                    Bytes my_fp = global::X3dhpq.Crypto.blake2b160(new Bytes(enc));
                    unowned uint8[] my_fp_bytes = my_fp.get_data();
                    is_self = true;
                    for (int i = 0; i < 20; i++) {
                        if (my_fp_bytes[i] != aik_fp_raw[i]) { is_self = false; break; }
                    }
                } catch (Error err) {
                    continue;
                }
                if (!is_self) {
                    // Last resort: scan the bundle table — when dino fetched
                    // the peer's bundle (e.g., for 1:1 chat or to broadcast
                    // a sender chain), the AIK halves were stored on the
                    // bundle row. The peer_account_identity index can lag
                    // briefly when the bundle landed before the bundle
                    // handler updated peer_account_identity. Falling
                    // through here means rebuild silently drops the entry
                    // and gs ends up with zero members, which makes
                    // accept_sender_chain reject every announcement.
                    if (!find_peer_aik_in_bundles(account, aik_fp_raw, out aik_ed, out aik_mldsa)) {
                        skipped_not_found++;
                        continue;
                    }
                } else {
                    aik_ed = my_ed;
                    aik_mldsa = my_ml;
                }
            }
            // Rebuild canonical AIK pub bytes for the GroupMember.
            int total = 3 + aik_ed.length + aik_mldsa.length;
            uint8[] aik_canonical = new uint8[total];
            aik_canonical[0] = 0; aik_canonical[1] = 1; aik_canonical[2] = 1;
            Memory.copy((uint8*) aik_canonical + 3, aik_ed, aik_ed.length);
            Memory.copy((uint8*) aik_canonical + 3 + aik_ed.length, aik_mldsa, aik_mldsa.length);
            try {
                if (e.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                    Protocol.GroupMember m = new Protocol.GroupMember();
                    m.aik_pub_bytes = aik_canonical;
                    gs.add_initial_member(m);
                    added++;
                } else if (e.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                    string fp_hex = "";
                    StringBuilder sb = new StringBuilder();
                    foreach (uint8 b in aik_fp_raw) {
                        sb.append_printf("%02X", b);
                    }
                    fp_hex = sb.str.substring(0, 30);
                    fp_hex = @"$(fp_hex.substring(0, 5)) $(fp_hex.substring(5, 5)) $(fp_hex.substring(10, 5)) $(fp_hex.substring(15, 5)) $(fp_hex.substring(20, 5)) $(fp_hex.substring(25, 5))";
                    gs.remove_member_by_fp(fp_hex);
                }
            } catch (GLib.Error err) {
                warning("rebuild journal: failed at seq=%llu: %s", e.seq, err.message);
            }
        }
    }

    // Bundle-table fallback for AIK lookup when peer_account_identity hasn't
    // been populated yet. The bundle row stores the peer AIK halves verbatim
    // and is written by handle_inbound_bundle just before peer_account_identity.
    private bool find_peer_aik_in_bundles(Account account, uint8[] aik_fp_raw_20,
            out uint8[] out_aik_ed, out uint8[] out_aik_mldsa) {
        out_aik_ed = {};
        out_aik_mldsa = {};
        if (aik_fp_raw_20.length != 20) return false;
        var rows = db.bundle.select().with(db.bundle.account_id, "=", account.id);
        foreach (Row r in rows) {
            string? ed_b64 = r[db.bundle.aik_pub_ed25519_base64];
            string? ml_b64 = r[db.bundle.aik_pub_mldsa_base64];
            if (ed_b64 == null || ml_b64 == null) continue;
            try {
                Bytes ed = bytes_from_base64(ed_b64);
                Bytes ml = bytes_from_base64(ml_b64);
                uint8[] ed_arr = bytes_to_uint8_array(ed);
                uint8[] ml_arr = bytes_to_uint8_array(ml);
                int total = 3 + ed_arr.length + ml_arr.length;
                uint8[] enc = new uint8[total];
                enc[0] = 0; enc[1] = 1; enc[2] = 1;
                Memory.copy((uint8*) enc + 3, ed_arr, ed_arr.length);
                Memory.copy((uint8*) enc + 3 + ed_arr.length, ml_arr, ml_arr.length);
                Bytes digest = global::X3dhpq.Crypto.blake2b160(new Bytes(enc));
                unowned uint8[] dig = digest.get_data();
                bool match = true;
                for (int i = 0; i < 20; i++) {
                    if (dig[i] != aik_fp_raw_20[i]) { match = false; break; }
                }
                if (match) {
                    out_aik_ed = ed_arr;
                    out_aik_mldsa = ml_arr;
                    return true;
                }
            } catch (Error e) {
                continue;
            }
        }
        return false;
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

    public async void prefetch_for_conversation(Conversation conversation) {
        if (conversation.type_ == Conversation.Type.GROUPCHAT_PM) {
            return;
        }

        if (conversation.type_ == Conversation.Type.CHAT) {
            yield ensure_get_keys_for_jid(conversation.account, conversation.counterpart.bare_jid);
            return;
        }

        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            Gee.List<Jid>? members = app.stream_interactor.get_module(MucManager.IDENTITY).get_offline_members(conversation.counterpart, conversation.account);
            if (members == null) {
                return;
            }
            foreach (Jid member in members) {
                if (member.equals(conversation.account.bare_jid)) {
                    continue;
                }
                yield ensure_get_keys_for_jid(conversation.account, member.bare_jid);
            }
        }
    }

    private void on_account_added(Account account) {
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            return;
        }
        // One-shot recovery: if Conversations (or any peer) wiped its
        // pairwise sessions for our JID, our cached session blob points at
        // a peer-side state that no longer exists. Subsequent outbound
        // messages aren't prekey envelopes, so the peer drops them and
        // group SenderChainAnnouncements get stranded. Wipe our pairwise
        // session table once per install so the very next outgoing
        // pairwise envelope re-runs initiate_session and the peer
        // re-runs respond_session.
        wipe_sessions_once(account);
        module.device_list_loaded.connect((jid, devices) => {
            retry_pending(account);
        });
        module.bundle_fetched.connect((jid, device_id, bundle) => {
            retry_pending(account);
        });
        // Wire the membership-journal handler so PEP +notify (and explicit
        // fetch_group_items) results land in the local journal table. Without
        // this connection the room stays "not yet x3dhpq-enabled" and
        // outbound group messages get refused with WONTSEND.
        module.membership_entry_received.connect((room_jid, item_id, b64_payload) => {
            on_membership_entry_received(account, room_jid, item_id, b64_payload);
        });
    }

    // Verify and persist a membership-journal entry received via PEP. The
    // owner AIK is resolved by matching the entry payload's aik_fp against
    // peers we already trust (TOFU on first AddMember). Subsequent entries
    // are verified against the same owner AIK.
    private void on_membership_entry_received(Account account, Jid room_jid, string? item_id, string b64_payload) {
        uint8[] entry_bytes;
        try {
            entry_bytes = Base64.decode(b64_payload);
        } catch (Error e) {
            warning("membership-entry: bad base64 from %s: %s", room_jid.to_string(), e.message);
            return;
        }
        Protocol.MemberAuditEntry? entry = Protocol.MemberAuditEntry.unmarshal(entry_bytes);
        if (entry == null) {
            // Diagnostic: show first 16 bytes so we can confirm whether the
            // wire prefix is the canonical 16-byte "X3DHPQ-Audit-v1\0".
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < entry_bytes.length && i < 24; i++) {
                hex.append_printf("%02x", entry_bytes[i]);
            }
            warning("membership-entry: unmarshal failed for %s (len=%d, head=%s)",
                room_jid.to_string(), entry_bytes.length, hex.str);
            return;
        }
        uint8[] aik_fp_raw;
        uint32 epoch_after;
        if (!Protocol.MemberAuditEntry.parse_member_payload(entry.payload, out aik_fp_raw, out epoch_after)) {
            warning("membership-entry: bad payload for %s", room_jid.to_string());
            return;
        }
        // Per XEP §13.8 the owner's AIK signs every entry; resolve it from
        // the genesis (seq=0) entry's own fp via TOFU.
        uint8[] owner_aik_ed;
        uint8[] owner_aik_mldsa;
        if (entry.seq == 0 && entry.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
            // Genesis adds the owner themselves: aik_fp_raw IS the owner's fp.
            if (!db.find_peer_account_identity_by_aik_fp(account, aik_fp_raw,
                    out owner_aik_ed, out owner_aik_mldsa)) {
                warning("membership-entry seq=0 in %s references unknown AIK fp; storing unverified",
                    room_jid.to_string());
                // Best-effort store anyway so subsequent rebuild can proceed.
                db.store_membership_journal_entry(account, room_jid.bare_jid.to_string(), entry);
                return;
            }
        } else {
            // Non-genesis: the owner is whoever published seq=0. Look it up
            // from any prior stored entry's payload.
            uint8[]? prior_owner_fp = first_stored_owner_fp(account, room_jid.bare_jid.to_string());
            if (prior_owner_fp == null) {
                warning("membership-entry seq=%llu arrived before genesis in %s; skipping",
                    entry.seq, room_jid.to_string());
                return;
            }
            if (!db.find_peer_account_identity_by_aik_fp(account, prior_owner_fp,
                    out owner_aik_ed, out owner_aik_mldsa)) {
                warning("membership-entry seq=%llu in %s: prior owner fp not resolvable",
                    entry.seq, room_jid.to_string());
                return;
            }
        }
        bool ok;
        try {
            ok = entry.verify(new Bytes(owner_aik_ed), new Bytes(owner_aik_mldsa));
        } catch (Error e) {
            warning("membership-entry verify error for %s: %s", room_jid.to_string(), e.message);
            return;
        }
        if (!ok) {
            warning("membership-entry signature INVALID for %s seq=%llu",
                room_jid.to_string(), entry.seq);
            return;
        }
        db.store_membership_journal_entry(account, room_jid.bare_jid.to_string(), entry);
    }

    // Returns the AIK fp (raw 20 bytes) embedded in the seq=0 AddMember entry
    // already stored for the given room, or null if not yet seen.
    private uint8[]? first_stored_owner_fp(Account account, string room_jid_str) {
        Row? r = db.membership_journal.select()
            .with(db.membership_journal.account_id, "=", account.id)
            .with(db.membership_journal.room_jid, "=", room_jid_str)
            .with(db.membership_journal.seq, "=", 0)
            .single().row().inner;
        if (r == null) return null;
        string? payload_b64 = ((!) r)[db.membership_journal.payload_base64];
        if (payload_b64 == null) return null;
        try {
            uint8[] payload = Base64.decode(payload_b64);
            uint8[] fp;
            uint32 ep;
            if (!Protocol.MemberAuditEntry.parse_member_payload(payload, out fp, out ep)) return null;
            return fp;
        } catch (Error e) {
            return null;
        }
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

        // GROUPCHAT path: use sender-chain group encryption.
        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            string room_jid_str = conversation.counterpart.bare_jid.to_string();
            if (!db.has_membership_journal(conversation.account, room_jid_str)) {
                // No membership journal — room is not yet x3dhpq-enabled. Refuse.
                warning("x3dhpq group send refused for %s: no membership journal", room_jid_str);
                message.marked = Message.Marked.WONTSEND;
                return;
            }
            try {
                build_group_encrypted_message(message, message_stanza, conversation);
                pending_messages.unset(message);
            } catch (Error e) {
                warning("Unable to group-encrypt x3dhpq message for %s: %s", room_jid_str, e.message);
                mark_pending(message, conversation);
            }
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

    // Per-room dedup of "we have already broadcast our sender chain to this
    // (peer_bare_jid, peer_device_id)". Without this, every encrypt would
    // fan out duplicate announcements.
    private HashMap<string, Gee.Set<string>> announced_to = new HashMap<string, Gee.Set<string>>();

    private void broadcast_sender_chain(Conversation conversation, Protocol.GroupSession gs,
            string room_jid_str, uint8[] aik_ed, uint8[] aik_mldsa) {
        XmppStream? stream = app.stream_interactor.get_stream(conversation.account);
        if (stream == null) return;

        Protocol.SenderChainAnnouncement ann;
        try {
            ann = gs.announce_sender_chain();
        } catch (GLib.Error e) {
            warning("announce_sender_chain failed for %s: %s", room_jid_str, e.message);
            return;
        }
        uint8[] ann_bytes = ann.marshal();

        Gee.Set<string> already = announced_to.get(room_jid_str);
        if (already == null) {
            already = new Gee.HashSet<string>();
            announced_to.set(room_jid_str, already);
        }

        // Iterate occupants of the MUC, skip ourselves, send pairwise envelope
        // tagged <payload type='sender-chain'> to each remaining device.
        Gee.List<Jid>? occupants = app.stream_interactor.get_module(MucManager.IDENTITY)
            .get_offline_members(conversation.counterpart, conversation.account);
        if (occupants == null) return;

        StreamModule? module = app.stream_interactor.module_manager.get_module(conversation.account, StreamModule.IDENTITY);
        int sent = 0;
        foreach (Jid occ in occupants) {
            if (occ.equals_bare(conversation.account.bare_jid)) continue;
            string peer_bare = occ.bare_jid.to_string();
            Gee.List<int> device_ids = db.get_remote_device_ids(conversation.account, peer_bare);
            if (device_ids.size == 0) {
                if (module != null) {
                    module.request_device_list.begin((!) stream, occ.bare_jid);
                }
                continue;
            }
            foreach (int device_id in device_ids) {
                string key = "%s/%d".printf(peer_bare, device_id);
                Protocol.PeerBundle? bundle = db.get_remote_bundle(conversation.account, peer_bare, device_id);
                if (bundle == null || !bundle.verify()) {
                    if (module != null) {
                        module.request_bundle.begin((!) stream, occ.bare_jid, device_id);
                    }
                    continue;
                }
                // Re-broadcast on every encrypt. The dedup ("already
                // announced") set was masking failed deliveries: if the
                // first announcement got lost on the wire (e.g. server-side
                // CSI hold or Conversations-side parser miss), we'd never
                // retry. Until we have a positive ACK that the peer
                // installed the chain, every send re-announces — peers
                // dedup on (sender_aik_fp, device, epoch) when accepting
                // and reinstalling the same recv chain is a no-op.
                if (send_sender_chain_to_device(conversation, occ.bare_jid, device_id, bundle, ann_bytes)) {
                    already.add(key);
                    sent++;
                }
            }
        }
    }

    private bool send_sender_chain_to_device(Conversation conversation, Jid peer_bare,
            int device_id, Protocol.PeerBundle bundle, uint8[] ann_bytes) {
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null) return false;

        try {
            // Random transport key (32 + 12 = 44 bytes), used to AES-GCM the
            // announcement bytes; the transport key itself is then sealed
            // pairwise via the existing X3DHPQ session.
            Bytes payload_key = global::X3dhpq.Crypto.random_bytes(32);
            Bytes payload_nonce = global::X3dhpq.Crypto.random_bytes(12);
            Bytes payload_transport_key = bytes_from_uint8_array(
                concat_byte_arrays(bytes_to_uint8_array(payload_key), bytes_to_uint8_array(payload_nonce)));
            Bytes payload_ciphertext = Protocol.encrypt_payload_bytes(new Bytes(ann_bytes), payload_transport_key);

            Protocol.SessionState? state = db.get_session(conversation.account, peer_bare.to_string(), device_id);
            if (state != null && (state.chain_send_key == null
                    || bytes_to_uint8_array((!) state.chain_send_key).length == 0)) {
                db.delete_session(conversation.account, peer_bare.to_string(), device_id);
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
            db.store_session(conversation.account, peer_bare.to_string(), device_id, (!) state);

            // Build the wire message. <x3dhpq><key rid=...><hdr/><emk/>{<prekey/>}</key>
            //   <payload type='sender-chain'>BASE64(ct)</payload></x3dhpq>
            StanzaNode envelope = new StanzaNode.build("x3dhpq", Protocol.NS_ENVELOPE)
                .add_self_xmlns()
                .put_attribute("sender-device", ((!) local_device_id).to_string())
                .put_attribute("sender-jid", conversation.account.bare_jid.to_string())
                .put_attribute("ts", new DateTime.now_utc().format_iso8601());

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
            envelope.put_node(new StanzaNode.build("payload", Protocol.NS_ENVELOPE)
                .put_attribute("type", Protocol.PAYLOAD_TYPE_SENDER_CHAIN)
                .put_node(new StanzaNode.text(bytes_to_base64(payload_ciphertext))));

            Xmpp.MessageStanza msg = new Xmpp.MessageStanza();
            msg.to = peer_bare;
            msg.type_ = Xmpp.MessageStanza.TYPE_CHAT;
            msg.stanza.put_node(envelope);
            // Tell the server: don't store, don't carbon (XEP-0334 / XEP-0280).
            Xmpp.Xep.MessageProcessingHints.set_message_hint(msg, Xmpp.Xep.MessageProcessingHints.HINT_NO_STORE);
            Xmpp.Xep.MessageProcessingHints.set_message_hint(msg, Xmpp.Xep.MessageProcessingHints.HINT_NO_COPY);

            XmppStream? stream = app.stream_interactor.get_stream(conversation.account);
            if (stream == null) return false;
            stream.get_module(Xmpp.MessageModule.IDENTITY).send_message.begin(stream, msg);
            return true;
        } catch (Error e) {
            warning("send_sender_chain_to_device(%s/%d) failed: %s",
                peer_bare.to_string(), device_id, e.message);
            return false;
        }
    }

    private void build_group_encrypted_message(Entities.Message message, Xmpp.MessageStanza message_stanza, Conversation conversation) throws Error {
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null || message_stanza.body == null) {
            throw new IOError.FAILED("Missing local device or body");
        }
        string room_jid_str = conversation.counterpart.bare_jid.to_string();
        // Build canonical aik pub bytes (version | has_mldsa | ed25519 | mldsa).
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);

        Protocol.GroupSession? gs = db.load_group_session(conversation.account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        }

        // Replay the persisted journal so members map is up to date. Without
        // this, the local session has empty members and announce_sender_chain
        // can't tell who to address.
        rebuild_group_session_from_journal(conversation.account, room_jid_str, (!) gs);

        // Broadcast our sender chain to every member device that hasn't yet
        // received it. Without this, peers see "no recv chain for ..." and
        // drop our group messages. Idempotent via announced_to.
        broadcast_sender_chain(conversation, (!) gs, room_jid_str, aik_ed, aik_mldsa);

        uint8[] plaintext = string_to_bytes((!) message_stanza.body);
        Protocol.GroupMessageHeader hdr;
        uint8[] ciphertext;
        gs.encrypt(plaintext, out hdr, out ciphertext);

        db.store_group_session(conversation.account, room_jid_str, (!) gs);

        // Compute sender AIK fingerprint for the envelope attribute.
        string sender_aik_fp = db.get_aik_fingerprint(conversation.account) ?? "";

        StanzaNode group_env = new StanzaNode.build("x3dhpq-group", Protocol.NS_ENVELOPE)
            .add_self_xmlns()
            .put_attribute("sender-aik-fp", sender_aik_fp)
            .put_node(new StanzaNode.build("hdr", Protocol.NS_ENVELOPE)
                .put_node(new StanzaNode.text(Base64.encode(hdr.marshal()))))
            .put_node(new StanzaNode.build("ct", Protocol.NS_ENVELOPE)
                .put_node(new StanzaNode.text(Base64.encode(ciphertext))));

        message_stanza.stanza.put_node(group_env);
        ExplicitEncryption.add_encryption_tag_to_message(message_stanza, Protocol.NS_X3DHPQ, "x3dhpq");
        message_stanza.body = "[This message is x3dhpq group encrypted]";
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
        // Check for group envelope first.
        StanzaNode? group_env = stanza.stanza.get_subnode("x3dhpq-group", Protocol.NS_ENVELOPE);
        if (group_env != null) {
            return decrypt_group_message(message, stanza, conversation, group_env);
        }

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
        Protocol.SessionState? state_to_commit = null;
        bool consume_one_time_prekey = false;
        int consumed_opk_id = 0;

        StanzaNode? prekey_node = ((!) key_node).get_subnode("prekey", Protocol.NS_ENVELOPE);

        // Both sides may initiate near-simultaneously; whichever envelope arrives
        // first finds an existing self-initiated session whose chain_recv_key is
        // null because we never received from the peer. The cached session is
        // useless for decrypting the peer's incoming prekey envelope — its
        // sending_dh_priv is our own ephemeral, not our SPK priv. Treat that
        // case as if no session existed and run respond_session, which derives
        // the canonical responder state and replaces the orphan. Our previously
        // queued outbound (encrypted under the orphan) is acceptable to drop —
        // the peer never set up a session that could decrypt it anyway.
        bool prekey_overrides_orphan = state != null
            && prekey_node != null
            && (state.chain_recv_key == null
                || bytes_to_uint8_array((!) state.chain_recv_key).length == 0);

        if (state == null || prekey_overrides_orphan) {
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
                state_to_commit = Protocol.respond_session(
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
                if (local_opk != null) {
                    consume_one_time_prekey = true;
                    consumed_opk_id = opk_id;
                }
            } catch (Error e) {
                warning("Unable to respond to x3dhpq prekey message from %s/%d: %s", sender_jid_value, sender_device_id, e.message);
                return false;
            }
        } else {
            state_to_commit = Protocol.SessionState.deserialize((!) state.serialize());
            if (state_to_commit == null) {
                db.delete_session(conversation.account, sender_jid_value, sender_device_id);
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
            Bytes transport_key = Protocol.decrypt_transport_key((!) state_to_commit, header, bytes_from_base64(emk_node.get_string_content()));

            // Check for a sender-chain typed payload in place of a chat message payload.
            StanzaNode? typed_payload = envelope.get_subnode("payload", Protocol.NS_ENVELOPE);
            if (typed_payload != null) {
                string? ptype = typed_payload.get_attribute("type");
                if (ptype == Protocol.PAYLOAD_TYPE_SENDER_CHAIN) {
                    // Decrypt and route the sender chain announcement.
                    string? sc_b64 = typed_payload.get_string_content();
                    if (sc_b64 != null) {
                        try {
                            Bytes sc_bytes_decrypted = Protocol.decrypt_payload_bytes(transport_key, bytes_from_base64(sc_b64));
                            Protocol.SenderChainAnnouncement? ann = Protocol.SenderChainAnnouncement.unmarshal(
                                bytes_to_uint8_array(sc_bytes_decrypted));
                            if (ann != null) {
                                on_sender_chain_announcement(conversation.account, ann);
                            } else {
                                warning("x3dhpq sender-chain unmarshal returned null from %s/%d",
                                    sender_jid_value, sender_device_id);
                            }
                        } catch (GLib.Error e) {
                            warning("x3dhpq sender-chain payload decrypt failed: %s", e.message);
                        }
                    }
                    db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state_to_commit);
                    if (consume_one_time_prekey) {
                        db.mark_local_one_time_pre_key_consumed(conversation.account, consumed_opk_id);
                    }
                    // Do not set message.body — this is a control message, not visible.
                    return false;
                }
            }

            string plaintext;
            Protocol.decrypt_payload(transport_key, bytes_from_base64((!) payload_node.get_string_content()), out plaintext);
            db.store_session(conversation.account, sender_jid_value, sender_device_id, (!) state_to_commit);
            if (consume_one_time_prekey) {
                db.mark_local_one_time_pre_key_consumed(conversation.account, consumed_opk_id);
            }
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

    private void on_sender_chain_announcement(Dino.Entities.Account account, Protocol.SenderChainAnnouncement ann) {
        // Look up or create the group session for this room.
        string room_jid_str = ann.room_jid;
        int? local_device_id = db.get_local_device_id(account);
        if (local_device_id == null) return;
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
        Protocol.GroupSession? gs = db.load_group_session(account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            try {
                gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
            } catch (GLib.Error e) {
                warning("x3dhpq new_session failed for %s: %s", room_jid_str, e.message);
                return;
            }
        }
        // Replay journal so the members map is non-empty before accept.
        rebuild_group_session_from_journal(account, room_jid_str, (!) gs);
        try {
            gs.accept_sender_chain(ann);
            db.store_group_session(account, room_jid_str, gs);
        } catch (GLib.Error e) {
            warning("x3dhpq accept_sender_chain failed for %s: %s", room_jid_str, e.message);
        }
    }

    private bool decrypt_group_message(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation, StanzaNode group_env) {
        StanzaNode? hdr_node = group_env.get_subnode("hdr", Protocol.NS_ENVELOPE);
        StanzaNode? ct_node = group_env.get_subnode("ct", Protocol.NS_ENVELOPE);
        if (hdr_node == null || ct_node == null) return false;
        string? hdr_b64 = hdr_node.get_string_content();
        string? ct_b64 = ct_node.get_string_content();
        if (hdr_b64 == null || ct_b64 == null) return false;

        Protocol.GroupMessageHeader? hdr = Protocol.GroupMessageHeader.unmarshal(
            bytes_to_uint8_array(bytes_from_base64(hdr_b64)));
        if (hdr == null) return false;

        string? sender_aik_fp = group_env.get_attribute("sender-aik-fp");
        if (sender_aik_fp == null) return false;

        string room_jid_str = conversation.counterpart.bare_jid.to_string();
        int? local_device_id = db.get_local_device_id(conversation.account);
        if (local_device_id == null) return false;
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(conversation.account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);

        // MUC echoes our own groupchat messages back to us. We don't have a
        // recv chain for ourselves (we have the send chain), so attempting
        // to decrypt would always fail with "no recv chain". Skip silently
        // — the local UI already shows the message from when we sent it.
        try {
            string my_fp = account_fingerprint(new Bytes(aik_ed), new Bytes(aik_mldsa));
            if (my_fp == sender_aik_fp) {
                return false;
            }
        } catch (Error e) {
            // fall through; worst case is a "no recv chain" warning we
            // already saw before this guard.
        }

        Protocol.GroupSession? gs = db.load_group_session(conversation.account, room_jid_str, canonical_aik, (uint32)(!) local_device_id);
        if (gs == null) {
            try {
                gs = Protocol.GroupSession.new_session(room_jid_str, canonical_aik, (uint32)(!) local_device_id);
            } catch (GLib.Error e) {
                return false;
            }
        }
        // Replay journal so members + removed_aiks are populated before
        // gs.decrypt does its sender-membership check.
        rebuild_group_session_from_journal(conversation.account, room_jid_str, (!) gs);

        try {
            uint8[] plaintext = gs.decrypt((!) sender_aik_fp, hdr, bytes_to_uint8_array(bytes_from_base64(ct_b64)));
            db.store_group_session(conversation.account, room_jid_str, gs);
            message.body = (string) plaintext;
            message.encryption = Encryption.X3DHPQ;
            return true;
        } catch (GLib.Error e) {
            warning("x3dhpq group decrypt failed from %s in %s: %s", sender_aik_fp, room_jid_str, e.message);
            return false;
        }
    }

    // Static helper so on_sender_chain_announcement and build_group_encrypted_message share logic.
    private static uint8[] build_canonical_aik_bytes_static(uint8[] ed25519_pub, uint8[] mldsa_pub) {
        bool has_mldsa = mldsa_pub.length > 0;
        int total = 2 + 1 + 32 + mldsa_pub.length;
        uint8[] buf = new uint8[total];
        buf[0] = 0; buf[1] = 1;
        buf[2] = has_mldsa ? 1 : 0;
        Memory.copy((uint8*) buf + 3, ed25519_pub, 32);
        if (has_mldsa) {
            Memory.copy((uint8*) buf + 35, mldsa_pub, mldsa_pub.length);
        }
        return buf;
    }

    // Bootstrap x3dhpq on a newly created private group.
    // Publishes the genesis journal entry (seq=0 AddMember[self]) so that
    // has_membership_journal() returns true immediately and the first
    // outbound group message is not refused.
    public async bool ensure_private_group_bootstrapped(Dino.Entities.Account account, Jid room_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return false;
        }
        string room_jid_str = room_jid.bare_jid.to_string();
        if (db.has_membership_journal(account, room_jid_str)) {
            return true;
        }
        db.ensure_local_identity(account);
        db.ensure_local_prekeys(account);
        uint8[] aik_ed = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_ed25519_base64));
        uint8[] aik_mldsa = bytes_to_uint8_array(db.get_local_identity_bytes(account, db.account_identity.aik_pub_mldsa_base64));
        uint8[] canonical_aik = Manager.build_canonical_aik_bytes_static(aik_ed, aik_mldsa);
        uint8[] aik_fp_raw = null;
        try {
            Bytes fp_bytes = global::X3dhpq.Crypto.blake2b160(new Bytes(canonical_aik));
            aik_fp_raw = bytes_to_uint8_array(fp_bytes);
        } catch (GLib.Error e) {
            return false;
        }
        try {
            Protocol.MemberAuditEntry entry = new Protocol.MemberAuditEntry();
            entry.seq = 0;
            entry.prev_hash = new uint8[32];
            entry.action = (uint8) Protocol.MemberAuditAction.ADD_MEMBER;
            entry.payload = Protocol.MemberAuditEntry.build_member_payload(aik_fp_raw, 1);
            entry.timestamp = new DateTime.now_utc().to_unix();
            try {
                uint8[] sp = entry.signed_part();
                Bytes aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
                Bytes aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
                entry.signature = bytes_to_uint8_array(
                    global::X3dhpq.Crypto.ed25519_sign(aik_priv_ed, new Bytes(sp)));
                entry.mldsa_signature = bytes_to_uint8_array(
                    global::X3dhpq.Crypto.mldsa65_sign(aik_priv_mldsa, new Bytes(sp)));
            } catch (GLib.Error e) {
                return false;
            }
            if (!yield module.publish_membership_audit_entry(stream, room_jid.bare_jid, entry)) {
                return false;
            }
            db.store_membership_journal_entry(account, room_jid_str, entry);
            module.subscribe_to_group_node.begin((!) stream, room_jid.bare_jid, (obj, res) => {
                module.subscribe_to_group_node.end(res);
                module.fetch_group_items.begin((!) stream, room_jid.bare_jid);
            });
            return true;
        } catch (GLib.Error e) {
            return false;
        }
    }

    public async bool add_private_group_member(Dino.Entities.Account account, Jid room_jid, Jid member_jid) {
        XmppStream? stream = app.stream_interactor.get_stream(account);
        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (stream == null || module == null) {
            return false;
        }
        if (!yield ensure_private_group_bootstrapped(account, room_jid)) {
            return false;
        }
        if (!(yield ensure_get_keys_for_jid(account, member_jid.bare_jid))) {
            warning("x3dhpq member add failed for %s in %s: peer bundle unavailable",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string());
            return false;
        }

        uint8[] member_aik_fp_raw;
        if (!db.get_peer_aik_fingerprint_raw(account, member_jid.bare_jid.to_string(), out member_aik_fp_raw)) {
            warning("x3dhpq member add failed for %s in %s: peer AIK unavailable",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string());
            return false;
        }

        var entries = db.list_membership_journal_entries(account, room_jid.bare_jid.to_string());
        bool is_active_member = false;
        foreach (Protocol.MemberAuditEntry entry in entries) {
            uint8[] aik_fp_raw;
            uint32 epoch_after;
            if (!Protocol.MemberAuditEntry.parse_member_payload(entry.payload, out aik_fp_raw, out epoch_after)) {
                continue;
            }
            bool same_member = aik_fp_raw.length == member_aik_fp_raw.length;
            for (int i = 0; same_member && i < aik_fp_raw.length; i++) {
                if (aik_fp_raw[i] != member_aik_fp_raw[i]) same_member = false;
            }
            if (!same_member) continue;
            if (entry.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                is_active_member = true;
            } else if (entry.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                is_active_member = false;
            }
        }
        if (is_active_member) {
            return true;
        }

        uint64 next_seq = 0;
        uint8[] prev_hash = new uint8[32];
        if (entries.size > 0) {
            Protocol.MemberAuditEntry last_entry = entries[entries.size - 1];
            next_seq = last_entry.seq + 1;
            prev_hash = last_entry.compute_hash();
        }

        Bytes owner_aik_priv_ed = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_ed25519_base64));
        Bytes owner_aik_priv_mldsa = bytes_from_base64((!) db.get_local_identity_string(account, db.account_identity.aik_priv_mldsa_base64));
        Protocol.MemberAuditEntry stored_entry = new Protocol.MemberAuditEntry();
        stored_entry.seq = next_seq;
        stored_entry.prev_hash = prev_hash;
        stored_entry.action = (uint8) Protocol.MemberAuditAction.ADD_MEMBER;
        stored_entry.payload = Protocol.MemberAuditEntry.build_member_payload(member_aik_fp_raw, 1);
        stored_entry.timestamp = new DateTime.now_utc().to_unix();
        try {
            uint8[] sp = stored_entry.signed_part();
            stored_entry.signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.ed25519_sign(owner_aik_priv_ed, new Bytes(sp)));
            stored_entry.mldsa_signature = bytes_to_uint8_array(
                global::X3dhpq.Crypto.mldsa65_sign(owner_aik_priv_mldsa, new Bytes(sp)));
        } catch (GLib.Error e) {
            warning("x3dhpq member add local signing failed for %s in %s: %s",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string(), e.message);
            return false;
        }
        if (!yield module.publish_membership_audit_entry(stream, room_jid.bare_jid, stored_entry)) {
            warning("x3dhpq member add publish failed for %s in %s",
                member_jid.bare_jid.to_string(), room_jid.bare_jid.to_string());
            return false;
        }
        db.store_membership_journal_entry(account, room_jid.bare_jid.to_string(), stored_entry);
        return true;
    }
}

}
