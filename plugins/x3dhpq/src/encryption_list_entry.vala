using Dino.Entities;

namespace Dino.Plugins.X3dhpq {

public class EncryptionListEntry : Plugins.EncryptionListEntry, Object {
    private Plugin plugin;

    public EncryptionListEntry(Plugin plugin) {
        this.plugin = plugin;
    }

    public Entities.Encryption encryption { get { return Encryption.X3DHPQ; } }

    public string name { get { return "x3dhpq"; } }

    public Object? get_encryption_icon(Entities.Conversation conversation, ContentItem content_item) {
        return null;
    }

    public string? get_encryption_icon_name(Entities.Conversation conversation, ContentItem content_item) {
        if (content_item.encryption != encryption) {
            return null;
        }
        return "dino-security-high-symbolic";
    }

    // Attribute a message (1:1 or group/MUC) that was authored by ANOTHER of the
    // user's own devices (same bare JID, different x3dhpq device id) with the
    // local device label. Recorded at decrypt time in the plugin DB, keyed by
    // stanza id. The lookup is purely by stanza id and self-suppresses when the
    // source is this device, so it works uniformly for both conversation types.
    public string? get_message_attribution(Entities.Conversation conversation, ContentItem content_item) {
        if (content_item.encryption != encryption) return null;
        if (conversation.type_ != Conversation.Type.CHAT
                && conversation.type_ != Conversation.Type.GROUPCHAT) return null;
        MessageItem? message_item = content_item as MessageItem;
        if (message_item == null) return null;
        string? stanza_id = message_item.message.stanza_id;
        if (stanza_id == null) return null;
        int? source_device_id = plugin.db.lookup_message_source_device(conversation.account, (!) stanza_id);
        if (source_device_id == null) return null;
        int? local_device_id = plugin.db.get_local_device_id(conversation.account);
        if (local_device_id != null && ((int) (!) source_device_id) == ((int) (!) local_device_id)) return null;
        return "from " + plugin.db.device_display_label(conversation.account, (int) (!) source_device_id);
    }

    public void encryption_activated(Entities.Conversation conversation, Plugins.SetInputFieldStatus input_status_callback) {
        encryption_activated_async.begin(conversation, input_status_callback);
    }

    public async void encryption_activated_async(Entities.Conversation conversation, Plugins.SetInputFieldStatus input_status_callback) {
        if (conversation.type_ == Conversation.Type.GROUPCHAT_PM) {
            input_status_callback(new Plugins.InputFieldStatus("Can't use x3dhpq in a groupchat private message.", Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
            return;
        }

        if (!plugin.db.has_local_identity(conversation.account)) {
            input_status_callback(new Plugins.InputFieldStatus("x3dhpq identity setup has not completed for this account.", Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
            return;
        }

        // §10.6.6: a disabled device ("waiting for sync" — never confirmed, or
        // revoked) holds no usable AIK_priv/certificate and MUST NOT send as the
        // account; peers would reject its unverifiable DC. Block at the composer
        // level with a clear reason. An AUTHORIZED device (is_authorized() true)
        // is completely unaffected by this check and proceeds exactly as before.
        if (!plugin.db.is_authorized(conversation.account)) {
            input_status_callback(new Plugins.InputFieldStatus(
                "This device is waiting for sync — it is disabled until an existing authorized device confirms it (Account settings → x3dhpq), or you perform an account reset.",
                Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
            return;
        }

        if (conversation.type_ == Conversation.Type.CHAT) {
            // Enforce peer AIK trust in 1:1 too, consistently with groups. A
            // ROTATED identity (was trusted, key changed) is NOT authenticated —
            // refuse to send until the user reviews & accepts it (spec §12.3
            // RotationTrustStrict). Without this, 1:1 chat would silently encrypt
            // to an unverified new identity while groups correctly reject it, so
            // authenticity would not actually be guaranteed for direct chats.
            if (plugin.manager.peer_aik_needs_review(conversation.account, conversation.counterpart)) {
                input_status_callback(new Plugins.InputFieldStatus("This contact's identity key changed and hasn't been reviewed. Open Contact details → x3dhpq → Review identity before sending.", Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                return;
            }
            if (!(yield plugin.manager.ensure_get_keys_for_jid(conversation.account, conversation.counterpart.bare_jid))) {
                input_status_callback(new Plugins.InputFieldStatus("This contact does not publish usable x3dhpq bundle data.", Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                return;
            }
            // First contact (never verified out-of-band) is opportunistic —
            // allowed, but flagged so the user knows authenticity isn't confirmed.
            if (plugin.manager.get_member_trust_state(conversation.account, conversation.counterpart) == global::Dino.Plugins.MemberTrustState.UNVERIFIED) {
                input_status_callback(new Plugins.InputFieldStatus("Encrypting to an unverified identity — verify the fingerprint in Contact details for full authenticity.", Plugins.InputFieldStatus.MessageType.WARNING, Plugins.InputFieldStatus.InputState.NORMAL));
                return;
            }
        } else if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            string room_jid = conversation.counterpart.bare_jid.to_string();
            if (!plugin.db.has_membership_journal(conversation.account, room_jid)) {
                input_status_callback(new Plugins.InputFieldStatus("This private channel is missing x3dhpq membership state.", Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                return;
            }
            Gee.List<Xmpp.Jid>? members = plugin.app.stream_interactor.get_module(MucManager.IDENTITY).get_offline_members(conversation.counterpart, conversation.account);
            if (members == null) {
                input_status_callback(new Plugins.InputFieldStatus("Group member list is not available yet.", Plugins.InputFieldStatus.MessageType.WARNING, Plugins.InputFieldStatus.InputState.NORMAL));
                return;
            }
            foreach (Xmpp.Jid member in members) {
                if (member.equals(conversation.account.bare_jid)) {
                    continue;
                }
                if (!(yield plugin.manager.ensure_get_keys_for_jid(conversation.account, member.bare_jid))) {
                    input_status_callback(new Plugins.InputFieldStatus("A group member does not publish usable x3dhpq bundle data: %s".printf(member.to_string()), Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                    return;
                }
                uint8[] member_aik_fp_raw;
                if (!plugin.db.get_peer_aik_fingerprint_raw(conversation.account, member.bare_jid.to_string(), out member_aik_fp_raw)) {
                    input_status_callback(new Plugins.InputFieldStatus("A group member is missing x3dhpq identity data: %s".printf(member.to_string()), Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                    return;
                }
                if (!is_active_member(conversation.account, room_jid, member_aik_fp_raw)) {
                    // Owner-side reconciliation: a contact can be a MUC member
                    // (owner granted affiliation) yet absent from the journal if
                    // the invite-time add failed — e.g. their keys weren't fetched
                    // yet, a transient publish error, or they reset their identity
                    // and were only just re-accepted. Their keys are available now
                    // (fetched just above), so if we are the room owner add them to
                    // the journal here instead of dead-ending on an error.
                    if (is_room_owner(conversation) &&
                            (yield plugin.manager.add_private_group_member(conversation.account, conversation.counterpart, member))) {
                        // added (or already present) — continue to the next member
                    } else {
                        input_status_callback(new Plugins.InputFieldStatus("A group member has not been added to this channel's x3dhpq membership journal: %s".printf(member.to_string()), Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                        return;
                    }
                }
            }
        }

        input_status_callback(new Plugins.InputFieldStatus("x3dhpq is ready for this conversation.", Plugins.InputFieldStatus.MessageType.INFO, Plugins.InputFieldStatus.InputState.NORMAL));
    }

    private bool is_room_owner(Conversation conversation) {
        var mm = plugin.app.stream_interactor.get_module(MucManager.IDENTITY);
        Xmpp.Jid? own = mm.get_own_jid(conversation.counterpart, conversation.account);
        if (own == null) return false;
        return mm.get_affiliation(conversation.counterpart, own, conversation.account) == Xmpp.Xep.Muc.Affiliation.OWNER;
    }

    private bool is_active_member(Account account, string room_jid, uint8[] member_aik_fp_raw) {
        bool is_active_member = false;
        foreach (Protocol.MemberAuditEntry entry in plugin.db.list_membership_journal_entries(account, room_jid)) {
            uint8[] aik_fp_raw;
            uint32 epoch_after;
            if (!Protocol.MemberAuditEntry.parse_member_payload(entry.payload, out aik_fp_raw, out epoch_after)) {
                continue;
            }
            bool same_member = aik_fp_raw.length == member_aik_fp_raw.length;
            for (int i = 0; same_member && i < aik_fp_raw.length; i++) {
                if (aik_fp_raw[i] != member_aik_fp_raw[i]) {
                    same_member = false;
                }
            }
            if (!same_member) {
                continue;
            }
            if (entry.action == (uint8) Protocol.MemberAuditAction.ADD_MEMBER) {
                is_active_member = true;
            } else if (entry.action == (uint8) Protocol.MemberAuditAction.REMOVE_MEMBER) {
                is_active_member = false;
            }
        }
        return is_active_member;
    }
}

}
