using Dino.Entities;

namespace Dino.Plugins.X3dhpq {

public class EncryptionListEntry : Plugins.EncryptionListEntry, Object {
    private Plugin plugin;

    public EncryptionListEntry(Plugin plugin) {
        this.plugin = plugin;
    }

    public Entities.Encryption encryption { get { return Encryption.X3DHPQ; } }

    public string name { get { return "x3dhpq"; } }

    /* The composer's 1:1 identity gate, as a PURE function of the peer's persisted
     * trust_state. Returns null when sending may proceed, or the message to show
     * alongside NO_SEND.
     *
     * Split out from the async callback so the decision itself is assertable without a
     * live Application: it is a security decision — whether this client encrypts to a
     * key — and "which trust states stop a send" is exactly what §13.5c says the two
     * clients must not disagree on.
     *
     *  "rotated"          §12.2: the AIK changed and nobody has reviewed it. We suspect.
     *  "retired"          §12.3 step 3: AUTHORITATIVE retirement — the owner's own signed
     *                     statement that the key is dead. Stronger evidence than the
     *                     above, and the case that matters most: after a compromise-driven
     *                     reset the old key is precisely what the ATTACKER holds, so
     *                     continuing to encrypt to it delivers plaintext to them.
     *  "retired_witnessed" §13.5c: a kind-2 WITNESSED retirement. Deliberately NOT a block.
     *                     No signature binds it; it is one admin's word, authoritative for
     *                     room membership and nothing else. Blocking here would let a
     *                     mistaken or malicious admin render a peer permanently
     *                     unreachable to everyone in the room. It is surfaced in contact
     *                     details and prompts for re-verification instead. */
    public static string? pairwise_send_block_reason(string trust_state) {
        if (trust_state == "rotated") {
            return "This contact's identity key changed and hasn't been reviewed. Open Contact details → x3dhpq → Review identity before sending.";
        }
        if (trust_state == Database.TRUST_RETIRED) {
            return "This contact's identity was retired by an account reset signed with their old key. Sending is paused until you verify their new fingerprint out-of-band (Contact details → x3dhpq → Verify).";
        }
        return null;
    }

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
            /* §12.2 "rotated" AND §12.3 step 3 "retired", through one classifier: both
             * are "we hold no identity we are willing to encrypt to". The retirement arm
             * is not covered by the rotated one — a retirement never passes through
             * "rotated" — and it is the arm that matters most, because after a
             * compromise-driven reset the retired key is exactly what the attacker holds. */
            string? block_reason = pairwise_send_block_reason(
                plugin.db.get_peer_trust_state(conversation.account, conversation.counterpart.bare_jid.to_string()));
            if (block_reason != null) {
                input_status_callback(new Plugins.InputFieldStatus((!) block_reason, Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
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
            // Journal OR v2 DAG: rooms bootstrapped since the §13.1d switch carry a v2
            // genesis and no v1 journal at all, so a has_membership_journal()-only test
            // reports every newly created group as missing its membership state and
            // blocks sending into it. is_secret_pq_group covers both engines.
            if (!plugin.manager.is_secret_pq_group(conversation.account, conversation.counterpart)) {
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
            // §13.1b: a peer advertised membership-journal heads this device
            // lacks (withholding relay, or our own gap). Manager already
            // triggered a rate-limited MAM catch-up; the flag clears itself
            // once the frontiers converge, so this warning is transient.
            if (plugin.manager.is_frontier_divergent(conversation)) {
                input_status_callback(new Plugins.InputFieldStatus("A group member reports membership updates this device doesn't have — catching up. If this persists, a relay may be withholding the group journal (§13.1b).", Plugins.InputFieldStatus.MessageType.WARNING, Plugins.InputFieldStatus.InputState.NORMAL));
                return;
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

    // Delegates to the Manager so the v2 fold is consulted for rooms on the v2
    // engine; walking the v1 journal here reported every member of a v2 room as
    // absent (see Manager.is_active_group_member).
    private bool is_active_member(Account account, string room_jid, uint8[] member_aik_fp_raw) {
        return plugin.manager.is_active_group_member(account, room_jid, member_aik_fp_raw);
    }
}

}
