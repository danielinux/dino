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

        if (conversation.type_ == Conversation.Type.CHAT) {
            if (!(yield plugin.manager.ensure_get_keys_for_jid(conversation.account, conversation.counterpart.bare_jid))) {
                input_status_callback(new Plugins.InputFieldStatus("This contact does not publish usable x3dhpq bundle data.", Plugins.InputFieldStatus.MessageType.ERROR, Plugins.InputFieldStatus.InputState.NO_SEND));
                return;
            }
        } else if (conversation.type_ == Conversation.Type.GROUPCHAT) {
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
            }
        }

        input_status_callback(new Plugins.InputFieldStatus("x3dhpq is ready for this conversation.", Plugins.InputFieldStatus.MessageType.INFO, Plugins.InputFieldStatus.InputState.NORMAL));
    }
}

}
