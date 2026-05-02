using Adw;
using Dino.Entities;
using Qlite;

namespace Dino.Plugins.X3dhpq {

public class ContactDetailsProvider : Plugins.ContactDetailsProvider, Object {
    private Plugin plugin;

    public string id { get { return "x3dhpq_info"; } }
    public string tab { get { return "encryption"; } }

    public ContactDetailsProvider(Plugin plugin) {
        this.plugin = plugin;
    }

    public void populate(Conversation conversation, Plugins.ContactDetails contact_details, WidgetType type) { }

    public Object? get_widget(Conversation conversation) {
        if (conversation.type_ != Conversation.Type.CHAT) {
            return null;
        }

        bool supports_x3dhpq = plugin.contact_supports_x3dhpq(conversation);
        string bare_jid = conversation.counterpart.bare_jid.to_string();
        string fingerprint = plugin.db.get_peer_aik_fingerprint(conversation.account, bare_jid) ?? "Unavailable";
        int device_count = plugin.db.get_remote_device_ids(conversation.account, bare_jid).size;
        int session_count = plugin.db.get_session_count(conversation.account, bare_jid);
        Row? identity = plugin.db.get_peer_account_identity_row(conversation.account, bare_jid);
        string trust_state = identity != null ? ((!) identity)[plugin.db.peer_account_identity.trust_state] : "unknown";
        PreferencesGroup group = new PreferencesGroup() { title = "x3dhpq" };
        group.add(new ActionRow() {
            title = "Capability advertisement",
            subtitle = supports_x3dhpq ? "This contact has advertised x3dhpq support." : "This contact has not advertised x3dhpq support yet.",
        });
        group.add(new ActionRow() {
            title = "Account fingerprint",
            subtitle = fingerprint,
        });
        group.add(new ActionRow() {
            title = "Trust state",
            subtitle = trust_state == "rotated" ? "The contact AIK changed and needs review." : trust_state,
        });
        group.add(new ActionRow() {
            title = "Known devices",
            subtitle = device_count.to_string(),
        });
        group.add(new ActionRow() {
            title = "Established sessions",
            subtitle = session_count.to_string(),
        });
        return group;
    }
}

}
