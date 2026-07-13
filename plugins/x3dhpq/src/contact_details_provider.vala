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
            title = "Identity fingerprint",
            subtitle = fingerprint,
        });
        var trust_row = new ActionRow() {
            title = "Trust state",
            subtitle = trust_state_subtitle(trust_state),
        };
        if (trust_state == "rotated" || trust_state == "unverified") {
            var review_button = new Gtk.Button.with_label(trust_state == "rotated" ? "Review" : "Verify") {
                valign = Gtk.Align.CENTER
            };
            review_button.add_css_class(trust_state == "rotated" ? "warning" : "flat");
            bool changed = trust_state == "rotated";
            review_button.clicked.connect(() => {
                show_accept_identity_dialog(conversation, review_button, trust_row, fingerprint, changed);
            });
            trust_row.add_suffix(review_button);
            trust_row.activatable_widget = review_button;
        }
        group.add(trust_row);
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

    private string trust_state_subtitle(string trust_state) {
        switch (trust_state) {
            case "rotated":    return "The contact's identity key changed and needs review.";
            case "verified":   return "Verified — you accepted this identity.";
            case "unverified": return "Unverified — not yet confirmed out-of-band.";
            default:           return trust_state;
        }
    }

    // Impersonation-aware accept flow. A changed AIK is exactly what a malicious
    // server would substitute, so we NEVER auto-accept: the user must review the
    // new fingerprint out-of-band and confirm here. Only then do we re-pin and
    // recover (accept_peer_aik), which also clears the rollback state rejecting
    // the peer's post-reset devicelist.
    private void show_accept_identity_dialog(Conversation conversation, Gtk.Button button, ActionRow trust_row, string fingerprint, bool changed) {
        string peer = conversation.counterpart.bare_jid.to_string();
        string title = changed ? "Accept changed identity?" : "Verify contact identity?";
        string body;
        if (changed) {
            body = ("%s's post-quantum identity key CHANGED. This is expected if they reinstalled or reset their client, but a changed key can also be an impersonation attempt by a malicious server.\n\n" +
                    "Only accept if you have confirmed this new fingerprint with them out-of-band (in person, a call, or a QR scan):\n\n%s").printf(peer, fingerprint);
        } else {
            body = ("Confirm %s's post-quantum identity fingerprint out-of-band (in person, a call, or a QR scan) before trusting:\n\n%s").printf(peer, fingerprint);
        }
        var confirm = new Adw.AlertDialog(title, body);
        confirm.add_response("cancel", "Cancel");
        confirm.add_response("accept", changed ? "Accept new identity" : "Mark verified");
        confirm.set_response_appearance("accept", changed ? Adw.ResponseAppearance.DESTRUCTIVE : Adw.ResponseAppearance.SUGGESTED);
        confirm.set_default_response("cancel");
        confirm.set_close_response("cancel");
        confirm.choose.begin(button, null, (obj, res) => {
            if (confirm.choose.end(res) != "accept") return;
            button.sensitive = false;
            plugin.manager.accept_peer_aik.begin(conversation.account, conversation.counterpart, (o, r) => {
                bool ok = plugin.manager.accept_peer_aik.end(r);
                if (ok) {
                    trust_row.subtitle = "Verified — identity accepted.";
                    button.visible = false;
                } else {
                    trust_row.subtitle = "Couldn't fetch the new keys — try again when the contact is online.";
                    button.sensitive = true;
                }
            });
        });
    }
}

}
