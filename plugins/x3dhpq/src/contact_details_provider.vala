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
            subtitle = trust_state == "retired"
                ? retired_subtitle(conversation, identity)
                : trust_state_subtitle(trust_state),
        };
        /* §13.5c: a retired contact still offers the ORDINARY verify flow — with the full
         * "what verifying means" text — because the successor is adopted only by explicit
         * out-of-band re-verification (§12.2). Retirement itself adopts nothing.
         * Deliberately NOT wired to the DESTRUCTIVE "Accept changed identity" styling of
         * the §12.2 takeover alarm. */
        if (trust_state == "rotated" || trust_state == "unverified" || trust_state == "retired") {
            var review_button = new Gtk.Button.with_label(trust_state == "rotated" ? "Review" : "Verify") {
                valign = Gtk.Align.CENTER
            };
            review_button.add_css_class(trust_state == "rotated" ? "warning" : "flat");
            if (trust_state == "retired") {
                // Neutral affordance: this is an expected event, not an alarm.
                review_button.add_css_class("flat");
            }
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
            case "retired":    return "Retired — this identity was replaced by an account reset.";
            default:           return trust_state;
        }
    }

    /* §13.5c client requirement: distinguish the EVIDENCE in the copy.
     *
     * Kind 1 is a statement signed by the old key itself — cryptographic, re-verified
     * locally. Kind 2 is another member's word, and the copy says so and names them,
     * because presenting an unevidenced claim in the same language as a signature is how
     * a user ends up trusting the wrong successor. Either way the successor fingerprint
     * shown is a value to COMPARE OUT OF BAND, never one to accept from this screen.
     */
    private string retired_subtitle(Conversation conversation, Row? identity) {
        string tail = "";
        if (identity != null) {
            string? fp_display = ((!) identity)[plugin.db.peer_account_identity.aik_fingerprint];
            string? fp_hex = (fp_display == null) ? null
                : fp_display.replace(" ", "").down();
            if (fp_hex != null) {
                Row? rec = plugin.db.get_retired_identity_any_room(conversation.account, (!) fp_hex);
                if (rec != null) {
                    int kind = ((!) rec)[plugin.db.retired_identity.evidence_kind];
                    string author = ((!) rec)[plugin.db.retired_identity.author_fp_hex];
                    string successor = ((!) rec)[plugin.db.retired_identity.successor_fp_hex];
                    if (kind == 1) {
                        tail = " The retirement is signed by the old key itself.";
                        if (successor != "") {
                            tail += " They claim to have moved to %s — confirm that fingerprint with them out-of-band before verifying it.".printf(successor);
                        }
                    } else if (kind == 2) {
                        tail = " This is a CLAIM by another member (%s), not proof. Verify the new identity with the contact directly.".printf(author);
                    }
                }
            }
        }
        return "Retired — this identity was replaced by an account reset." + tail;
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
                    // The stale pin was forgotten (the reset IS accepted), but the
                    // contact's NEW identity isn't fetchable yet — usually because
                    // the contact hasn't republished it (e.g. it is offline or has
                    // not reconnected since resetting). It will be adopted
                    // automatically when it arrives; the user can then verify the
                    // new fingerprint. Not a dead end, and not a retry-the-same-way.
                    trust_row.subtitle = "Old identity forgotten. Waiting for the contact to publish its new identity — it will be adopted automatically, then you can verify the new fingerprint.";
                    button.visible = false;
                }
            });
        });
    }
}

}
