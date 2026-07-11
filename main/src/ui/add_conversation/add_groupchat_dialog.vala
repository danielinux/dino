using Gee;
using Gtk;

using Dino.Entities;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Ui {

[GtkTemplate (ui = "/im/dino/Dino/add_conversation/add_groupchat_dialog.ui")]
protected class AddGroupchatDialog : Gtk.Dialog {

    [GtkChild] private unowned Stack accounts_stack;
    [GtkChild] private unowned AccountComboBox account_combobox;
    [GtkChild] private unowned Button ok_button;
    [GtkChild] private unowned Button cancel_button;
    [GtkChild] private unowned Entry jid_entry;
    [GtkChild] private unowned Entry alias_entry;
    [GtkChild] private unowned Entry nick_entry;
    [GtkChild] private unowned Entry password_entry;
    [GtkChild] private unowned Switch private_group_switch;
    [GtkChild] private unowned Label jid_label;
    [GtkChild] private unowned Label nick_label;
    [GtkChild] private unowned Label password_label;
    [GtkChild] private unowned Label private_group_label;
    [GtkChild] private unowned Label alias_label;
    [GtkChild] private unowned Box secret_header;
    [GtkChild] private unowned Label secret_header_subtitle;

    private StreamInteractor stream_interactor;
    private bool alias_entry_changed = false;
    // When true, this dialog only ever creates an invite-only, non-anonymous,
    // persistent, x3dhpq-encrypted "Secret Post-Quantum Group". The JID is
    // auto-generated on the account's MUC service and encryption is always on.
    private bool secret_pq_mode = false;

    public AddGroupchatDialog(StreamInteractor stream_interactor, string? title = null, bool private_group_default = true, bool secret_pq_mode = false) {
        Object(use_header_bar : 1);
        this.stream_interactor = stream_interactor;
        this.secret_pq_mode = secret_pq_mode;
        this.title = title ?? (secret_pq_mode ? _("New Secret Post-Quantum Group") : _("New Channel"));
        ok_button.label = secret_pq_mode ? _("Create Secret Group") : _("Create");
        ok_button.add_css_class("suggested-action"); // TODO why doesn't it work in XML
        accounts_stack.set_visible_child_name("combobox");
        account_combobox.initialize(stream_interactor);
        private_group_switch.active = secret_pq_mode || private_group_default;

        if (secret_pq_mode) {
            setup_secret_pq_mode();
        }

        cancel_button.clicked.connect(() => { close(); });
        ok_button.clicked.connect(() => { on_ok_button_clicked.begin(); });

        jid_entry.changed.connect(on_jid_key_release);
        nick_entry.changed.connect(check_ok);
        account_combobox.changed.connect(check_ok);
        if (secret_pq_mode) {
            account_combobox.changed.connect(update_secret_server_gate);
            update_secret_server_gate();
        }
    }

    // Configure the dialog as an explicit "Secret Post-Quantum Group" creator:
    // reveal the post-quantum / invite-only banner, force the private group
    // toggle on and hide it (encryption is always-on), and drop the manual JID,
    // nick and password fields — the room is auto-created on the account's MUC
    // service and the user only picks a display name.
    private void setup_secret_pq_mode() {
        secret_header.visible = true;
        private_group_switch.active = true;

        jid_entry.visible = false;
        jid_label.visible = false;
        nick_entry.visible = false;
        nick_label.visible = false;
        password_entry.visible = false;
        password_label.visible = false;
        private_group_switch.visible = false;
        private_group_label.visible = false;

        alias_label.label = _("Name");
        alias_entry.grab_focus();
    }

    // Server capability gate: only offer creation if the selected account has a
    // discovered MUC (XEP-0045) conference service. Dino discovers a
    // CATEGORY_CONFERENCE service (advertising http://jabber.org/protocol/muc)
    // and exposes it via MucManager.default_muc_server; a null entry means the
    // server does not offer group chats, so we disable creation and explain why.
    private void update_secret_server_gate() {
        if (!secret_pq_mode) return;
        Account? account = account_combobox.selected;
        bool muc_available = account != null &&
                stream_interactor.get_module(MucManager.IDENTITY).default_muc_server[account] != null;
        if (muc_available) {
            secret_header_subtitle.label = _("End-to-end post-quantum encrypted and invite-only. Only you, the creator, can add or remove members.");
            secret_header_subtitle.remove_css_class("error");
            alias_entry.sensitive = true;
        } else {
            secret_header_subtitle.label = _("Your server doesn’t allow group chats, so a secret group can’t be created on this account.");
            secret_header_subtitle.add_css_class("error");
            alias_entry.sensitive = false;
        }
        check_ok();
    }

    private void on_jid_key_release() {
        check_ok();
        if (!alias_entry_changed) {
            if (jid_entry.text.strip() == "") {
                alias_entry.text = "";
                return;
            }
            try {
                Jid parsed_jid = new Jid(jid_entry.text);
                alias_entry.text = parsed_jid != null && parsed_jid.localpart != null ? parsed_jid.localpart : jid_entry.text;
            } catch (InvalidJidError e) {
                alias_entry.text = jid_entry.text;
            }
        }
    }

    private void check_ok() {
        if (secret_pq_mode) {
            // JID is auto-generated on the account's MUC service; the only
            // requirement is that such a service exists.
            Account? account = account_combobox.selected;
            ok_button.sensitive = account != null &&
                    stream_interactor.get_module(MucManager.IDENTITY).default_muc_server[account] != null;
            return;
        }
        if (jid_entry.text.strip() == "") {
            ok_button.sensitive = stream_interactor.get_module(MucManager.IDENTITY).default_muc_server[account_combobox.selected] != null;
            return;
        }
        try {
            Jid parsed_jid = new Jid(jid_entry.text);
            ok_button.sensitive = parsed_jid != null && parsed_jid.localpart != null && parsed_jid.resourcepart == null;
        } catch (InvalidJidError e) {
            ok_button.sensitive = false;
        }
    }

    private async void on_ok_button_clicked() {
        try {
            Account account = account_combobox.selected;
            Jid room_jid = yield get_target_room_jid(account);

            Conference conference = new Conference();
            conference.jid = room_jid;
            conference.nick = nick_entry.text != "" ? nick_entry.text : null;
            conference.password = password_entry.text != "" ? password_entry.text : null;
            conference.name = alias_entry.text != "" ? alias_entry.text : room_jid.localpart;

            bool should_join = private_group_switch.active || jid_entry.text.strip() == "";
            if (should_join) {
                Muc.JoinResult? join_result = yield stream_interactor.get_module(MucManager.IDENTITY).join(account, room_jid, conference.nick, conference.password);
                if (join_result == null || join_result.nick == null) {
                    return;
                }
                if (join_result.newly_created && private_group_switch.active) {
                    yield configure_private_room(account, conference);

                    // Force x3dhpq encryption for privacy
                    Conversation? conversation = stream_interactor.get_module(ConversationManager.IDENTITY).get_conversation(room_jid.bare_jid, account, Conversation.Type.GROUPCHAT);
                    if (conversation != null) {
                        conversation.encryption = Encryption.X3DHPQ;
                    }

                    // Bootstrap membership journal
                    Application? app = GLib.Application.get_default() as Application;
                    if (app != null && app.plugin_registry.x3dhpq_group_manager != null) {
                        yield app.plugin_registry.x3dhpq_group_manager.ensure_private_group_bootstrapped(account, conference.jid);
                    }
                }
            }

            // join() already persists/updates the bookmark via set_autojoin().
            // Adding it again here creates a duplicate entry for the same room.
            if (!should_join) {
                stream_interactor.get_module(MucManager.IDENTITY).add_bookmark(account, conference);
            }
            close();
        } catch (Error e) {
            warning("Failed to create groupchat: %s", e.message);
        }
    }

    private async Jid get_target_room_jid(Account account) throws Error {
        if (jid_entry.text.strip() != "") {
            return new Jid(jid_entry.text);
        }
        Jid? muc_service = stream_interactor.get_module(MucManager.IDENTITY).default_muc_server[account];
        if (muc_service == null) {
            throw new IOError.FAILED("MUC service not available");
        }
        return new Jid("%08x@".printf(Random.next_int()) + muc_service.to_string());
    }

    private async void configure_private_room(Account account, Conference conference) {
        Xep.DataForms.DataForm? data_form = yield stream_interactor.get_module(MucManager.IDENTITY).get_config_form(account, conference.jid);
        if (data_form == null) return;

        foreach (Xep.DataForms.DataForm.Field field in data_form.fields) {
            switch (field.var) {
                case "muc#roomconfig_allowinvites":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = false;
                    }
                    break;
                case "muc#roomconfig_persistentroom":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = true;
                    }
                    break;
                case "muc#roomconfig_publicroom":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = false;
                    }
                    break;
                case "muc#roomconfig_membersonly":
                    // Secret PQ groups are NOT members-only. x3dhpq's membership
                    // journal is the sole source of truth for who may decrypt;
                    // the MUC stays agnostic (a dumb transport). An open room also
                    // sidesteps server-side entry gating (affiliation grants,
                    // CAPTCHA on members-only entry) that blocked invitees from
                    // joining. Confidentiality is unaffected — a non-member can
                    // join the MUC and see only ciphertext.
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = false;
                    }
                    break;
                case "muc#roomconfig_changesubject":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = false;
                    }
                    break;
                case "muc#roomconfig_whois":
                    if (field.type_ == Xep.DataForms.DataForm.Type.LIST_SINGLE) {
                        ((Xep.DataForms.DataForm.ListSingleField) field).value = "anyone";
                    }
                    break;
                case "muc#roomconfig_enablearchiving":
                case "mam":
                case "muc#roomconfig_mam":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = true;
                    }
                    break;
                case "muc#roomconfig_enablelogging":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = false;
                    }
                    break;
                case "muc#roomconfig_roomname":
                    if (field.type_ == Xep.DataForms.DataForm.Type.TEXT_SINGLE && conference.name != null) {
                        ((Xep.DataForms.DataForm.TextSingleField) field).value = conference.name;
                    }
                    break;
                case "muc#roomconfig_roomsecret":
                    if (conference.password == null) break;
                    if (field.type_ == Xep.DataForms.DataForm.Type.TEXT_PRIVATE) {
                        ((Xep.DataForms.DataForm.TextPrivateField) field).value = conference.password;
                    } else if (field.type_ == Xep.DataForms.DataForm.Type.TEXT_SINGLE) {
                        ((Xep.DataForms.DataForm.TextSingleField) field).value = conference.password;
                    }
                    break;
            }
        }
        yield stream_interactor.get_module(MucManager.IDENTITY).set_config_form(account, conference.jid, data_form);
        // The room's disco#info features (muc_membersonly, muc_nonanonymous) only
        // reflect the config we just applied after a fresh disco. Refresh now so
        // is_private_room() is reliable immediately (invite type, member ops, etc.)
        // instead of staying false until the next app restart / room reopen.
        yield stream_interactor.get_module(Dino.EntityInfo.IDENTITY).refresh_features(account, conference.jid);
    }
}

}
