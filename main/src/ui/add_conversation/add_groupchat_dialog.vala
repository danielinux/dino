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

    private StreamInteractor stream_interactor;
    private bool alias_entry_changed = false;

    public AddGroupchatDialog(StreamInteractor stream_interactor, string? title = null, bool private_group_default = true) {
        Object(use_header_bar : 1);
        this.stream_interactor = stream_interactor;
        this.title = title ?? _("New Channel");
        ok_button.label = _("Create");
        ok_button.add_css_class("suggested-action"); // TODO why doesn't it work in XML
        accounts_stack.set_visible_child_name("combobox");
        account_combobox.initialize(stream_interactor);
        private_group_switch.active = private_group_default;

        cancel_button.clicked.connect(() => { close(); });
        ok_button.clicked.connect(() => { on_ok_button_clicked.begin(); });

        jid_entry.changed.connect(on_jid_key_release);
        nick_entry.changed.connect(check_ok);
        account_combobox.changed.connect(check_ok);
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
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = true;
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
    }
}

}
