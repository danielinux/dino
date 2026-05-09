using Dino;
using Dino.Entities;
using Xmpp;
using Xmpp.Xep;
using Gee;
using Gtk;

namespace Dino.Ui.ConversationDetails {

    public void populate_dialog(Model.ConversationDetails model, Conversation conversation, StreamInteractor stream_interactor) {
        model.conversation = conversation;
        model.display_name = stream_interactor.get_module(ContactModels.IDENTITY).get_display_name_model(conversation);
        model.blocked = stream_interactor.get_module(BlockingManager.IDENTITY).is_blocked(model.conversation.account, model.conversation.counterpart);
        model.domain_blocked = stream_interactor.get_module(BlockingManager.IDENTITY).is_blocked(model.conversation.account, model.conversation.counterpart.domain_jid);

        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            stream_interactor.get_module(MucManager.IDENTITY).get_config_form.begin(conversation.account, conversation.counterpart, (_, res) => {
                model.data_form = stream_interactor.get_module(MucManager.IDENTITY).get_config_form.end(res);
                if (model.data_form == null) return;
                model.data_form_bak = model.data_form.stanza_node.to_string();
            });
        }
        if (conversation.type_ == Conversation.Type.CHAT) {
            stream_interactor.get_module(EntityInfo.IDENTITY).get_utc_offset_minutes_for_bare_jid.begin(conversation.account, conversation.counterpart, (_, res) => {
                model.utc_offset_minutes = stream_interactor.get_module(EntityInfo.IDENTITY).get_utc_offset_minutes_for_bare_jid.end(res);
            });
        }
    }

    public void bind_dialog(Model.ConversationDetails model, ViewModel.ConversationDetails view_model, StreamInteractor stream_interactor) {
        // Set some data once
        view_model.conversation = model.conversation;
        view_model.avatar = new ViewModel.CompatAvatarPictureModel(stream_interactor).set_conversation(model.conversation);
        view_model.show_blocked = model.conversation.type_ == Conversation.Type.CHAT && stream_interactor.get_module(BlockingManager.IDENTITY).is_supported(model.conversation.account);
        view_model.members_sorted.set_model(model.members);
        view_model.members.set_map_func((item) => {
            var conference_member = (Ui.Model.ConferenceMember) item;
            Jid? nick_jid = stream_interactor.get_module(MucManager.IDENTITY).get_occupant_jid(model.conversation.account, model.conversation.counterpart, conference_member.jid);
            return new Ui.ViewModel.ConferenceMemberListRow() {
                avatar = new ViewModel.CompatAvatarPictureModel(stream_interactor).add_participant(model.conversation, conference_member.jid),
                name = nick_jid != null ? nick_jid.resourcepart : conference_member.jid.localpart,
                jid = conference_member.jid.to_string(),
                affiliation = conference_member.affiliation
            };
        });
        view_model.account_jid = stream_interactor.get_accounts().size > 1 ? model.conversation.account.bare_jid.to_string() : null;

        if (model.domain_blocked) {
            view_model.blocked = DOMAIN;
        } else if (model.blocked) {
            view_model.blocked = USER;
        } else {
            view_model.blocked = UNBLOCK;
        }

        // Bind properties
        model.display_name.bind_property("display-name", view_model, "name", BindingFlags.SYNC_CREATE);
        model.conversation.bind_property("notify-setting", view_model, "notification", BindingFlags.SYNC_CREATE, (_, from, ref to) => {
            switch (model.conversation.get_notification_setting(stream_interactor)) {
                case ON:
                    to = ViewModel.ConversationDetails.NotificationSetting.ON;
                    break;
                case OFF:
                    to = ViewModel.ConversationDetails.NotificationSetting.OFF;
                    break;
                case HIGHLIGHT:
                    to = ViewModel.ConversationDetails.NotificationSetting.HIGHLIGHT;
                    break;
                case DEFAULT:
                    // A "default" setting should have been resolved to the actual default value
                    assert_not_reached();
            }
            return true;
        });
        model.conversation.bind_property("notify-setting", view_model, "notification-is-default", BindingFlags.SYNC_CREATE, (_, from, ref to) => {
            var notify_setting = (Conversation.NotifySetting) from;
            to = notify_setting == Conversation.NotifySetting.DEFAULT;
            return true;
        });
        model.conversation.bind_property("pinned", view_model, "pinned", BindingFlags.SYNC_CREATE, (_, from, ref to) => {
            var from_int = (int) from;
            to = from_int > 0;
            return true;
        });
        model.conversation.bind_property("type-", view_model, "notification-options", BindingFlags.SYNC_CREATE, (_, from, ref to) => {
            var ty = (Conversation.Type) from;
            to = ty == Conversation.Type.GROUPCHAT ? ViewModel.ConversationDetails.NotificationOptions.ON_HIGHLIGHT_OFF : ViewModel.ConversationDetails.NotificationOptions.ON_OFF;
            return true;
        });
        model.bind_property("data-form", view_model, "room-configuration-rows", BindingFlags.SYNC_CREATE, (_, from, ref to) => {
            var data_form = (DataForms.DataForm) from;
            if (data_form == null) return true;
            var list_store = new GLib.ListStore(typeof(ViewModel.PreferencesRow.Any));

            foreach (var field in data_form.fields) {
                var field_view_model = Util.get_data_form_field_view_model(field);
                if (field_view_model != null) {
                    list_store.append(field_view_model);
                }
            }

            to = list_store;
            return true;
        });

        view_model.pin_changed.connect(() => {
            model.conversation.pinned = model.conversation.pinned == 1 ? 0 : 1;
        });
        view_model.block_changed.connect((view_model, action) => {
            switch (action) {
                case USER:
                    stream_interactor.get_module(BlockingManager.IDENTITY).block(model.conversation.account, model.conversation.counterpart);
                    stream_interactor.get_module(BlockingManager.IDENTITY).unblock(model.conversation.account, model.conversation.counterpart.domain_jid);
                    break;
                case DOMAIN:
                    stream_interactor.get_module(BlockingManager.IDENTITY).block(model.conversation.account, model.conversation.counterpart.domain_jid);
                    break;
                case UNBLOCK:
                    stream_interactor.get_module(BlockingManager.IDENTITY).unblock(model.conversation.account, model.conversation.counterpart);
                    stream_interactor.get_module(BlockingManager.IDENTITY).unblock(model.conversation.account, model.conversation.counterpart.domain_jid);
                    break;
            }
            view_model.blocked = action;
        });
        view_model.notification_changed.connect((setting) => {
            switch (setting) {
                case ON:
                    model.conversation.notify_setting = ON;
                    break;
                case OFF:
                    model.conversation.notify_setting = OFF;
                    break;
                case HIGHLIGHT:
                    model.conversation.notify_setting = HIGHLIGHT;
                    break;
                case DEFAULT:
                    model.conversation.notify_setting = DEFAULT;
                    break;
            }
        });

        view_model.notification_flipped.connect((view_model) => {
            model.conversation.notify_setting = view_model.notification == ON ? Conversation.NotifySetting.OFF : Conversation.NotifySetting.ON;
        });
    }

    private static string format_utc_offset_minutes(int utc_offset_minutes) {
        var datetime = new DateTime.now(new TimeZone.offset(utc_offset_minutes * 60));
        return datetime.format(Util.is_24h_format() ?
                /* xgettext:no-c-format */ /* Weekday and time in 24h format (w/o seconds) */ _("%A, %H∶%M") :
                /* xgettext:no-c-format */ /* Weekday and time in 12h format (w/o seconds) */ _("%A, %l∶%M %p"));
    }

    private uint get_interval_till_next_full_minute() {
        return 60000 - (int) (new DateTime.now_utc().get_seconds()*1000d);
    }

    private static void notify_binding_once(Binding binding) {
        binding.source.notify_property(binding.source_property);
    }

    private void add_group_management_rows(ViewModel.ConversationDetails view_model, Conversation conversation, StreamInteractor stream_interactor) {
        add_group_privacy_row(view_model, conversation, stream_interactor);

        var muc_manager = stream_interactor.get_module(MucManager.IDENTITY);
        Jid? own_jid = muc_manager.get_own_jid(conversation.counterpart, conversation.account);
        if (own_jid != null) {
            Xmpp.Xep.Muc.Affiliation own_affiliation = muc_manager.get_affiliation(conversation.counterpart, own_jid, conversation.account) ?? Xmpp.Xep.Muc.Affiliation.NONE;
            if (own_affiliation == Xmpp.Xep.Muc.Affiliation.ADMIN || own_affiliation == Xmpp.Xep.Muc.Affiliation.OWNER) {
                invite_to_room(view_model, conversation, stream_interactor);
            }
        }
    }

    private void invite_to_room(ViewModel.ConversationDetails view_model, Conversation conversation, StreamInteractor stream_interactor) {
        var invite_row = new ViewModel.PreferencesRow.Button() {
            title = _("Invitations"),
            subtitle = stream_interactor.get_module(MucManager.IDENTITY).is_private_room(conversation.account, conversation.counterpart) ?
                    _("Grant membership and invite a contact") :
                    _("Invite a contact into this room"),
            button_text = _("Invite")
        };
        invite_row.clicked.connect(() => {
            select_contact_and_invite(view_model, conversation, stream_interactor);
        });
        view_model.settings_rows.append(invite_row);
    }

    private void select_contact_and_invite(ViewModel.ConversationDetails view_model, Conversation conversation, StreamInteractor stream_interactor) {
        Gee.List<Account> acc_list = new ArrayList<Account>(Account.equals_func);
        acc_list.add(conversation.account);
        SelectContactDialog dialog = new SelectContactDialog(stream_interactor, acc_list);
        dialog.set_transient_for((Window) ((GLib.Application.get_default()) as Application).active_window);
        dialog.title = _("Invite to Conference");
        dialog.ok_button.label = _("Invite");
        dialog.selected.connect( (account, jid) => {
            send_invite.begin(conversation, stream_interactor, jid);
        });
        dialog.present();
    }

    private async void send_invite(Conversation conversation, StreamInteractor stream_interactor, Jid jid) {
        var muc_manager = stream_interactor.get_module(MucManager.IDENTITY);
        if (muc_manager.is_private_room(conversation.account, conversation.counterpart)) {
            bool success = yield muc_manager.yield_change_affiliation_for_jid(conversation.account, conversation.counterpart, jid, "member");
            if (!success) {
                show_group_error(_("Could not invite contact"), _("Dino could not grant membership for %s in this private channel.").printf(jid.to_string()));
                return;
            }
            Application? app = GLib.Application.get_default() as Application;
            if (app != null && app.plugin_registry.x3dhpq_group_manager != null) {
                if (!(yield app.plugin_registry.x3dhpq_group_manager.add_private_group_member(conversation.account, conversation.counterpart, jid))) {
                    show_group_error(_("Could not invite contact"), _("Dino could not publish x3dhpq membership data for %s in this private channel.").printf(jid.to_string()));
                    return;
                }
            }
        }
        muc_manager.invite(conversation.account, conversation.counterpart, jid);
    }

    private void add_group_privacy_row(ViewModel.ConversationDetails view_model, Conversation conversation, StreamInteractor stream_interactor) {
        var muc_manager = stream_interactor.get_module(MucManager.IDENTITY);
        Jid? own_jid = muc_manager.get_own_jid(conversation.counterpart, conversation.account);
        if (own_jid == null) return;

        Xmpp.Xep.Muc.Affiliation own_affiliation = muc_manager.get_affiliation(conversation.counterpart, own_jid, conversation.account) ?? Xmpp.Xep.Muc.Affiliation.NONE;
        if (own_affiliation != Xmpp.Xep.Muc.Affiliation.OWNER) return;

        bool is_private = muc_manager.is_private_room(conversation.account, conversation.counterpart);
        if (is_private) return;
        var privacy_row = new ViewModel.PreferencesRow.Button() {
            title = _("Channel Type"),
            subtitle = is_private ?
                    _("Private channel: members only, hidden from public listings") :
                    _("Public channel: discoverable and open to non-members"),
            button_text = is_private ? _("Make Public") : _("Make Private")
        };
        privacy_row.clicked.connect(() => {
            update_room_privacy.begin(view_model, conversation, stream_interactor, !is_private);
        });
        view_model.settings_rows.append(privacy_row);
    }

    private async void update_room_privacy(ViewModel.ConversationDetails view_model, Conversation conversation, StreamInteractor stream_interactor, bool private_room) {
        Xep.DataForms.DataForm? data_form = yield stream_interactor.get_module(MucManager.IDENTITY).get_config_form(conversation.account, conversation.counterpart);
        if (data_form == null) return;

        foreach (Xep.DataForms.DataForm.Field field in data_form.fields) {
            switch (field.var) {
                case "muc#roomconfig_publicroom":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = !private_room;
                    }
                    break;
                case "muc#roomconfig_membersonly":
                    if (field.type_ == Xep.DataForms.DataForm.Type.BOOLEAN) {
                        ((Xep.DataForms.DataForm.BooleanField) field).value = private_room;
                    }
                    break;
                case "muc#roomconfig_whois":
                    if (field.type_ == Xep.DataForms.DataForm.Type.LIST_SINGLE) {
                        ((Xep.DataForms.DataForm.ListSingleField) field).value = private_room ? "anyone" : "moderators";
                    }
                    break;
            }
        }

        yield stream_interactor.get_module(MucManager.IDENTITY).set_config_form(conversation.account, conversation.counterpart, data_form);

        if (private_room) {
            conversation.encryption = Encryption.X3DHPQ;
            Application? app = GLib.Application.get_default() as Application;
            if (app != null && app.plugin_registry.x3dhpq_group_manager != null) {
                if (!(yield app.plugin_registry.x3dhpq_group_manager.ensure_private_group_bootstrapped(conversation.account, conversation.counterpart))) {
                    show_group_error(_("Could not make channel private"), _("Dino could not create the x3dhpq membership journal for this channel."));
                }
            }
        }

        refresh_group_rows(view_model, conversation, stream_interactor);
    }

    private void refresh_group_rows(ViewModel.ConversationDetails view_model, Conversation conversation, StreamInteractor stream_interactor) {
        while (view_model.settings_rows.get_n_items() > 0) {
            view_model.settings_rows.remove(view_model.settings_rows.get_n_items() - 1);
        }
        add_group_management_rows(view_model, conversation, stream_interactor);
    }

    private void show_group_error(string title, string body) {
        Window? window = (GLib.Application.get_default() as Application).active_window;
        if (window == null) {
            warning("%s: %s", title, body);
            return;
        }
        var dialog = new Adw.AlertDialog(title, body);
        dialog.add_response("close", _("Close"));
        dialog.set_default_response("close");
        dialog.set_close_response("close");
        dialog.present(window);
    }

    private void add_forget_contact_row(Dialog dialog, Conversation conversation, StreamInteractor stream_interactor) {
        if (conversation.type_ != Conversation.Type.CHAT && conversation.type_ != Conversation.Type.GROUPCHAT_PM) {
            return;
        }

        var forget_row = new ViewModel.PreferencesRow.Button() {
            title = _("Forget contact"),
            subtitle = _("Remove local messages, metadata, and encryption state for this JID"),
            button_text = _("Forget")
        };
        forget_row.clicked.connect(() => {
            var confirm = new Adw.AlertDialog(
                _("Forget this contact?"),
                _("This removes Dino's local history and cached encryption state for %s.")
                    .printf(conversation.counterpart.bare_jid.to_string())
            );
            confirm.add_response("cancel", _("Cancel"));
            confirm.add_response("forget", _("Forget"));
            confirm.set_response_appearance("forget", Adw.ResponseAppearance.DESTRUCTIVE);
            confirm.set_default_response("cancel");
            confirm.set_close_response("cancel");
            confirm.choose.begin(dialog, null, (obj, res) => {
                if (confirm.choose.end(res) == "forget") {
                    stream_interactor.get_module(ConversationManager.IDENTITY).forget_contact(conversation);
                    dialog.close();
                }
            });
        });
        dialog.model.settings_rows.append(forget_row);
    }

    public void set_about_rows(Model.ConversationDetails model, ViewModel.ConversationDetails view_model, StreamInteractor stream_interactor) {
        Conversation conversation = model.conversation;
        view_model.about_rows.append(new ViewModel.PreferencesRow.Text() {
            title = _("XMPP Address"),
            text = conversation.counterpart.to_string()
        });
        if (conversation.type_ == Conversation.Type.CHAT) {
            var display_name = model.display_name;
            var about_row = new ViewModel.PreferencesRow.Entry() {
                title = _("Display name"),
                text = display_name.display_name
            };
            about_row.changed.connect((about_row) => {
                if (about_row.text != display_name.display_name) {
                    stream_interactor.get_module(RosterManager.IDENTITY).set_jid_handle(conversation.account, conversation.counterpart, about_row.text);
                }
            });
            view_model.about_rows.append(about_row);
            var time_row = new ViewModel.PreferencesRow.Text() {
                title = _("Local Time")
            };
            model.bind_property("utc-offset-minutes", time_row, "visible", BindingFlags.SYNC_CREATE, (binding, from, ref to) => {
                int utc_offset_minutes = (int) from;
                to = utc_offset_minutes != int.MIN;
                return true;
            });
            model.bind_property("utc-offset-minutes", time_row, "text", BindingFlags.SYNC_CREATE, (binding, from, ref to) => {
                var interval = get_interval_till_next_full_minute();
                to = format_utc_offset_minutes((int) from);
                WeakTimeout.add_once(interval, binding, notify_binding_once);
                return true;
            });
            view_model.about_rows.append(time_row);
        }
        if (conversation.type_ == Conversation.Type.GROUPCHAT) {
            add_group_management_rows(view_model, conversation, stream_interactor);
            var topic = stream_interactor.get_module(MucManager.IDENTITY).get_groupchat_subject(conversation.counterpart, conversation.account);

            Ui.ViewModel.PreferencesRow.Any preferences_row = null;
            Jid? own_muc_jid = stream_interactor.get_module(MucManager.IDENTITY).get_own_jid(conversation.counterpart, conversation.account);
            if (own_muc_jid != null) {
                Xep.Muc.Role? own_role = stream_interactor.get_module(MucManager.IDENTITY).get_role(own_muc_jid, conversation.account);
                if (own_role != null) {
                    if (own_role == MODERATOR) {
                        var preferences_row_entry = new ViewModel.PreferencesRow.Entry() {
                            title = _("Topic"),
                            text = topic
                        };
                        preferences_row_entry.changed.connect(() => {
                            if (preferences_row_entry.text != topic) {
                                stream_interactor.get_module(MucManager.IDENTITY).change_subject(conversation.account, conversation.counterpart, preferences_row_entry.text);
                            }
                        });
                        preferences_row = preferences_row_entry;
                    }
                }
            }
            if (preferences_row == null && topic != null && topic != "") {
                preferences_row = new ViewModel.PreferencesRow.Text() {
                    title = _("Topic"),
                    text = Util.parse_add_markup(topic, null, true, true)
                };
            }
            if (preferences_row != null) {
                view_model.about_rows.append(preferences_row);
            }
        }
    }

    public Dialog setup_dialog(Conversation conversation, StreamInteractor stream_interactor) {
        var dialog = new Dialog();
        var model = new Model.ConversationDetails();
        model.populate(stream_interactor, conversation);
        bind_dialog(model, dialog.model, stream_interactor);

        set_about_rows(model, dialog.model, stream_interactor);
        add_forget_contact_row(dialog, conversation, stream_interactor);

        dialog.closed.connect(() => {
            // Only send the config form if something was changed
            if (model.data_form_bak != null && model.data_form_bak != model.data_form.stanza_node.to_string()) {
                stream_interactor.get_module(MucManager.IDENTITY).set_config_form.begin(conversation.account, conversation.counterpart, model.data_form);
            }
        });

        Plugins.ContactDetails contact_details = new Plugins.ContactDetails();
        var settings_rows = dialog.model.settings_rows;
        contact_details.add_settings_action_row.connect((entry_row_model) => {
            settings_rows.append((Ui.ViewModel.PreferencesRow.Any) entry_row_model);
        });
        Application app = GLib.Application.get_default() as Application;
        app.plugin_registry.register_contact_details_entry(new ContactDetails.SettingsProvider(stream_interactor));
        app.plugin_registry.register_contact_details_entry(new ContactDetails.PermissionsProvider(stream_interactor));

        foreach (Plugins.ContactDetailsProvider provider in app.plugin_registry.contact_details_entries) {
            var preferences_group = (Adw.PreferencesGroup) provider.get_widget(conversation);
            if (preferences_group != null) {
                dialog.add_encryption_tab_element((Adw.PreferencesGroup) provider.get_widget(conversation));
            }
            provider.populate(conversation, contact_details, Plugins.WidgetType.GTK4);
        }

        return dialog;
    }
}
