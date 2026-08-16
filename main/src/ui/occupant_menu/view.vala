using Gee;
using Gtk;

using Dino.Entities;
using Xmpp;

namespace Dino.Ui.OccupantMenu {
public class View : Popover {

    private StreamInteractor stream_interactor;
    private Conversation conversation;

    private Stack stack = new Stack() { vhomogeneous=false };
    private Box list_box = new Box(Orientation.VERTICAL, 1);
    private List? list = null;
    private ListBox? invite_list = null;
    private Box? jid_menu = null;

    private Jid? selected_jid;

    construct {
        check_widget_leak(this);
    }

    public View(StreamInteractor stream_interactor, Conversation conversation) {
        this.stream_interactor = stream_interactor;
        this.conversation = conversation;

        this.show.connect(initialize_list);

        stack.add_named(list_box, "list");
        set_child(stack);
        stack.visible_child_name = "list";

        hide.connect(reset);
    }

    public void reset() {
        stack.transition_type = StackTransitionType.NONE;
        stack.visible_child_name = "list";
        if (list != null) list.list_box.unselect_all();
        if (invite_list != null) invite_list.unselect_all();
    }

    private void initialize_list() {
        if (list == null) {
            list = new List(stream_interactor, conversation);
            list_box.prepend(list);

            list.list_box.row_activated.connect((row) => {
                ListRow row_wrapper = list.row_wrappers[row.get_child()];
                show_menu(row_wrapper.jid, row_wrapper.name_label.label);
            });
        }
    }

    private void show_list() {
        if (list != null) list.list_box.unselect_all();
        stack.transition_type = StackTransitionType.SLIDE_RIGHT;
        stack.visible_child_name = "list";
    }

    private void show_menu(Jid jid, string name_) {
        selected_jid = jid;
        stack.transition_type = StackTransitionType.SLIDE_LEFT;

        string name = Markup.escape_text(name_);
        Jid? real_jid = stream_interactor.get_module(MucManager.IDENTITY).get_real_jid(jid, conversation.account);
        if (real_jid != null) name += "\n<span font=\'8\'>%s</span>".printf(Markup.escape_text(real_jid.bare_jid.to_string()));

        Box header_box = new Box(Orientation.HORIZONTAL, 5);
        header_box.append(new Image.from_icon_name("pan-start-symbolic"));
        header_box.append(new Label(name) { xalign=0, use_markup=true, hexpand=true });
        Button header_button = new Button() { has_frame=false };
        header_button.child = header_box;

        Box outer_box = new Box(Orientation.VERTICAL, 5);
        outer_box.append(header_button);
        header_button.clicked.connect(show_list);

        Button private_button = new Button.with_label(_("Start private conversation")) ;
        outer_box.append(private_button);
        private_button.clicked.connect(private_conversation_button_clicked);

        Jid? own_jid = stream_interactor.get_module(MucManager.IDENTITY).get_own_jid(conversation.counterpart, conversation.account);
        Xmpp.Xep.Muc.Role? role = stream_interactor.get_module(MucManager.IDENTITY).get_role(own_jid, conversation.account);
        Xmpp.Xep.Muc.Affiliation? own_affiliation = own_jid != null ? stream_interactor.get_module(MucManager.IDENTITY).get_affiliation(conversation.counterpart, own_jid, conversation.account) : Xmpp.Xep.Muc.Affiliation.NONE;

        // WS2/3: in a secret post-quantum group the owner OR any journal admin
        // may add/manage members (crypto authority = the folded v2 admin set,
        // queried via local_is_group_admin). Public rooms keep the usual MUC
        // admin-or-owner rule.
        Application? app_pq = GLib.Application.get_default() as Application;
        var pq = (app_pq != null) ? app_pq.plugin_registry.x3dhpq_group_manager : null;
        bool is_pq_group = pq != null && pq.is_secret_pq_group(conversation.account, conversation.counterpart);
        bool pq_local_admin = is_pq_group && pq.local_is_group_admin(conversation.account, conversation.counterpart);
        bool is_private_room = stream_interactor.get_module(MucManager.IDENTITY).is_private_room(conversation.account, conversation.counterpart);
        bool can_invite = (is_private_room || is_pq_group) ?
                ((own_affiliation == Xmpp.Xep.Muc.Affiliation.OWNER) || pq_local_admin) :
                (own_affiliation == Xmpp.Xep.Muc.Affiliation.ADMIN || own_affiliation == Xmpp.Xep.Muc.Affiliation.OWNER);
        if (can_invite && invite_list == null) {
            invite_list = new ListBox();
            invite_list.append(new ListRow.label("+", _("Invite")).get_widget());
            invite_list.can_focus = false;
            invite_list.row_activated.connect((row) => {
                invite_list.unselect_all();
                invite_occupant();
            });
            list_box.append(invite_list);
        }
        if (role ==  Xmpp.Xep.Muc.Role.MODERATOR && stream_interactor.get_module(MucManager.IDENTITY).kick_possible(conversation.account, jid)) {
            Button kick_button = new Button.with_label(_("Kick")) ;
            outer_box.append(kick_button);
            kick_button.clicked.connect(kick_button_clicked);
        }
        bool can_admin_ops = (own_affiliation == Xmpp.Xep.Muc.Affiliation.ADMIN || own_affiliation == Xmpp.Xep.Muc.Affiliation.OWNER) || pq_local_admin;
        if (real_jid != null && can_admin_ops) {
            Button ban_button = new Button.with_label(_("Ban"));
            outer_box.append(ban_button);
            ban_button.clicked.connect(() => {
                stream_interactor.get_module(MucManager.IDENTITY).change_affiliation_for_jid(conversation.account, conversation.counterpart, real_jid, "outcast");
                // Banning must also revoke the member from the x3dhpq membership
                // journal (RemoveMember + ban flag) and rotate the group epoch — a
                // MUC outcast that stays in the crypto member set would still
                // receive future group keys, and a ban (unlike a kick) must block
                // silent re-admission.
                ban_x3dhpq_member.begin(jid);
            });

            // Admin promote/demote. Owner OR (in a v2 PQ group) an existing admin
            // may promote/demote. The MUC affiliation change is a cosmetic mirror;
            // the crypto authority is the signed AddAdmin/RemoveAdmin journal entry.
            bool target_pq_admin = is_pq_group && pq.member_is_group_admin(conversation.account, conversation.counterpart, real_jid);
            Xmpp.Xep.Muc.Affiliation? target_aff = stream_interactor.get_module(MucManager.IDENTITY)
                .get_affiliation(conversation.counterpart, real_jid, conversation.account);
            bool target_is_admin = is_pq_group ? target_pq_admin
                : (target_aff == Xmpp.Xep.Muc.Affiliation.ADMIN || target_aff == Xmpp.Xep.Muc.Affiliation.OWNER);
            bool may_promote = (own_affiliation == Xmpp.Xep.Muc.Affiliation.OWNER) || pq_local_admin;
            if (may_promote && !target_is_admin) {
                Button admin_button = new Button.with_label(_("Make admin"));
                outer_box.append(admin_button);
                admin_button.clicked.connect(() => {
                    stream_interactor.get_module(MucManager.IDENTITY).change_affiliation_for_jid(conversation.account, conversation.counterpart, real_jid, "admin");
                    if (is_pq_group) pq.group_add_admin.begin(conversation.account, conversation.counterpart, real_jid.bare_jid);
                });
            } else if (may_promote && target_is_admin && target_aff != Xmpp.Xep.Muc.Affiliation.OWNER) {
                Button unadmin_button = new Button.with_label(_("Remove admin"));
                outer_box.append(unadmin_button);
                unadmin_button.clicked.connect(() => {
                    stream_interactor.get_module(MucManager.IDENTITY).change_affiliation_for_jid(conversation.account, conversation.counterpart, real_jid, "member");
                    if (is_pq_group) pq.group_remove_admin.begin(conversation.account, conversation.counterpart, real_jid.bare_jid);
                });
            }
        }
        /* §13.5c witnessed retirement. Owner/admin only, deliberately separate from Ban:
         * a retirement says "this identity is dead", not "this person was ejected", so
         * the successor is not later fighting removal-wins re-admission. It retires the
         * old key and nothing else — admitting the successor stays a separate, deliberate
         * act, which is the whole reason a thief who steals a key cannot use this to take
         * their victim's seat. */
        if (real_jid != null && can_admin_ops && is_pq_group && pq_local_admin) {
            Button retire_button = new Button.with_label(_("Retire identity…"));
            outer_box.append(retire_button);
            retire_button.clicked.connect(() => {
                confirm_retire_identity(real_jid);
            });
        }
        if (stream_interactor.get_module(MucManager.IDENTITY).is_moderated_room(conversation.account, conversation.counterpart) && role ==  Xmpp.Xep.Muc.Role.MODERATOR){
            if (stream_interactor.get_module(MucManager.IDENTITY).get_role(selected_jid, conversation.account) ==  Xmpp.Xep.Muc.Role.VISITOR) {
                Button voice_button = new Button.with_label(_("Grant write permission")) ;
                outer_box.append(voice_button);
                voice_button.clicked.connect(() => 
                    voice_button_clicked("participant"));
            } 
            else if (stream_interactor.get_module(MucManager.IDENTITY).get_role(selected_jid, conversation.account) ==  Xmpp.Xep.Muc.Role.PARTICIPANT){
                Button voice_button = new Button.with_label(_("Revoke write permission")) ;
                outer_box.append(voice_button);
                voice_button.clicked.connect(() => 
                    voice_button_clicked("visitor"));
            }
            
        }

        if (jid_menu != null) stack.remove(jid_menu);
        stack.add_named(outer_box, "menu");
        stack.visible_child_name = "menu";
        jid_menu = outer_box;
    }

    private void private_conversation_button_clicked() {
        if (selected_jid == null) return;

        Conversation conversation = stream_interactor.get_module(ConversationManager.IDENTITY).create_conversation(selected_jid, conversation.account, Conversation.Type.GROUPCHAT_PM);
        stream_interactor.get_module(ConversationManager.IDENTITY).start_conversation(conversation);

        Application app = GLib.Application.get_default() as Application;
        app.controller.select_conversation(conversation);
    }

    private void kick_button_clicked() {
        if (selected_jid == null) return;

        Jid occupant = selected_jid;
        stream_interactor.get_module(MucManager.IDENTITY).kick(conversation.account, conversation.counterpart, occupant.resourcepart);
        // For x3dhpq private channels, kicking must also revoke the member from
        // the cryptographic membership journal and rotate the group epoch so
        // the removed device can no longer read future group messages.
        remove_x3dhpq_member.begin(occupant);
    }

    private async void remove_x3dhpq_member(Jid occupant) {
        var muc_manager = stream_interactor.get_module(MucManager.IDENTITY);
        if (!muc_manager.is_private_room(conversation.account, conversation.counterpart)) {
            return;
        }
        Jid? real_jid = muc_manager.get_real_jid(occupant, conversation.account);
        if (real_jid == null) {
            return;
        }
        Application? app = GLib.Application.get_default() as Application;
        if (app == null || app.plugin_registry.x3dhpq_group_manager == null) {
            return;
        }
        yield app.plugin_registry.x3dhpq_group_manager.remove_private_group_member(
            conversation.account, conversation.counterpart, real_jid.bare_jid);
    }

    // Ban variant: RemoveMember with the ban flag so the AIK is not silently
    // re-added (falls back to a plain removal on a still-v1 room).
    private async void ban_x3dhpq_member(Jid occupant) {
        var muc_manager = stream_interactor.get_module(MucManager.IDENTITY);
        Application? app = GLib.Application.get_default() as Application;
        var pq = (app != null) ? app.plugin_registry.x3dhpq_group_manager : null;
        if (pq == null) return;
        if (!muc_manager.is_private_room(conversation.account, conversation.counterpart)
                && !pq.is_secret_pq_group(conversation.account, conversation.counterpart)) {
            return;
        }
        Jid? real_jid = muc_manager.get_real_jid(occupant, conversation.account);
        if (real_jid == null) return;
        yield pq.group_ban_member(conversation.account, conversation.counterpart, real_jid.bare_jid);
    }

    /* §13.5c kind 2. The confirmation text is doing real work: this entry carries no
     * evidence at all, so it is the local user's word that they performed the §12.2
     * out-of-band re-verification, and every other member's client will label it as such.
     * It must therefore never fire as a side effect of some other action. */
    private void confirm_retire_identity(Jid real_jid) {
        Application? app = GLib.Application.get_default() as Application;
        var pq = (app != null) ? app.plugin_registry.x3dhpq_group_manager : null;
        if (pq == null) return;
        var confirm = new Adw.AlertDialog(
            _("Retire this identity?"),
            _("Only do this if %s has told you — out-of-band, in person or on a call — that they reset their client, and you have compared their NEW fingerprint with them.\n\nThis marks their OLD key dead for everyone in the room and rotates the group keys. It does NOT add their new identity: you add that separately, and every member still verifies it for themselves.\n\nOther members will see this as YOUR claim, not as proof.").printf(real_jid.bare_jid.to_string())
        );
        confirm.add_response("cancel", _("Cancel"));
        confirm.add_response("retire", _("Retire identity"));
        confirm.set_default_response("cancel");
        confirm.set_close_response("cancel");
        confirm.choose.begin(this, null, (obj, res) => {
            if (confirm.choose.end(res) != "retire") return;
            pq.group_retire_member_witnessed.begin(conversation.account,
                conversation.counterpart, real_jid.bare_jid);
        });
    }

    private void voice_button_clicked(string role) {
        if (selected_jid == null) return;

        stream_interactor.get_module(MucManager.IDENTITY).change_role(conversation.account, conversation.counterpart, selected_jid.resourcepart, role);
    }

    private void invite_occupant() {
        hide();
        Gee.List<Account> acc_list = new ArrayList<Account>(Account.equals_func);
        acc_list.add(conversation.account);
        SelectContactDialog add_chat_dialog = new SelectContactDialog(stream_interactor, acc_list);
        add_chat_dialog.set_transient_for((Window) get_root());
        add_chat_dialog.title = _("Invite to Conference");
        add_chat_dialog.ok_button.label = _("Invite");
        add_chat_dialog.selected.connect( (account, invitee_jid) => {
            invite_occupant_async(conversation.account, conversation.counterpart, invitee_jid, stream_interactor);
        });
        add_chat_dialog.present();
    }

    private async void invite_occupant_async(Account account, Jid muc_jid, Jid invitee_jid, StreamInteractor stream_interactor) {
        var muc_manager = stream_interactor.get_module(MucManager.IDENTITY);
        Application? app = GLib.Application.get_default() as Application;
        var pq = (app != null) ? app.plugin_registry.x3dhpq_group_manager : null;
        // Enter the members-only invite path for a private room OR a secret PQ
        // group we own (decided from local journal state, not the possibly-stale
        // is_private_room() disco cache) so the invitee is always granted MUC
        // membership and added to the x3dhpq membership journal.
        bool is_pq_group = pq != null && pq.is_secret_pq_group(account, muc_jid);
        if (muc_manager.is_private_room(account, muc_jid) || is_pq_group) {
            // A secret post-quantum group can only include contacts that publish
            // an x3dhpq devicelist; surface a clear message otherwise.
            if (pq != null && !pq.member_has_x3dhpq(account, invitee_jid)) {
                show_invite_error(_("%s isn’t using a post-quantum client, so they can’t join this secret group.").printf(invitee_jid.to_string()));
                return;
            }
            // Membership is controlled exclusively by the x3dhpq journal (the MUC
            // is open/agnostic); no affiliation grant. Add to the journal, then
            // point the invitee at the room.
            if (pq != null) {
                if (!(yield pq.add_private_group_member(account, muc_jid, invitee_jid))) {
                    return;
                }
            }
        }
        muc_manager.invite(account, muc_jid, invitee_jid);
    }

    private void show_invite_error(string body) {
        Window? window = get_root() as Window;
        var dialog = new Adw.AlertDialog(_("Could not invite contact"), body);
        dialog.add_response("close", _("Close"));
        dialog.set_default_response("close");
        dialog.set_close_response("close");
        if (window != null) {
            dialog.present(window);
        } else {
            warning("Could not invite contact: %s", body);
        }
    }
}

}
