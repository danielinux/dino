using Gee;
using Gtk;

using Dino.Entities;
using Xmpp;
using Xmpp.Xep;

namespace Dino.Ui {

public class AddConferenceDialog : Gtk.Dialog {

    private Stack stack = new Stack();
    private Button cancel_button = new Button();
    private Button ok_button;

    private SelectJidFragment select_fragment;
    private ConferenceDetailsFragment details_fragment;
    private ConferenceList conference_list;
    private ListBox conference_list_box;

    private StreamInteractor stream_interactor;
    private ulong cancel_clicked_handler_id = 0;
    private ulong ok_clicked_handler_id = 0;
    private ulong select_done_handler_id = 0;
    private ulong details_done_handler_id = 0;

    public AddConferenceDialog(StreamInteractor stream_interactor) {
        Object(use_header_bar : 1);
        this.title = _("Join Channel");
        this.modal = true;
        this.default_width = 460;
        this.default_height = 550;
        this.stream_interactor = stream_interactor;

        setup_headerbar();
        stack.visible = true;
        stack.vhomogeneous = false;
        Box? content_area = get_content_area() as Box;
        if (content_area != null) {
            content_area.append(stack);
        }
        setup_jid_add_view();
        setup_conference_details_view();
        show_jid_add_view();
    }

    private void show_jid_add_view() {
        cancel_button.set_label(_("Cancel"));
        disconnect_cancel_clicked_handler();
        cancel_clicked_handler_id = cancel_button.clicked.connect(() => on_cancel());
        ok_button.label = _("Next");
        ok_button.sensitive = select_fragment.done;
        disconnect_ok_clicked_handler();
        ok_clicked_handler_id = ok_button.clicked.connect(() => on_next_button_clicked());
        details_fragment.fragment_active = false;
        set_details_done_handler(false);
        set_select_done_handler(true);

        stack.transition_type = StackTransitionType.SLIDE_RIGHT;
        stack.set_visible_child_name("select");
    }

    private void show_conference_details_view() {
        cancel_button.set_icon_name("dino-go-previous-symbolic");
        disconnect_cancel_clicked_handler();
        cancel_clicked_handler_id = cancel_button.clicked.connect(() => show_jid_add_view());
        ok_button.label = _("Join");
        ok_button.sensitive = details_fragment.done;
        disconnect_ok_clicked_handler();
        details_fragment.fragment_active = true;
        set_select_done_handler(false);
        set_details_done_handler(true);

        stack.transition_type = StackTransitionType.SLIDE_LEFT;
        stack.set_visible_child_name("details");
        animate_window_resize(details_fragment);
    }

    private void disconnect_cancel_clicked_handler() {
        if (cancel_clicked_handler_id != 0) {
            cancel_button.disconnect(cancel_clicked_handler_id);
            cancel_clicked_handler_id = 0;
        }
    }

    private void disconnect_ok_clicked_handler() {
        if (ok_clicked_handler_id != 0) {
            ok_button.disconnect(ok_clicked_handler_id);
            ok_clicked_handler_id = 0;
        }
    }

    private void set_select_done_handler(bool enabled) {
        if (select_done_handler_id != 0) {
            select_fragment.disconnect(select_done_handler_id);
            select_done_handler_id = 0;
        }
        if (enabled) {
            select_done_handler_id = select_fragment.notify["done"].connect(set_ok_sensitive_from_select);
        }
    }

    private void set_details_done_handler(bool enabled) {
        if (details_done_handler_id != 0) {
            details_fragment.disconnect(details_done_handler_id);
            details_done_handler_id = 0;
        }
        if (enabled) {
            details_done_handler_id = details_fragment.notify["done"].connect(set_ok_sensitive_from_details);
        }
    }

    private void setup_headerbar() {
        ok_button = new Button() { can_focus=true };
        ok_button.add_css_class("suggested-action");

        HeaderBar header_bar = new HeaderBar();
        header_bar.show_title_buttons = false;
        set_titlebar(header_bar);

        header_bar.pack_start(cancel_button);
        header_bar.pack_end(ok_button);
    }

    private void setup_jid_add_view() {
        conference_list = new ConferenceList(stream_interactor);
        conference_list_box = conference_list.get_list_box();
        conference_list_box.row_activated.connect(() => { ok_button.clicked(); });

        select_fragment = new SelectJidFragment(stream_interactor, conference_list_box, stream_interactor.get_accounts());
        select_fragment.add_jid.connect(() => {
            AddGroupchatDialog dialog = new AddGroupchatDialog(stream_interactor, _("New Private Channel"), true);
            dialog.set_transient_for(this);
            dialog.present();
        });
        select_fragment.remove_jid.connect((row) => {
            ConferenceListRow conference_row = row as ConferenceListRow;
            if (conference_row == null) return;
            stream_interactor.get_module(MucManager.IDENTITY).remove_bookmark(conference_row.account, conference_row.bookmark);
        });

        Box wrap_box = new Box(Orientation.VERTICAL, 0);
        wrap_box.append(select_fragment);
        stack.add_named(wrap_box, "select");
    }

    private void setup_conference_details_view() {
        details_fragment = new ConferenceDetailsFragment(stream_interactor) { ok_button=ok_button };
        details_fragment.joined.connect(() => this.close());

        Box wrap_box = new Box(Orientation.VERTICAL, 0);
        wrap_box.append(details_fragment);

        stack.add_named(wrap_box, "details");
    }

    private void set_ok_sensitive_from_select() {
        ok_button.sensitive = select_fragment.done;
    }

    private void set_ok_sensitive_from_details() {
        ok_button.sensitive = details_fragment.done;
    }

    private void on_next_button_clicked() {
        details_fragment.clear();

        ListBoxRow? selected = conference_list_box.get_selected_row();
        if (selected == null || selected.get_child() == null) return;

        ListRow? row = selected.get_child() as ListRow;
        ConferenceListRow? conference_row = selected.get_child() as ConferenceListRow;
        if (conference_row != null) {
            details_fragment.account = conference_row.account;
            details_fragment.jid = conference_row.bookmark.jid.to_string();
            details_fragment.nick = conference_row.bookmark.nick;
            if (conference_row.bookmark.password != null) details_fragment.password = conference_row.bookmark.password;
            ok_button.grab_focus();
        } else if (row != null) {
            details_fragment.account = row.account;
            details_fragment.jid = row.jid.to_string();
        } else {
            return;
        }
        show_conference_details_view();
    }

    private void on_cancel() {
        close();
    }

    private void animate_window_resize(Widget widget) {
        int curr_height = get_size(Orientation.VERTICAL);
        var natural_size = Requisition();
        widget.get_preferred_size(null, out natural_size);
        int difference = natural_size.height - curr_height;
        Timer timer = new Timer();
        Timeout.add((int) (stack.transition_duration / 30), () => {
            ulong microsec;
            timer.elapsed(out microsec);
            ulong millisec = microsec / 1000;
            double partial = double.min(1, (double) millisec / stack.transition_duration);
            default_height = (int) (curr_height + difference * partial);
            return millisec < stack.transition_duration;
        });
    }
}

}
