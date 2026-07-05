using Gee;
using Gtk;
using Qlite;
using Dino.Entities;

namespace Dino.Plugins.X3dhpq.UI {

public class SelfDevicesWidget : Gtk.Box {
    public signal void add_device_requested();

    private Database db;
    private Account account;

    private Gtk.Label fingerprint_label;
    private Gtk.Label local_device_label;
    private Gtk.Label devices_header_label;
    private Gtk.ListBox devices_listbox;

    public SelfDevicesWidget(Database db, Account account) {
        Object(orientation: Gtk.Orientation.VERTICAL, spacing: 6);
        this.db = db;
        this.account = account;

        var fp_header = new Gtk.Label("Account fingerprint") {
            halign = Gtk.Align.START,
            margin_start = 6,
            margin_top = 6
        };
        fp_header.add_css_class("heading");
        append(fp_header);

        fingerprint_label = new Gtk.Label("") {
            halign = Gtk.Align.START,
            selectable = true,
            wrap = true,
            margin_start = 6
        };
        fingerprint_label.add_css_class("monospace");
        append(fingerprint_label);

        local_device_label = new Gtk.Label("") {
            halign = Gtk.Align.START,
            margin_start = 6
        };
        append(local_device_label);

        append(new Gtk.Separator(Gtk.Orientation.HORIZONTAL) { margin_top = 6, margin_bottom = 6 });

        devices_header_label = new Gtk.Label("") {
            halign = Gtk.Align.START,
            margin_start = 6
        };
        devices_header_label.add_css_class("heading");
        append(devices_header_label);

        devices_listbox = new Gtk.ListBox() {
            selection_mode = Gtk.SelectionMode.NONE,
            margin_start = 6,
            margin_end = 6
        };
        devices_listbox.add_css_class("boxed-list");
        append(devices_listbox);

        var add_button = new Gtk.Button.with_label("Add device…") {
            halign = Gtk.Align.START,
            margin_start = 6,
            margin_top = 6,
            margin_bottom = 6
        };
        add_button.clicked.connect(() => add_device_requested());
        append(add_button);

        refresh();
    }

    public void refresh() {
        string fingerprint = db.get_aik_fingerprint(account) ?? "Unavailable";
        fingerprint_label.label = format_fingerprint(fingerprint);

        int? device_id = db.get_local_device_id(account);
        Row? local_row = db.get_local_identity(account.id);
        bool is_primary = local_row != null && ((!) local_row)[db.account_identity.is_primary];
        string device_id_str = device_id != null ? ((uint32) ((!) device_id)).to_string() : "Unavailable";
        if (is_primary) {
            local_device_label.label = @"This device: $device_id_str (primary)";
        } else {
            local_device_label.label = @"This device: $device_id_str";
        }

        // Remove all existing rows from the listbox
        Gtk.Widget? child = devices_listbox.get_first_child();
        while (child != null) {
            Gtk.Widget next = ((!) child).get_next_sibling();
            devices_listbox.remove((!) child);
            child = next;
        }

        string own_jid = account.bare_jid.to_string();
        Gee.List<int> device_ids = db.get_remote_device_ids(account, own_jid);

        devices_header_label.label = @"Authorised devices ($(device_ids.size))";

        if (device_ids.is_empty) {
            var placeholder_row = new Adw.ActionRow() {
                title = "Devices will appear after first sync"
            };
            devices_listbox.append(placeholder_row);
            return;
        }

        foreach (int did in device_ids) {
            devices_listbox.append(build_device_row(did));
        }
    }

    private Gtk.Widget build_device_row(int device_id) {
        string own_jid = account.bare_jid.to_string();
        Row? peer_row = db.peer_device.select()
            .with(db.peer_device.account_id, "=", account.id)
            .with(db.peer_device.bare_jid, "=", own_jid)
            .with(db.peer_device.device_id, "=", device_id)
            .single().row().inner;

        string created_str = "";
        if (peer_row != null) {
            long ts = ((!) peer_row)[db.peer_device.created_at];
            var dt = new DateTime.from_unix_utc(ts);
            created_str = dt.format("%Y-%m-%d");
        }

        int? local_id = db.get_local_device_id(account);
        bool this_device = local_id != null && ((!) local_id) == device_id;
        string label_text = ((uint32) device_id).to_string();
        if (this_device) {
            label_text += " · primary";
        }
        if (created_str != "") {
            label_text += @" · created $created_str";
        }

        var row = new Adw.ActionRow() { title = label_text };

        // The local device is excluded from removal — the user cannot revoke
        // their own currently-bound device from this UI.
        var remove_button = new Gtk.Button.with_label("Remove") {
            valign = Gtk.Align.CENTER,
            sensitive = !this_device
        };
        remove_button.add_css_class("destructive-action");
        if (!this_device) {
            int captured_id = device_id;
            remove_button.clicked.connect(() => {
                confirm_and_remove(captured_id);
            });
        } else {
            remove_button.tooltip_text = "Cannot remove the device you are currently using";
        }
        row.add_suffix(remove_button);

        return row;
    }

    private void confirm_and_remove(int device_id) {
        var dialog = new Adw.AlertDialog(
            "Remove device %s?".printf(((uint32) device_id).to_string()),
            "The device will be revoked: a signed RemoveDevice record is published to your account's audit chain and the local session, bundle and pre-key state for it are torn down. Contacts drop it when they see it disappear from a signed, version-advanced devicelist."
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("remove", "Remove");
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE);
        dialog.default_response = "cancel";
        dialog.close_response = "cancel";
        dialog.response.connect((id) => {
            if (id == "remove") {
                Plugin.manager.remove_own_device.begin(account, (uint32) device_id, (obj, res) => {
                    Plugin.manager.remove_own_device.end(res);
                    refresh();
                });
            }
        });
        dialog.present(this);
    }

    private static string format_fingerprint(string raw) {
        // Break into 5-char groups separated by spaces
        var sb = new StringBuilder();
        int i = 0;
        unichar c;
        while (raw.get_next_char(ref i, out c)) {
            if (i > 1 && (i - 1) % 5 == 0) {
                sb.append_c(' ');
            }
            sb.append_unichar(c);
        }
        return sb.str;
    }
}

}
