using Gee;
using Gtk;
using Qlite;
using Dino.Entities;

namespace Dino.Plugins.X3dhpq.UI {

// §10.6: the account's associated-devices list. One row per device known
// under this account's AIK — sourced from the local devicelist (peer_device,
// keyed by our own bare JID) plus the audit-chain trust gate already applied
// by StreamModule.parse_device_list's is_self branch:
//  - "confirmed" devices (peer_device.active=true) are covered by a
//    chain-verified AddDevice entry (or are this local device) — §10.6.3.
//  - "pending" devices (peer_device.active=false) appear in the signed
//    devicelist but have NO verified AddDevice entry yet; surfaced here as a
//    security event rather than silently trusted or silently dropped.
public class SelfDevicesWidget : Gtk.Box {
    public signal void add_device_requested();
    public signal void confirm_device_requested();

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

        var fp_subtitle = new Gtk.Label(
            "Shared by every device on this account. Compare it out-of-band with your other devices."
        ) {
            halign = Gtk.Align.START,
            wrap = true,
            margin_start = 6
        };
        fp_subtitle.add_css_class("dim-label");
        fp_subtitle.add_css_class("caption");
        append(fp_subtitle);

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

        // §10.6.2 entry points: "Add / link a device" (existing device
        // presents a code/QR; a new device scans/enters it — PairNewDeviceDialog)
        // and "Confirm a device" (a pending device presents its own code/QR;
        // this device scans/enters it — PairNewDeviceDialog in confirm_mode).
        var button_box = new Gtk.Box(Gtk.Orientation.HORIZONTAL, 6) {
            halign = Gtk.Align.START,
            margin_start = 6,
            margin_top = 6,
            margin_bottom = 6
        };
        var add_button = new Gtk.Button.with_label("Add / link a device…");
        add_button.clicked.connect(() => add_device_requested());
        button_box.append(add_button);

        var confirm_button = new Gtk.Button.with_label("Confirm a device…");
        confirm_button.clicked.connect(() => confirm_device_requested());
        button_box.append(confirm_button);
        append(button_box);

        refresh();
    }

    public void refresh() {
        fingerprint_label.label = db.get_aik_fingerprint(account) ?? "Unavailable";

        int? device_id = db.get_local_device_id(account);
        Row? local_row = db.get_local_identity(account.id);
        bool is_primary = local_row != null && ((!) local_row)[db.account_identity.is_primary];
        string device_id_str = device_id != null ? ((uint32) ((!) device_id)).to_string() : "Unavailable";
        local_device_label.label = is_primary
            ? @"This device: $device_id_str (Primary)"
            : @"This device: $device_id_str (Secondary)";

        // Remove all existing rows from the listbox
        Gtk.Widget? child = devices_listbox.get_first_child();
        while (child != null) {
            Gtk.Widget next = ((!) child).get_next_sibling();
            devices_listbox.remove((!) child);
            child = next;
        }

        string own_jid = account.bare_jid.to_string();
        Gee.List<int> confirmed_ids = db.get_remote_device_ids(account, own_jid);
        Gee.List<int> pending_ids = db.get_pending_own_device_ids(account);

        int total = confirmed_ids.size + pending_ids.size;
        devices_header_label.label = pending_ids.is_empty
            ? @"Associated devices ($total)"
            : @"Associated devices ($total, $(pending_ids.size) pending confirmation)";

        if (total == 0) {
            var placeholder_row = new Adw.ActionRow() {
                title = "Devices will appear after first sync"
            };
            devices_listbox.append(placeholder_row);
            return;
        }

        foreach (int did in confirmed_ids) {
            devices_listbox.append(build_device_row(did, true));
        }
        foreach (int did in pending_ids) {
            devices_listbox.append(build_device_row(did, false));
        }
    }

    private Gtk.Widget build_device_row(int device_id, bool confirmed) {
        string own_jid = account.bare_jid.to_string();
        Row? peer_row = db.peer_device.select()
            .with(db.peer_device.account_id, "=", account.id)
            .with(db.peer_device.bare_jid, "=", own_jid)
            .with(db.peer_device.device_id, "=", device_id)
            .single().row().inner;

        string created_str = "";
        int flags = 0;
        if (peer_row != null) {
            long ts = ((!) peer_row)[db.peer_device.added_at];
            if (ts <= 0) {
                ts = ((!) peer_row)[db.peer_device.created_at];
            }
            if (ts > 0) {
                var dt = new DateTime.from_unix_utc(ts);
                created_str = dt.format("%Y-%m-%d");
            }
            flags = ((!) peer_row)[db.peer_device.flags];
        }
        bool row_is_primary = (flags & 1) != 0;

        int? local_id = db.get_local_device_id(account);
        bool this_device = local_id != null && ((!) local_id) == device_id;

        string role = row_is_primary ? "Primary" : "Secondary";
        var title_parts = new Gee.ArrayList<string>();
        title_parts.add(@"Device $(((uint32) device_id).to_string())");
        title_parts.add(role);
        if (this_device) title_parts.add("this device");
        if (!confirmed) title_parts.add("PENDING — not yet confirmed");
        string title = string.joinv(" · ", title_parts.to_array());

        var row = new Adw.ExpanderRow() { title = title };
        if (!confirmed) {
            row.add_css_class("warning");
        }

        string? device_fp = db.get_device_fingerprint(account, own_jid, device_id);
        var fp_row = new Adw.ActionRow() {
            title = "Device key fingerprint",
            subtitle = device_fp ?? "Not yet known (bundle not fetched)"
        };
        fp_row.subtitle_selectable = true;
        row.add_row(fp_row);

        string added_str = created_str != "" ? created_str : "Unknown";
        row.add_row(new Adw.ActionRow() { title = "Added", subtitle = added_str });

        if (!confirmed) {
            row.add_row(new Adw.ActionRow() {
                title = "Not yet confirmed",
                subtitle = "This device appears in the signed devicelist but has no verified " +
                    "AddDevice audit-chain record. If you don't recognize it, revoke it — this " +
                    "may be an unauthorized device (§10.6.3)."
            });
        }

        // Any device can be revoked from here, including a pending/unconfirmed
        // one (in fact that's the primary way to kick out a rogue addition) —
        // except the device the user is currently using.
        var revoke_button = new Gtk.Button.with_label("Revoke") {
            valign = Gtk.Align.CENTER,
            sensitive = !this_device
        };
        revoke_button.add_css_class("destructive-action");
        if (!this_device) {
            int captured_id = device_id;
            revoke_button.clicked.connect(() => {
                confirm_and_remove(captured_id);
            });
        } else {
            revoke_button.tooltip_text = "Cannot revoke the device you are currently using";
        }
        row.add_suffix(revoke_button);

        return row;
    }

    private void confirm_and_remove(int device_id) {
        var dialog = new Adw.AlertDialog(
            "Revoke device %s?".printf(((uint32) device_id).to_string()),
            "The device will be revoked: a signed RemoveDevice record is published to your account's audit chain and the local session, bundle and pre-key state for it are torn down. Contacts drop it when they see it disappear from a signed, version-advanced devicelist."
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("remove", "Revoke");
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
}

}
