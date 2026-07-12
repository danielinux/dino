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
    public signal void confirm_device_requested();

    private Database db;
    private Account account;

    private Gtk.Label fingerprint_label;
    private Gtk.Label local_device_label;
    private Gtk.Label devices_header_label;
    private Gtk.ListBox devices_listbox;
    private Gtk.Button confirm_button;

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

        // §10.6.2 pairing uses a single direction (the new device presents its
        // own code/QR; this existing device enters it): "Confirm a device"
        // (PairNewDeviceDialog in confirm_mode). The opposite direction (this
        // device presenting a code for a newcomer to enter) is intentionally not
        // offered — one tested flow keeps the UI unambiguous.
        var button_box = new Gtk.Box(Gtk.Orientation.HORIZONTAL, 6) {
            halign = Gtk.Align.START,
            margin_start = 6,
            margin_top = 6,
            margin_bottom = 6
        };
        confirm_button = new Gtk.Button.with_label("Confirm a device…");
        confirm_button.clicked.connect(() => confirm_device_requested());
        button_box.append(confirm_button);
        append(button_box);

        refresh();
    }

    // §11.8 queued enrollment request: surfaces the most recently seen,
    // persisted <enroll-request> item (StreamModule.handle_enroll_request_node
    // / db.store_pending_enrollment_request) so a human opening this page sees
    // "device X wants to join" and can act on it via the existing "Confirm a
    // device" flow, even if the request arrived while nobody had a pairing
    // dialog open to catch the live +notify.
    private Gtk.Widget build_pending_enrollment_request_row(Row req) {
        uint32 device_id = (uint32) req[db.pending_enrollment_request.device_id];
        var row = new Adw.ActionRow() {
            title = @"Device $device_id wants to join this account",
            subtitle = "Received via this account's pairing rendezvous. Use “Confirm a device…” " +
                "below and complete the manual code/QR handshake to admit it."
        };
        row.add_css_class("warning");
        var confirm_button = new Gtk.Button.with_label("Review") {
            valign = Gtk.Align.CENTER
        };
        confirm_button.add_css_class("suggested-action");
        confirm_button.clicked.connect(() => confirm_device_requested());
        row.add_suffix(confirm_button);
        return row;
    }

    public void refresh() {
        fingerprint_label.label = db.get_aik_fingerprint(account) ?? "Unavailable";

        int? device_id = db.get_local_device_id(account);
        Row? local_row = db.get_local_identity(account.id);
        bool is_primary = local_row != null && ((!) local_row)[db.account_identity.is_primary];
        string device_id_str = device_id != null ? ((uint32) ((!) device_id)).to_string() : "Unavailable";
        // §10.6.6: "authorized" is what actually matters for management/send
        // decisions (any authorized device — primary or secondary — is an
        // equal manager); Primary/Secondary is shown only as an informational
        // label for an already-authorized device. A disabled device (never
        // confirmed, or revoked) is called out distinctly regardless.
        bool authorized = db.is_authorized(account);
        string status_str = authorized
            ? (is_primary ? "Primary" : "Secondary")
            : "Disabled — waiting for sync";
        local_device_label.label = @"This device: $device_id_str ($status_str)";

        // §10.6.6: a disabled device holds no AIK_priv and cannot sign the
        // AddDevice entry confirming a newcomer requires — grey the button out
        // with an explanatory tooltip instead of letting the human hit a silent
        // failure after completing a pairing handshake.
        confirm_button.sensitive = authorized;
        confirm_button.tooltip_text = authorized ? "" :
            "This device is disabled (waiting for sync) and cannot confirm other devices yet.";

        // Remove all existing rows from the listbox
        Gtk.Widget? child = devices_listbox.get_first_child();
        while (child != null) {
            Gtk.Widget next = ((!) child).get_next_sibling();
            devices_listbox.remove((!) child);
            child = next;
        }

        Row? pending_request = db.get_pending_enrollment_request_row(account);
        if (pending_request != null) {
            devices_listbox.append(build_pending_enrollment_request_row((!) pending_request));
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

        // §10.6.6: any AUTHORIZED device can revoke another device from here,
        // including a pending/unconfirmed one (in fact that's the primary way
        // to kick out a rogue addition) — except the device the user is
        // currently using. A disabled (not-yet-authorized) local device holds
        // no AIK_priv and cannot sign a RemoveDevice entry at all.
        bool can_revoke = !this_device && db.is_authorized(account);
        var revoke_button = new Gtk.Button.with_label("Revoke") {
            valign = Gtk.Align.CENTER,
            sensitive = can_revoke
        };
        revoke_button.add_css_class("destructive-action");
        if (can_revoke) {
            int captured_id = device_id;
            revoke_button.clicked.connect(() => {
                confirm_and_remove(captured_id);
            });
        } else if (this_device) {
            revoke_button.tooltip_text = "Cannot revoke the device you are currently using";
        } else {
            revoke_button.tooltip_text = "This device is disabled (waiting for sync) and cannot revoke other devices yet.";
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
