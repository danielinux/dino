using Gee;
using Gtk;
using Qlite;
using Dino.Entities;

namespace Dino.Plugins.X3dhpq.UI {

// §10.6: the account's associated-devices list. One row per device known
// under this account's AIK — sourced from the local peer_device rows (keyed by
// our own bare JID). Trust Manifest Phase 2: trust = presence in the account's
// manifest fold, which StreamModule.verify_and_apply_manifest persists as
// active peer_device rows (each carrying the folded DeviceCertificate):
//  - "confirmed"/trusted devices (peer_device.active=true) are present in the
//    current manifest fold (or are this local device).
//  - "not-in-manifest" devices (peer_device.active=false) appear under the
//    account but are NOT in the current fold; surfaced here so the user can
//    confirm or revoke them rather than silently trusting or dropping them.
// (The retired audit-chain "AddDevice record" gate no longer decides trust.)
public class SelfDevicesWidget : Gtk.Box {
    public signal void confirm_device_requested();

    private Database db;
    private Account account;

    private Gtk.Label fingerprint_label;
    private Gtk.Label local_device_label;
    private Gtk.Label devices_header_label;
    private Gtk.ListBox devices_listbox;
    private Gtk.Button confirm_button;

    // device_id → 1-based "Device N" ordinal, recomputed each refresh over the
    // full known device set (this device + confirmed + pending), so the default
    // labels stay stable and shared between the local row and the sibling rows.
    private Gee.HashMap<int, int> device_ordinals = new Gee.HashMap<int, int>();

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

        var local_box = new Gtk.Box(Gtk.Orientation.HORIZONTAL, 6) {
            margin_start = 6,
            margin_end = 6
        };
        local_device_label = new Gtk.Label("") {
            halign = Gtk.Align.START,
            hexpand = true,
            xalign = 0,
            wrap = true
        };
        local_box.append(local_device_label);
        var local_rename_button = new Gtk.Button.with_label("Rename") {
            valign = Gtk.Align.CENTER
        };
        local_rename_button.add_css_class("flat");
        local_rename_button.clicked.connect(() => {
            int? lid = db.get_local_device_id(account);
            if (lid != null) rename_device((int) ((!) lid));
        });
        local_box.append(local_rename_button);
        append(local_box);

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
        recompute_ordinals(device_id);
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
        string local_name = device_id != null ? device_display_name((int) ((!) device_id)) : "This device";
        local_device_label.label = @"$local_name — this device ($device_id_str · $status_str)";

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
        // §8.6: never surface a device we've revoked, even if a stale row lingers.
        Gee.Set<int> revoked = db.get_revoked_device_ids(account);
        var confirmed_ids = new Gee.ArrayList<int>();
        foreach (int did in db.get_remote_device_ids(account, own_jid)) {
            if (!revoked.contains(did)) confirmed_ids.add(did);
        }
        var pending_ids = new Gee.ArrayList<int>();
        foreach (int did in db.get_pending_own_device_ids(account)) {
            if (!revoked.contains(did)) pending_ids.add(did);
        }

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
        var subtitle_parts = new Gee.ArrayList<string>();
        subtitle_parts.add(@"ID $(((uint32) device_id).to_string())");
        subtitle_parts.add(role);
        if (this_device) subtitle_parts.add("this device");
        if (!confirmed) subtitle_parts.add("NOT IN MANIFEST — not trusted yet");

        var row = new Adw.ExpanderRow() {
            title = device_display_name(device_id),
            subtitle = string.joinv(" · ", subtitle_parts.to_array())
        };
        if (!confirmed) {
            row.add_css_class("warning");
        }

        // Local, never-published rename (§10.6 label). Available for every row
        // including this device — the nickname is stored per (account, device_id).
        var rename_button = new Gtk.Button.with_label("Rename") {
            valign = Gtk.Align.CENTER
        };
        rename_button.add_css_class("flat");
        int rename_id = device_id;
        rename_button.clicked.connect(() => rename_device(rename_id));
        row.add_suffix(rename_button);

        // Trust Manifest Phase 2 (task #67): the device fingerprint is derived from
        // the device's DeviceCertificate as carried in the manifest fold (its DIK
        // pubs) — no separate bundle fetch required. Only show a "not known" message
        // when there is genuinely no certificate for this device.
        string? device_fp = db.get_device_fingerprint(account, own_jid, device_id);
        var fp_row = new Adw.ActionRow() {
            title = "Device key fingerprint",
            subtitle = device_fp ?? "Not known (no device certificate yet)"
        };
        fp_row.subtitle_selectable = true;
        row.add_row(fp_row);

        string added_str = created_str != "" ? created_str : "Unknown";
        row.add_row(new Adw.ActionRow() { title = "Added", subtitle = added_str });

        if (!confirmed) {
            // Trust Manifest Phase 2 (task #67): trust = presence in the account's
            // manifest fold (the audit-chain "AddDevice record" gate is retired). A
            // device shown here appears under the account but is NOT in the current
            // fold, so it is not trusted yet — admit it via "Confirm a device…" or
            // revoke it if unrecognized.
            row.add_row(new Adw.ActionRow() {
                title = "Not in the trust manifest",
                subtitle = "This device appears under the account but is not part of the current " +
                    "trust manifest, so it is not trusted yet. Confirm it via “Confirm a device…”, " +
                    "or revoke it if you don't recognize it."
            });
        }

        // Trust Manifest Phase 2 (task #54): any TRUSTED device — one present in
        // the current manifest fold — can revoke another device, not only the
        // AIK_priv holder, because revoke is a DIK-signed REMOVE entry the local
        // device signs with its own DIK. Except the device the user is currently
        // using (hard self-revoke guard). A device not in the fold (disabled/
        // pending/waiting-for-sync) cannot author a valid REMOVE.
        bool can_revoke = !this_device && db.is_local_device_trusted_member(account);
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

    // Assign stable 1-based "Device N" ordinals over the full known device set
    // (this device + confirmed siblings + pending), sorted ascending by id so the
    // default label is deterministic and shared across the local and sibling rows.
    private void recompute_ordinals(int? local_device_id) {
        device_ordinals.clear();
        Gee.Set<int> revoked = db.get_revoked_device_ids(account);
        var ids = new Gee.TreeSet<int>();
        if (local_device_id != null) ids.add((int) ((!) local_device_id));
        string own_jid = account.bare_jid.to_string();
        foreach (int did in db.get_remote_device_ids(account, own_jid)) {
            if (!revoked.contains(did)) ids.add(did);
        }
        foreach (int did in db.get_pending_own_device_ids(account)) {
            if (!revoked.contains(did)) ids.add(did);
        }
        int n = 1;
        foreach (int did in ids) {
            device_ordinals.set(did, n);
            n++;
        }
    }

    // The user's local nickname for a device, or the "Device N" default.
    private string device_display_name(int device_id) {
        string? nick = db.lookup_device_nickname(account, device_id);
        if (nick != null && nick.strip() != "") return (!) nick;
        int ord = device_ordinals.has_key(device_id) ? device_ordinals.get(device_id) : device_id;
        return @"Device $ord";
    }

    private void rename_device(int device_id) {
        string current = db.lookup_device_nickname(account, device_id) ?? "";
        var dialog = new Adw.AlertDialog(
            "Rename device",
            "Set a local nickname for this device. It is stored only on this device and never shared."
        );
        var entry = new Gtk.Entry() {
            text = current,
            placeholder_text = device_display_name(device_id),
            activates_default = true
        };
        dialog.set_extra_child(entry);
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("save", "Save");
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED);
        dialog.default_response = "save";
        dialog.close_response = "cancel";
        dialog.response.connect((id) => {
            if (id == "save") {
                db.store_device_nickname(account, device_id, entry.text);
                refresh();
            }
        });
        dialog.present(this);
    }

    private void confirm_and_remove(int device_id) {
        var dialog = new Adw.AlertDialog(
            "Revoke device %s?".printf(((uint32) device_id).to_string()),
            "The device will be revoked: a DIK-signed REMOVE entry is appended to your account's trust manifest and the local session, bundle and pre-key state for it are torn down. Contacts drop it when they see it leave the version-advanced manifest (and the derived devicelist)."
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
