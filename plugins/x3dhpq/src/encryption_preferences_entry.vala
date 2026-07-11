using Adw;
using Dino.Entities;
using Xmpp;

namespace Dino.Plugins.X3dhpq {

public class X3dhpqPreferencesEntry : Plugins.EncryptionPreferencesEntry {
    private Plugin plugin;

    public X3dhpqPreferencesEntry(Plugin plugin) {
        this.plugin = plugin;
    }

    public override string id { get { return "x3dhpq_preferences_encryption"; } }

    public override Object? get_widget(Account account, WidgetType type) {
        if (type != WidgetType.GTK4) {
            return null;
        }

        PreferencesGroup group = new PreferencesGroup() { title = "x3dhpq" };
        var default_row = new SwitchRow() {
            title = "Use x3dhpq by Default for Private Conversations",
            subtitle = "Start new one-to-one conversations with x3dhpq selected and turn off OMEMO-by-default.",
            use_underline = true
        };
        plugin.app.settings.bind_property(
            "default-private-x3dhpq",
            default_row,
            "active",
            BindingFlags.SYNC_CREATE | BindingFlags.BIDIRECTIONAL
        );
        group.add(default_row);

        var devices_widget = new UI.SelfDevicesWidget(plugin.db, account);
        devices_widget.add_device_requested.connect(() => {
            launch_pair_dialog(account, devices_widget);
        });
        group.add(devices_widget);

        var pair_existing_row = new ActionRow() {
            title = "Pair This Device to an Existing Account",
            subtitle = "Already have another device for this account? Enter its pairing code here to join instead of creating a new identity."
        };
        var pair_existing_button = new Gtk.Button.with_label("Pair") {
            valign = Gtk.Align.CENTER
        };
        pair_existing_button.clicked.connect(() => {
            launch_pair_to_existing_dialog(account, pair_existing_row);
        });
        pair_existing_row.add_suffix(pair_existing_button);
        pair_existing_row.activatable_widget = pair_existing_button;
        group.add(pair_existing_row);

        return group;
    }

    private void launch_pair_dialog(Account account, Gtk.Widget anchor) {
        StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            warning("x3dhpq: no StreamModule for account; cannot open pair dialog");
            return;
        }
        XmppStream? stream = plugin.app.stream_interactor.get_stream(account);

        Gtk.Root? root = anchor.get_root();
        Gtk.Window? parent = (root as Gtk.Window);

        var dialog = new UI.PairNewDeviceDialog(parent, plugin.db, account, module, stream);
        dialog.pairing_completed.connect((cert) => {
            // Persist the newly enrolled device under our own account so the next
            // devicelist republish (union) includes it immediately, without waiting
            // for an inbound devicelist round-trip.
            plugin.db.store_remote_device(account, account.bare_jid.to_string(),
                (int) cert.device_id, Base64.encode(cert.marshal()), (long) cert.created_at, cert.flags);
            if (stream != null) {
                module.publish_current_state.begin((!) stream);
                // §10.6.3: append + publish the AddDevice audit entry so this
                // sibling passes the audit-chain trust gate (stream_module.vala's
                // audit_chain_confirmed_device_ids) on every device — including
                // this one — that later observes the account's own devicelist.
                module.publish_add_device_audit_entry.begin((!) stream, cert);
            }
        });
        dialog.present();
    }

    private void launch_pair_to_existing_dialog(Account account, Gtk.Widget anchor) {
        StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            warning("x3dhpq: no StreamModule for account; cannot open pair-to-existing dialog");
            return;
        }
        XmppStream? stream = plugin.app.stream_interactor.get_stream(account);

        Gtk.Root? root = anchor.get_root();
        Gtk.Window? parent = (root as Gtk.Window);

        var dialog = new UI.PairToExistingDialog(parent, plugin.db, account, module, stream);
        dialog.pairing_completed.connect((result) => {
            // Adopt the primary's AIK (and, if shared, its ML-DSA-65 private
            // key) into our account_identity row, and cache the DC the
            // primary issued us so publish_device_list / bundle fetches can
            // serve it without waiting on an inbound devicelist round-trip.
            plugin.db.apply_paired_identity(account, result);
            plugin.db.store_local_device_certificate(account, (int) result.cert.device_id, Base64.encode(result.cert.marshal()));
            if (stream != null) {
                module.publish_current_state.begin((!) stream);
            }
        });
        dialog.present();
    }
}

}
