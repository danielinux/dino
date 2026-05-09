using Adw;
using Dino.Entities;

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
        string fingerprint = plugin.db.get_aik_fingerprint(account) ?? "Unavailable";
        int? device_id = plugin.db.get_local_device_id(account);

        group.add(new ActionRow() {
            title = "Account fingerprint",
            subtitle = fingerprint,
        });
        group.add(new ActionRow() {
            title = "Local device id",
            subtitle = device_id != null ? ((!) device_id).to_string() : "Unavailable",
        });
        group.add(new ActionRow() {
            title = "Status",
            subtitle = "wolfSSL-backed keys, x3dhpq PEP publication, pairwise PQXDH sessions, private-group membership journal handling, and dedicated group sender chains are active. Pairing/recovery flows and fuller audit UX are still pending.",
        });

        return group;
    }
}

}
