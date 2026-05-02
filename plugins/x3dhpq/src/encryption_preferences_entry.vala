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
            subtitle = "wolfSSL-backed keys, x3dhpq PEP publication, pairwise PQXDH sessions, and message envelopes are active. Audit, pairing/recovery, and dedicated group sender chains are still pending.",
        });

        return group;
    }
}

}
