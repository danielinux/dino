using Gee;
using Gtk;
using Qlite;
using Dino.Entities;
using Xmpp;

namespace Dino.Plugins.X3dhpq.UI {

public class PairNewDeviceDialog : Gtk.Window {
    public signal void pairing_completed(Protocol.DeviceCertificate cert);
    public signal void pairing_failed(string reason);

    private Database db;
    private Account account;
    private StreamModule stream_module;
    private XmppStream? active_stream;

    private string code;
    private uint8[] sid;
    private Protocol.AccountIdentityKey? aik;
    private Protocol.PairingOptions opts;

    private Gtk.Label status_label;

    private ulong verify_handler_id;
    private ulong msg_handler_id;

    private Protocol.PairingExisting? existing;
    private Jid? peer_jid;

    public PairNewDeviceDialog(Gtk.Window parent, Database db, Account account, StreamModule stream_module, XmppStream? stream = null) {
        Object(
            title: "Add new device",
            modal: true,
            transient_for: parent,
            default_width: 400,
            resizable: false
        );

        this.db = db;
        this.account = account;
        this.stream_module = stream_module;
        this.active_stream = stream;

        Row? identity_row = db.get_local_identity(account.id);
        if (identity_row != null) {
            Protocol.AccountIdentityKey key = new Protocol.AccountIdentityKey();
            key.priv_ed25519 = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_priv_ed25519_base64]));
            key.pub_ed25519  = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_pub_ed25519_base64]));
            key.priv_mldsa   = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_priv_mldsa_base64]));
            key.pub_mldsa    = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_pub_mldsa_base64]));
            aik = key;
        }

        try {
            code = Protocol.PairingCode.generate();
        } catch (GLib.Error e) {
            code = "0000000000";
            warning("PairNewDeviceDialog: failed to generate pairing code: %s", e.message);
        }

        try {
            Bytes sid_bytes = global::X3dhpq.Crypto.random_bytes(32);
            sid = bytes_to_uint8_array(sid_bytes);
        } catch (GLib.Error e) {
            sid = new uint8[32];
            warning("PairNewDeviceDialog: failed to generate sid: %s", e.message);
        }

        opts = new Protocol.PairingOptions();
        try {
            Bytes id_bytes = global::X3dhpq.Crypto.random_bytes(4);
            unowned uint8[] id_data = id_bytes.get_data();
            opts.new_device_id = ((uint32) id_data[0] << 24)
                               | ((uint32) id_data[1] << 16)
                               | ((uint32) id_data[2] <<  8)
                               |  (uint32) id_data[3];
        } catch (GLib.Error e) {
            opts.new_device_id = 1;
            warning("PairNewDeviceDialog: failed to generate device id: %s", e.message);
        }
        opts.share_primary = false;
        opts.new_device_flags = 0;

        build_ui();
        wire_signals();
    }

    private void build_ui() {
        var header = new Gtk.HeaderBar();
        header.set_title_widget(new Gtk.Label("Add new device"));
        var cancel_button = new Gtk.Button.with_label("Cancel");
        cancel_button.clicked.connect(() => cancel());
        header.pack_start(cancel_button);
        set_titlebar(header);

        var box = new Gtk.Box(Gtk.Orientation.VERTICAL, 12) {
            margin_top = 18,
            margin_bottom = 18,
            margin_start = 18,
            margin_end = 18
        };

        var hint_label = new Gtk.Label("Show this code on the new device") {
            halign = Gtk.Align.CENTER
        };
        box.append(hint_label);

        string formatted = Protocol.PairingCode.format(code);
        var code_label = new Gtk.Label(formatted) {
            halign = Gtk.Align.CENTER,
            selectable = true
        };
        code_label.add_css_class("monospace");
        Pango.AttrList attrs = new Pango.AttrList();
        attrs.insert(Pango.attr_scale_new(2.0));
        code_label.set_attributes(attrs);
        box.append(code_label);

        string uri = build_qr_uri();
        var uri_view = new Gtk.TextView() {
            editable = false,
            wrap_mode = Gtk.WrapMode.WORD_CHAR,
            monospace = true,
            margin_top = 6
        };
        uri_view.get_buffer().set_text(uri, -1);
        box.append(uri_view);

        status_label = new Gtk.Label("Waiting for new device…") {
            halign = Gtk.Align.CENTER,
            margin_top = 6
        };
        status_label.add_css_class("dim-label");
        box.append(status_label);

        set_child(box);
    }

    private string build_qr_uri() {
        // XEP §10.1a method A: the QR carries this (existing) device's FULL JID
        // — including the resource — so a scanning device can address it
        // directly and start the FSM. Fall back to the bare JID only if the
        // bound resource is not yet available.
        string jid_str = account.bare_jid.to_string();
        if (active_stream != null) {
            Xmpp.Bind.Flag? bind_flag = ((!) active_stream).get_flag(Xmpp.Bind.Flag.IDENTITY);
            if (bind_flag != null && bind_flag.my_jid != null) {
                jid_str = ((!) bind_flag.my_jid).to_string();
            }
        }
        string b64_sid = base64url_encode(sid);
        return @"xmppqr-pair:$jid_str?code=$code&sid=$b64_sid";
    }

    private static string base64url_encode(uint8[] data) {
        string b64 = Base64.encode(data);
        var sb = new StringBuilder();
        for (int i = 0; i < b64.length; i++) {
            char c = b64[i];
            if (c == '+') {
                sb.append_c('-');
            } else if (c == '/') {
                sb.append_c('_');
            } else if (c == '=') {
                // strip padding
            } else {
                sb.append_c(c);
            }
        }
        return sb.str;
    }

    private void wire_signals() {
        // verify_device_received: the server notifies us that a new device with
        // the given resource has been verified. We use this as the trigger to
        // start the pairing exchange with the new device.
        verify_handler_id = stream_module.verify_device_received.connect((new_resource, device_id) => {
            on_verify_device_received(new_resource);
        });

        // pair_message_received: carries subsequent FSM messages matched by sid.
        msg_handler_id = stream_module.pair_message_received.connect((msg_sid, from_jid, msg) => {
            if (!bytes_equal(msg_sid, sid)) return;
            on_pair_message_received(from_jid, msg);
        });
    }

    private static bool bytes_equal(uint8[] a, uint8[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private void on_verify_device_received(Jid new_resource) {
        if (aik == null) {
            set_status("Failed: local identity key not available");
            pairing_failed("local identity key not available");
            return;
        }
        peer_jid = new_resource;
        try {
            existing = new Protocol.PairingExisting((!) aik, code, sid, opts);
            Protocol.PairingMsg? pake1 = ((!) existing).step(null);
            if (pake1 != null) {
                stream_module.send_pair_stanza(new_resource, sid, (!) pake1);
            }
            set_status("Verifying…");
        } catch (GLib.Error e) {
            set_status("Failed: %s".printf(e.message));
            pairing_failed(e.message);
        }
    }

    private void on_pair_message_received(Jid from_jid, Protocol.PairingMsg msg) {
        if (existing == null) return;
        try {
            Protocol.PairingMsg? reply = ((!) existing).step(msg);
            if (reply != null) {
                Jid target = peer_jid ?? from_jid;
                stream_module.send_pair_stanza(target, sid, (!) reply);
            }
            if (((!) existing).is_done()) {
                Protocol.DeviceCertificate? cert = ((!) existing).get_issued_cert();
                if (cert != null) {
                    set_status("Done");
                    pairing_completed((!) cert);
                } else {
                    set_status("Failed: no certificate issued");
                    pairing_failed("no certificate issued");
                }
                disconnect_signals();
                close();
            }
        } catch (GLib.Error e) {
            set_status("Failed: %s".printf(e.message));
            pairing_failed(e.message);
            disconnect_signals();
        }
    }

    private void set_status(string text) {
        Idle.add(() => {
            status_label.label = text;
            return false;
        });
    }

    private void disconnect_signals() {
        if (verify_handler_id != 0) {
            stream_module.disconnect(verify_handler_id);
            verify_handler_id = 0;
        }
        if (msg_handler_id != 0) {
            stream_module.disconnect(msg_handler_id);
            msg_handler_id = 0;
        }
    }

    public void cancel() {
        disconnect_signals();
        close();
    }
}

}
