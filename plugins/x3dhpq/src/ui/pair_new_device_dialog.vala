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

    private ulong pair_hello_handler_id;
    private ulong msg_handler_id;

    private Protocol.PairingExisting? existing;
    private Jid? peer_jid;

    // §10.6.2 "Confirm a device" direction: this device (existing/primary)
    // does NOT generate its own code — the user types in / scans the code
    // that the PENDING device is showing (PairToExistingDialog with
    // show_own_code=true). Everything else (the PairingExisting FSM, the
    // pair-hello rendezvous handling) is identical to the "Add device"
    // direction; only who originates the code differs (§10.6.2).
    private bool confirm_mode;
    private bool code_confirmed = false;
    private Gtk.Entry? code_entry;
    private Gtk.Button? confirm_button;

    public PairNewDeviceDialog(Gtk.Window parent, Database db, Account account, StreamModule stream_module, XmppStream? stream = null, bool confirm_mode = false) {
        Object(
            title: confirm_mode ? "Confirm a device" : "Add new device",
            modal: true,
            transient_for: parent,
            default_width: 400,
            resizable: false
        );

        this.db = db;
        this.account = account;
        this.stream_module = stream_module;
        this.active_stream = stream;
        this.confirm_mode = confirm_mode;

        Row? identity_row = db.get_local_identity(account.id);
        if (identity_row != null) {
            Protocol.AccountIdentityKey key = new Protocol.AccountIdentityKey();
            key.priv_ed25519 = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_priv_ed25519_base64]));
            key.pub_ed25519  = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_pub_ed25519_base64]));
            key.priv_mldsa   = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_priv_mldsa_base64]));
            key.pub_mldsa    = bytes_to_uint8_array(bytes_from_base64(((!) identity_row)[db.account_identity.aik_pub_mldsa_base64]));
            aik = key;
        }

        if (confirm_mode) {
            // The code is user-supplied once they've read it off the pending
            // device; nothing to generate yet.
            code = "";
        } else {
            try {
                code = Protocol.PairingCode.generate();
            } catch (GLib.Error e) {
                code = "0000000000";
                warning("PairNewDeviceDialog: failed to generate pairing code: %s", e.message);
            }
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
        header.set_title_widget(new Gtk.Label(confirm_mode ? "Confirm a device" : "Add new device"));
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

        if (confirm_mode) {
            var hint_label = new Gtk.Label(
                "Enter (or scan) the code shown on the device that's waiting to be confirmed."
            ) {
                halign = Gtk.Align.CENTER,
                wrap = true
            };
            box.append(hint_label);

            var entry = new Gtk.Entry() {
                placeholder_text = "DDD-DDD-DDD-C",
                input_purpose = Gtk.InputPurpose.DIGITS,
                max_length = 14,
                halign = Gtk.Align.FILL,
                hexpand = true,
                margin_top = 6
            };
            entry.changed.connect(on_code_entry_changed);
            entry.activate.connect(on_confirm_clicked);
            code_entry = entry;
            box.append(entry);

            var button = new Gtk.Button.with_label("Confirm") {
                halign = Gtk.Align.FILL,
                margin_top = 6
            };
            button.add_css_class("suggested-action");
            button.clicked.connect(on_confirm_clicked);
            confirm_button = button;
            box.append(button);

            status_label = new Gtk.Label("Awaiting code.") {
                halign = Gtk.Align.CENTER,
                margin_top = 6
            };
            status_label.add_css_class("dim-label");
            box.append(status_label);

            set_child(box);
            return;
        }

        var hint_label2 = new Gtk.Label("Show this code on the new device") {
            halign = Gtk.Align.CENTER
        };
        box.append(hint_label2);

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

    // Suppress re-entrant `changed` signals while we rewrite the entry text.
    private bool formatting = false;

    private void on_code_entry_changed() {
        if (formatting || code_entry == null) return;
        Gtk.Entry entry = (!) code_entry;
        formatting = true;

        var sb = new StringBuilder();
        for (int i = 0; i < entry.text.length; i++) {
            unichar c = entry.text[i];
            if (c >= '0' && c <= '9') sb.append_unichar(c);
        }
        string digits = sb.str.length > 10 ? sb.str[0:10] : sb.str;
        var formatted = new StringBuilder();
        for (int i = 0; i < digits.length; i++) {
            if (i == 3 || i == 6 || i == 9) formatted.append_c('-');
            formatted.append_unichar(digits[i]);
        }
        if (entry.text != formatted.str) {
            entry.text = formatted.str;
            entry.set_position(-1);
        }
        entry.remove_css_class("error");
        formatting = false;
    }

    // §10.6.2 "Confirm a device": the user has read the code off the pending
    // device and typed/scanned it here. Lock it in, then proactively fetch
    // any pair-hello the pending device may have already published (covers
    // the "newcomer showed its code first" ordering — see
    // StreamModule.refresh_pair_hello) in addition to the live +notify path
    // already wired in wire_signals().
    private void on_confirm_clicked() {
        if (code_entry == null) return;
        Gtk.Entry entry = (!) code_entry;
        string parsed;
        try {
            parsed = Protocol.PairingCode.parse(entry.text);
        } catch (Protocol.PairingCodeError e) {
            set_status("Invalid code: %s".printf(e.message));
            entry.add_css_class("error");
            return;
        }
        code = parsed;
        code_confirmed = true;
        entry.sensitive = false;
        if (confirm_button != null) ((!) confirm_button).sensitive = false;
        set_status("Waiting for that device to respond…");
        if (active_stream != null) {
            stream_module.refresh_pair_hello.begin((!) active_stream);
        }
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
        // pair_hello_received: a joining device published a <pair-hello> to the
        // account's own pair:0 PEP node (XEP §10.1a method B), delivered to us
        // via self-PEP +notify. This is the serverless rendezvous trigger that
        // replaces the old server-pushed <verify-device> headline: we learn the
        // new device's full JID and the shared sid, then send PAKE1.
        pair_hello_handler_id = stream_module.pair_hello_received.connect((new_full_jid, device_id, hello_sid) => {
            on_pair_hello_received(new_full_jid, hello_sid);
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

    private void on_pair_hello_received(Jid new_full_jid, uint8[] hello_sid) {
        if (confirm_mode && !code_confirmed) {
            // Not yet — the user hasn't entered/confirmed a code, so we don't
            // know which pending device (if several were mid-rendezvous) or
            // what code to run CPace with. on_confirm_clicked() calls
            // refresh_pair_hello() once a code is confirmed, which re-delivers
            // this same event.
            return;
        }
        if (existing != null) {
            // Already mid-handshake with a peer for this dialog instance.
            return;
        }
        if (aik == null) {
            set_status("Failed: local identity key not available");
            pairing_failed("local identity key not available");
            return;
        }
        // Adopt the sid carried in the joining device's <pair-hello>. In the
        // self-PEP rendezvous (method B) the NEW device generates the sid, so
        // the existing device MUST use that value for the CPace transcript (and
        // the <pair> stanza matching) to line up on both sides.
        sid = hello_sid;
        peer_jid = new_full_jid;
        try {
            existing = new Protocol.PairingExisting((!) aik, code, sid, opts);
            Protocol.PairingMsg? pake1 = ((!) existing).step(null);
            if (pake1 != null) {
                stream_module.send_pair_stanza(new_full_jid, sid, (!) pake1);
            }
            set_status("Verifying…");
        } catch (GLib.Error e) {
            set_status("Failed: %s".printf(e.message));
            pairing_failed(e.message);
        }
    }

    private void on_pair_message_received(Jid from_jid, Protocol.PairingMsg msg) {
        if (existing == null) return;
        // Bind the handshake to the single peer we sent PAKE1 to. On a
        // multi-resource account, message carbons fan every directed <pair>
        // stanza out to all of our resources, so we may see PAKE traffic from
        // OTHER resources (another existing device racing to initiate, or a
        // carbon of our peer's reply to someone else). Only act on stanzas from
        // our chosen peer; drop everything else silently.
        if (peer_jid != null && !from_jid.equals((!) peer_jid)) {
            warning("X3DHPQ-PAIR: INITIATOR dropping stanza type=%u from non-peer %s (peer=%s)",
                    msg.msg_type, from_jid.to_string(), ((!) peer_jid).to_string());
            return;
        }
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
        } catch (Protocol.PairingError.PROTOCOL e) {
            // A stray/duplicate/out-of-order stanza (e.g. a carbon copy of a
            // message we already consumed, or one for a different FSM step).
            // The FSM checks the message type BEFORE mutating any state, so
            // nothing was corrupted — just ignore it and keep waiting.
            warning("X3DHPQ-PAIR: INITIATOR ignoring stray stanza type=%u from %s: %s",
                    msg.msg_type, from_jid.to_string(), e.message);
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
        if (pair_hello_handler_id != 0) {
            stream_module.disconnect(pair_hello_handler_id);
            pair_hello_handler_id = 0;
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
