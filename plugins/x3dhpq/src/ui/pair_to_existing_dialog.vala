// SPDX-License-Identifier: AGPL-3.0-or-later
using Dino.Entities;
using Gee;
using Gtk;
using Qlite;
using Xmpp;

namespace Dino.Plugins.X3dhpq.UI {

/**
 * PairToExistingDialog walks a brand-new (or still-pending) device through
 * joining an existing account via the x3dhpq pairing protocol (PairingNew
 * FSM). Both §10.6.2 confirmation directions share this one FSM/rendezvous
 * path — only the pairing CODE's origin differs:
 *
 *  - `show_own_code = false` (default): "primary presents the code" — the
 *    user types in / scans the 10-digit code that is displayed on the
 *    EXISTING device (PairNewDeviceDialog).
 *  - `show_own_code = true`: "new device presents the code" (§10.6.2's
 *    SHOULD-support direction) — THIS device generates and displays its own
 *    code/sid; the user walks to an existing/primary device and enters it
 *    there (see ConfirmDeviceDialog), which then drives the CPace exchange
 *    exactly as if the code had been typed in from an existing device's
 *    screen. The rendezvous (publish <pair-hello> to our own pair:0 node) and
 *    the PairingNew FSM are identical in both cases — the existing device
 *    always sends PAKE1 first (§10.1a).
 *
 * The dialog is modal and transient over the given parent window.  When
 * pairing succeeds it emits `pairing_completed`; on failure it emits
 * `pairing_failed`.  The caller may also call `cancel()` at any time.
 */
public class PairToExistingDialog : Adw.Window {

    public signal void pairing_completed(Protocol.PairingResult result);
    public signal void pairing_failed(string reason);

    // ── Held references ────────────────────────────────────────────────────────

    private Database      db;
    private Account       account;
    private StreamModule  stream_module;
    private XmppStream?   active_stream;

    // The active FSM; non-null once the user clicks "Pair".
    private Protocol.PairingNew? new_fsm = null;
    // Session-ID for the active pairing; matches what we registered with the
    // stream module.
    private uint8[]? active_sid = null;
    // The pairing code for this session, retained so we can re-arm a fresh FSM
    // if a stray/ghost existing device fails key confirmation.
    private string? active_code = null;
    // The existing device we locked onto (the sender of the first valid PAKE1).
    // On a multi-resource account, several existing resources may race to
    // initiate and message carbons duplicate their traffic to us; we handshake
    // with exactly one and ignore the rest.
    private Xmpp.Jid? locked_peer = null;
    // Signal-handler ID so we can disconnect on cancel / done.
    private ulong pair_message_handler_id = 0;

    // ── UI widgets ─────────────────────────────────────────────────────────────

    private Gtk.Entry? code_entry;
    private Gtk.Button? pair_button;
    private Gtk.Label  status_label;

    // §10.6.2 "new device presents the code" direction: when true, this
    // device generates and displays its own code/sid instead of asking the
    // user to type one in.
    private bool show_own_code;

    // ── Constructor ────────────────────────────────────────────────────────────

    public PairToExistingDialog(Gtk.Window parent, Database db, Account account, StreamModule stream_module, XmppStream? stream = null, bool show_own_code = false) {
        Object(
            modal: true,
            transient_for: parent,
            title: "Pair this device",
            default_width: 400,
            default_height: -1
        );

        this.db            = db;
        this.account       = account;
        this.stream_module = stream_module;
        this.active_stream = stream;
        this.show_own_code = show_own_code;

        build_ui();

        if (show_own_code) {
            begin_show_own_code();
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    public void cancel() {
        cleanup_handlers();
        close();
    }

    // ── Private — UI construction ──────────────────────────────────────────────

    private void build_ui() {
        // Header bar with title and Cancel button.
        var header = new Adw.HeaderBar();
        var cancel_btn = new Gtk.Button.with_label("Cancel");
        cancel_btn.clicked.connect(() => cancel());
        header.pack_start(cancel_btn);

        // Vertical content box.
        var content = new Gtk.Box(Gtk.Orientation.VERTICAL, 0);

        if (show_own_code) {
            // §10.6.2 "new device presents the code": no entry, no QR-scan —
            // we generate and DISPLAY our own code/sid (mirrors
            // PairNewDeviceDialog's own code display), and the pairing kicks
            // off automatically once built (begin_show_own_code()).
            var instruction = new Gtk.Label(
                "On one of your existing devices, open its device list and choose “Confirm a waiting device”, then enter (or scan) this code."
            ) {
                halign    = Gtk.Align.START,
                wrap      = true,
                margin_start  = 12,
                margin_end    = 12,
                margin_top    = 12,
                margin_bottom = 6
            };
            content.append(instruction);
        } else {
            // Instruction label.
            var instruction = new Gtk.Label(
                "Either type the 10-digit code shown on the existing device, or scan its QR."
            ) {
                halign    = Gtk.Align.START,
                wrap      = true,
                margin_start  = 12,
                margin_end    = 12,
                margin_top    = 12,
                margin_bottom = 6
            };
            content.append(instruction);

            // QR scan button — camera widget not yet wired; shows an
            // informational dialog when clicked.
            // TODO: wire a real camera/QR-scan widget once the dependency is in place.
            var qr_button = new Gtk.Button.with_label("Scan QR") {
                halign       = Gtk.Align.START,
                margin_start = 12,
                margin_end   = 12,
                margin_bottom = 6
            };
            qr_button.clicked.connect(() => {
                var dlg = new Adw.AlertDialog(
                    "QR scanning not yet available",
                    "Please type the 10-digit code from the existing device manually.");
                dlg.add_response("ok", "OK");
                dlg.present(this);
            });
            content.append(qr_button);

            // Pairing-code entry — placeholder shows expected format.
            var entry = new Gtk.Entry() {
                placeholder_text = "DDD-DDD-DDD-C",
                input_purpose    = Gtk.InputPurpose.DIGITS,
                max_length       = 14,   // 10 digits + 3 hyphens
                halign           = Gtk.Align.FILL,
                hexpand          = true,
                margin_start     = 12,
                margin_end       = 12,
                margin_bottom    = 6
            };
            // Auto-format: insert hyphens as the user types past positions 3, 6, 9.
            entry.changed.connect(on_entry_changed);
            // Allow Enter key to trigger pairing.
            entry.activate.connect(on_pair_clicked);
            code_entry = entry;
            content.append(entry);

            // "Pair" button.
            var button = new Gtk.Button.with_label("Pair") {
                halign       = Gtk.Align.FILL,
                margin_start = 12,
                margin_end   = 12,
                margin_bottom = 6
            };
            button.add_css_class("suggested-action");
            button.clicked.connect(on_pair_clicked);
            pair_button = button;
            content.append(button);
        }

        // Status label — keeps the user informed at each step.
        status_label = new Gtk.Label(show_own_code ? "Generating code…" : "Awaiting code.") {
            halign       = Gtk.Align.START,
            wrap         = true,
            margin_start = 12,
            margin_end   = 12,
            margin_bottom = 12
        };
        content.append(status_label);

        // Wrap content in a ToolbarView so the header bar sits at the top.
        var toolbar_view = new Adw.ToolbarView();
        toolbar_view.add_top_bar(header);
        toolbar_view.content = content;

        set_content(toolbar_view);
    }

    // ── Private — auto-format code entry ──────────────────────────────────────

    // Suppress re-entrant changed signals while we rewrite the text.
    private bool formatting = false;

    /**
     * Auto-format the entry text as DDD-DDD-DDD-C while the user types.
     * Only digits are kept; hyphens are inserted automatically.
     */
    private void on_entry_changed() {
        if (formatting || code_entry == null) {
            return;
        }
        Gtk.Entry entry = (!) code_entry;
        formatting = true;

        // Strip everything except digits.
        string raw = entry.text;
        var sb = new StringBuilder();
        for (int i = 0; i < raw.length; i++) {
            unichar c = raw[i];
            if (c >= '0' && c <= '9') {
                sb.append_unichar(c);
            }
        }
        // Limit to 10 digits.
        string digits = sb.str.length > 10 ? sb.str[0:10] : sb.str;

        // Re-insert hyphens: DDD-DDD-DDD-C
        var formatted = new StringBuilder();
        for (int i = 0; i < digits.length; i++) {
            if (i == 3 || i == 6 || i == 9) {
                formatted.append_c('-');
            }
            formatted.append_unichar(digits[i]);
        }

        if (entry.text != formatted.str) {
            entry.text = formatted.str;
            // Move cursor to end.
            entry.set_position(-1);
        }

        // Clear any previous error styling.
        entry.remove_css_class("error");

        formatting = false;
    }

    // ── Private — pairing flow ─────────────────────────────────────────────────

    private void on_pair_clicked() {
        // Prevent double-clicks.
        if (pair_button != null) ((!) pair_button).sensitive = false;
        if (code_entry != null) ((!) code_entry).sensitive  = false;

        // Validate the code.
        string raw_input = code_entry != null ? ((!) code_entry).text : "";
        string parsed_code;
        try {
            parsed_code = Protocol.PairingCode.parse(raw_input);
        } catch (Protocol.PairingCodeError e) {
            set_status("Invalid code: %s".printf(e.message));
            if (code_entry != null) ((!) code_entry).add_css_class("error");
            if (pair_button != null) ((!) pair_button).sensitive = true;
            if (code_entry != null) ((!) code_entry).sensitive  = true;
            return;
        }

        start_pairing(parsed_code);
    }

    // §10.6.2 "new device presents the code": generate our own code + sid,
    // display it (build_ui already rendered the placeholder), and kick off
    // pairing immediately — there is no user input to wait for on this side.
    private void begin_show_own_code() {
        string code;
        try {
            code = Protocol.PairingCode.generate();
        } catch (GLib.Error e) {
            string msg = "Failed to generate pairing code: %s".printf(e.message);
            set_status(msg);
            pairing_failed(msg);
            return;
        }

        string formatted = Protocol.PairingCode.format(code);
        var code_label = new Gtk.Label(formatted) {
            halign = Gtk.Align.CENTER,
            selectable = true,
            margin_top = 6,
            margin_bottom = 6
        };
        code_label.add_css_class("monospace");
        Pango.AttrList attrs = new Pango.AttrList();
        attrs.insert(Pango.attr_scale_new(2.0));
        code_label.set_attributes(attrs);
        // Insert the code display right before the status label.
        Gtk.Widget? content_parent = status_label.get_parent();
        if (content_parent != null) {
            code_label.insert_before((!) content_parent, status_label);
        }

        set_status("Waiting for your other device to confirm…");
        start_pairing(code);
    }

    // Shared FSM/rendezvous kickoff for both directions of §10.6.2: `code` is
    // either user-typed (existing device presented it) or self-generated
    // (this device presents it, show_own_code=true) — the FSM and rendezvous
    // are identical either way.
    private void start_pairing(string parsed_code) {
        // Load our DeviceIdentityKey from the database.
        Protocol.DeviceIdentityKey? dik = load_local_dik();
        if (dik == null) {
            string msg = "No local device identity found. Please set up this account first.";
            set_status(msg);
            pairing_failed(msg);
            if (pair_button != null) ((!) pair_button).sensitive = true;
            if (code_entry != null) ((!) code_entry).sensitive  = true;
            return;
        }

        // Generate a fresh session ID.
        uint8[] sid;
        try {
            sid = bytes_to_uint8_array(global::X3dhpq.Crypto.random_bytes(32));
        } catch (GLib.Error e) {
            string msg = "Failed to generate session ID: %s".printf(e.message);
            set_status(msg);
            pairing_failed(msg);
            if (pair_button != null) ((!) pair_button).sensitive = true;
            if (code_entry != null) ((!) code_entry).sensitive  = true;
            return;
        }
        active_sid = sid;
        // Keep the code so we can re-arm a fresh FSM if a stray/ghost existing
        // device races in with a stale code and fails key confirmation.
        active_code = parsed_code;

        // Instantiate the PairingNew FSM.
        try {
            new_fsm = new Protocol.PairingNew((!) dik, parsed_code, sid);
        } catch (GLib.Error e) {
            string msg = "Failed to initialise pairing FSM: %s".printf(e.message);
            set_status(msg);
            pairing_failed(msg);
            if (pair_button != null) ((!) pair_button).sensitive = true;
            if (code_entry != null) ((!) code_entry).sensitive  = true;
            return;
        }

        // Peer JID: we are pairing with another device on the same account.
        Xmpp.Jid peer_bare_jid = account.bare_jid;

        // Register the pairing session with the stream module (role=1 → "new
        // device") so inbound pairing stanzas for this SID are routed to the
        // pair_message_received signal.
        stream_module.register_pair_session(sid, peer_bare_jid, 1 /* role: new */);

        // Subscribe to inbound pairing messages for this SID.
        pair_message_handler_id = stream_module.pair_message_received.connect(
            (msg_sid, from_jid, msg) => {
                on_pair_message_received(msg_sid, from_jid, msg);
            }
        );

        if (!show_own_code) {
            set_status("Waiting for existing device to respond…");
        }

        // Rendezvous (XEP §10.1a method B): publish a self-addressed
        // <pair-hello> to our own pair:0 PEP node so an existing device on this
        // account learns our full JID + sid via +notify (or an explicit
        // "Confirm a device" fetch — see StreamModule.refresh_pair_hello) and
        // initiates the FSM toward us (sending PAKE1 first). Carries no secret
        // material — the pairing code travels only out-of-band.
        if (active_stream != null) {
            XmppStream stream = (!) active_stream;
            int? local_device_id = db.get_local_device_id(account);
            Xmpp.Bind.Flag? bind_flag = stream.get_flag(Xmpp.Bind.Flag.IDENTITY);
            Jid? my_full_jid = bind_flag != null ? bind_flag.my_jid : null;
            if (local_device_id != null && my_full_jid != null) {
                stream_module.publish_pair_hello.begin(
                    stream, (uint32) (!) local_device_id, ((!) my_full_jid).to_string(), sid);
            } else {
                warning("PairToExistingDialog: cannot publish pair-hello (device id or full JID unavailable)");
            }
        } else {
            warning("PairToExistingDialog: no active stream; cannot publish pair-hello");
        }

        // PairingNew INIT step requires the initiator to send the first message;
        // in the protocol, the *existing* device (PairingExisting) sends PAKE1
        // and the *new* device (PairingNew) responds.  We therefore do NOT call
        // step() here — we wait for the PAKE1 from the peer.
    }

    /**
     * Receive a pairing message from the stream module.
     * We only act on messages whose SID matches ours.
     */
    private void on_pair_message_received(uint8[] msg_sid, Xmpp.Jid from_jid, Protocol.PairingMsg msg) {
        if (active_sid == null) {
            return;
        }
        // Compare SIDs byte-by-byte.
        if (!bytes_equal(msg_sid, (!) active_sid)) {
            return;
        }

        // Lock onto the first existing device that reaches us; ignore stanzas
        // from any other resource. Several existing resources may race to
        // initiate, and message carbons duplicate each one's traffic across all
        // of our resources — we handshake with exactly one peer.
        if (locked_peer == null) {
            locked_peer = from_jid;
        } else if (!from_jid.equals((!) locked_peer)) {
            warning("X3DHPQ-PAIR: RESPONDER dropping stanza type=%u from non-peer %s (locked=%s)",
                    msg.msg_type, from_jid.to_string(), ((!) locked_peer).to_string());
            return;
        }

        set_status("Verifying…");

        Protocol.PairingMsg? response = null;
        try {
            response = ((!) new_fsm).step(msg);
        } catch (Protocol.PairingError.PROTOCOL e) {
            // Stray/duplicate/out-of-order stanza (e.g. a carbon copy already
            // consumed, or PAKE1 from a second racing initiator). The FSM
            // validates the message type before mutating state, so nothing was
            // corrupted — ignore and keep waiting.
            warning("X3DHPQ-PAIR: RESPONDER ignoring stray stanza type=%u from %s: %s",
                    msg.msg_type, from_jid.to_string(), e.message);
            return;
        } catch (Protocol.PairingError.AUTH e) {
            // Key confirmation failed for the peer we locked onto. On a polluted
            // account this is typically a ghost/stray existing device replaying a
            // stale code — NOT the genuine device. Re-arm a fresh FSM (fresh CPace
            // state) for the same sid+code and drop the lock, so the real device
            // can still complete.
            if (rearm_new_fsm(from_jid, e)) {
                return;
            }
            string reason = "Pairing failed: %s".printf(e.message);
            set_status(reason);
            cleanup_handlers();
            pairing_failed(reason);
            return;
        } catch (Protocol.PairingError e) {
            string reason = "Pairing failed: %s".printf(e.message);
            set_status(reason);
            cleanup_handlers();
            pairing_failed(reason);
            return;
        } catch (GLib.Error e) {
            string reason = "Internal error: %s".printf(e.message);
            set_status(reason);
            cleanup_handlers();
            pairing_failed(reason);
            return;
        }

        // Send the response stanza if the FSM produced one.
        if (response != null) {
            stream_module.send_pair_stanza(from_jid, (!) active_sid, (!) response);
        }

        // Check completion.
        if (((!) new_fsm).is_done()) {
            Protocol.PairingResult? result = ((!) new_fsm).get_result();
            if (result == null) {
                string reason = "Pairing completed but no result returned.";
                set_status(reason);
                cleanup_handlers();
                pairing_failed(reason);
                return;
            }
            set_status("Done.");
            cleanup_handlers();
            pairing_completed((!) result);
            close();
        }
    }

    // ── Private — helpers ──────────────────────────────────────────────────────

    /**
     * Re-arm the New-side FSM after a locked peer fails key confirmation, so a
     * stray/ghost existing device can't tear down a session the genuine device
     * may still complete. Returns true if re-armed (keep waiting), false if not
     * (caller should fail normally).
     */
    private bool rearm_new_fsm(Xmpp.Jid failed_peer, GLib.Error cause) {
        if (active_sid == null || active_code == null) {
            return false;
        }
        Protocol.DeviceIdentityKey? dik = load_local_dik();
        if (dik == null) {
            return false;
        }
        try {
            new_fsm = new Protocol.PairingNew((!) dik, (!) active_code, (!) active_sid);
        } catch (GLib.Error e) {
            warning("X3DHPQ-PAIR: RESPONDER failed to re-arm FSM: %s", e.message);
            return false;
        }
        locked_peer = null;
        set_status("That code didn't match. Re-check the code and enter it again on the other device.");
        return true;
    }

    /**
     * Build a DeviceIdentityKey (full, with private material) from the
     * local account_identity row.  Returns null if no identity row exists.
     */
    private Protocol.DeviceIdentityKey? load_local_dik() {
        Qlite.Row? row = db.get_local_identity(account.id);
        if (row == null) {
            return null;
        }
        var r = (!) row;

        Protocol.DeviceIdentityKey dik = new Protocol.DeviceIdentityKey();
        dik.pub_ed25519  = bytes_to_uint8_array(bytes_from_base64(r[db.account_identity.dik_pub_ed25519_base64]));
        dik.priv_ed25519 = bytes_to_uint8_array(bytes_from_base64(r[db.account_identity.dik_priv_ed25519_base64]));
        dik.pub_x25519   = bytes_to_uint8_array(bytes_from_base64(r[db.account_identity.dik_pub_x25519_base64]));
        dik.priv_x25519  = bytes_to_uint8_array(bytes_from_base64(r[db.account_identity.dik_priv_x25519_base64]));
        dik.pub_mldsa    = bytes_to_uint8_array(bytes_from_base64(r[db.account_identity.dik_pub_mldsa_base64]));
        dik.priv_mldsa   = bytes_to_uint8_array(bytes_from_base64(r[db.account_identity.dik_priv_mldsa_base64]));
        return dik;
    }

    /** Update the status label from any thread (marshalled to the main loop). */
    private void set_status(string text) {
        GLib.Idle.add(() => {
            status_label.label = text;
            return false;
        });
    }

    /** Disconnect the stream-module signal handler and clear FSM state. */
    private void cleanup_handlers() {
        if (pair_message_handler_id != 0) {
            stream_module.disconnect(pair_message_handler_id);
            pair_message_handler_id = 0;
        }
        new_fsm     = null;
        active_sid  = null;
    }

    /** Compare two uint8[] arrays for equality. */
    private static bool bytes_equal(uint8[] a, uint8[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }
}

} // namespace Dino.Plugins.X3dhpq.UI
