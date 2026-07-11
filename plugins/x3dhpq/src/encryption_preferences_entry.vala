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

        // §10.6.4 pending-enrollment banner: shown while this install has
        // detected an existing account identity and is waiting to be
        // confirmed by one of the account's existing devices. §11.8 extends
        // this same banner to a SECOND trigger: a previously-confirmed device
        // whose sealed device-state tracker copy stopped decrypting (i.e. it
        // was revoked) is re-flagged pending too (db.mark_tracker_not_authorized
        // in StreamModule.interpret_device_tracker), and gets a distinct
        // "you were revoked" message instead of "never confirmed".
        if (plugin.db.is_pending_enrollment(account)) {
            group.add(build_pending_enrollment_banner(account, plugin.db.is_tracker_revoked(account)));
        }

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
        devices_widget.confirm_device_requested.connect(() => {
            launch_confirm_device_dialog(account, devices_widget);
        });
        group.add(devices_widget);

        // §11.8: a queued enrollment request (persisted or live) or a pair-hello
        // arriving while this page is open should refresh the pending-request
        // row immediately, not only the next time the page is reopened.
        StreamModule? live_module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (live_module != null) {
            ulong enroll_handler = ((!) live_module).enrollment_request_received.connect((jid, did, sid, ed, x, ml) => {
                devices_widget.refresh();
            });
            devices_widget.destroy.connect(() => {
                ((!) live_module).disconnect(enroll_handler);
            });
        }

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

    // §10.6.4: this install detected an existing account identity on first
    // run and is deferring AIK minting (see database.vala's
    // ensure_local_identity / is_pending_enrollment). Offer the two outcomes
    // the XEP requires the client to distinguish explicitly: associate with
    // the existing identity (the default, non-destructive path — either
    // direction of §10.6.2), or mint a brand-new identity (destructive).
    private Gtk.Widget build_pending_enrollment_banner(Account account, bool revoked = false) {
        var box = new Gtk.Box(Gtk.Orientation.VERTICAL, 6) {
            margin_start = 6,
            margin_end = 6,
            margin_top = 6,
            margin_bottom = 6
        };
        box.add_css_class("card");

        var inner = new Gtk.Box(Gtk.Orientation.VERTICAL, 6) {
            margin_start = 12,
            margin_end = 12,
            margin_top = 12,
            margin_bottom = 12
        };
        var title = new Gtk.Label(revoked
            ? "This device was removed from the account"
            : "This device is waiting to be confirmed") {
            halign = Gtk.Align.START,
            wrap = true
        };
        title.add_css_class("heading");
        inner.append(title);

        var subtitle = new Gtk.Label(revoked
            ? ("Another device revoked this one's access (§11.8: its sealed device-state tracker copy " +
                "no longer decrypts). If this was not you, treat this device as compromised. If it was, " +
                "Associate again from one of your remaining devices to rejoin, or generate a new identity " +
                "if you have no other working device left.")
            : ("This account already has an identity on another device. Confirm this device from " +
                "one of your existing devices to join it — your prior messages, groups and contacts' " +
                "trust are preserved. Only generate a new identity if you have no working device left.")
        ) {
            halign = Gtk.Align.START,
            wrap = true
        };
        subtitle.add_css_class("dim-label");
        inner.append(subtitle);

        var button_box = new Gtk.Box(Gtk.Orientation.HORIZONTAL, 6) { halign = Gtk.Align.START, margin_top = 6 };

        var associate_button = new Gtk.Button.with_label("Associate (enter code)");
        associate_button.add_css_class("suggested-action");
        associate_button.clicked.connect(() => {
            // §11.8 queued enrollment request: persist a signed request to our
            // own pair-hello node so an authorized device that is offline RIGHT
            // NOW still discovers it on its next connect, in addition to the
            // live handshake attempted below (which succeeds immediately if one
            // is already online).
            StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
            XmppStream? stream = plugin.app.stream_interactor.get_stream(account);
            if (module != null && stream != null) {
                module.publish_enrollment_request.begin((!) stream);
            }
            launch_pair_to_existing_dialog(account, box);
        });
        button_box.append(associate_button);

        var show_code_button = new Gtk.Button.with_label("Show this device's code");
        show_code_button.clicked.connect(() => launch_show_own_code_dialog(account, box));
        button_box.append(show_code_button);

        var new_identity_button = new Gtk.Button.with_label("Generate a new identity instead");
        new_identity_button.add_css_class("destructive-action");
        new_identity_button.clicked.connect(() => confirm_generate_new_identity(account, box));
        button_box.append(new_identity_button);

        inner.append(button_box);
        box.append(inner);
        return box;
    }

    // §10.6.4b: destructive override. Mints a brand-new AIK, explicitly
    // revoking access to everything under the previous identity (if any) —
    // MUST be presented as such per the XEP.
    private void confirm_generate_new_identity(Account account, Gtk.Widget anchor) {
        var dialog = new Adw.AlertDialog(
            "Generate a new identity?",
            "This creates a brand-new post-quantum identity for this account instead of joining " +
            "the one your other devices already use.\n\n" +
            "This is DESTRUCTIVE:\n" +
            " • All messages under the previous identity are lost.\n" +
            " • The previous identity is revoked — your other devices will no longer trust it.\n" +
            " • You lose access to all prior groups (your old identity is no longer a member).\n" +
            " • Every contact will see your identity change and MUST re-verify you out-of-band " +
            "before trusting you again.\n\n" +
            "Only do this if you have no other working device for this account."
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("generate", "Generate new identity");
        dialog.set_response_appearance("generate", Adw.ResponseAppearance.DESTRUCTIVE);
        dialog.default_response = "cancel";
        dialog.close_response = "cancel";
        dialog.response.connect((id) => {
            if (id != "generate") return;
            // Wipe any own-account sibling rows learned under the OLD identity
            // (pending or confirmed) — they are meaningless once the AIK
            // changes; a stale row here would otherwise resurrect a phantom
            // "sibling" in the devices-list UI under the new identity.
            plugin.db.prune_remote_devices_not_in(account, account.bare_jid.to_string(), new Gee.HashSet<int>());
            plugin.db.mint_fresh_identity(account);

            StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
            XmppStream? stream = plugin.app.stream_interactor.get_stream(account);
            if (module != null && stream != null) {
                // Publishes the fresh, self-signed devicelist under the new AIK
                // so contacts observe the reconstruction event (§10.6.5) and a
                // fresh bundle so PQXDH can proceed with the new identity.
                module.publish_current_state.begin((!) stream);
            }
        });
        dialog.present(anchor);
    }

    private void launch_confirm_device_dialog(Account account, Gtk.Widget anchor) {
        StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            warning("x3dhpq: no StreamModule for account; cannot open confirm-device dialog");
            return;
        }
        XmppStream? stream = plugin.app.stream_interactor.get_stream(account);

        Gtk.Root? root = anchor.get_root();
        Gtk.Window? parent = (root as Gtk.Window);

        // §10.6.2 "Confirm a device": mirrors launch_pair_dialog, but the code
        // is entered/scanned here (as shown on the pending device) rather than
        // generated by this (existing/primary) device.
        var dialog = new UI.PairNewDeviceDialog(parent, plugin.db, account, module, stream, true);
        dialog.pairing_completed.connect((cert) => {
            plugin.db.store_remote_device(account, account.bare_jid.to_string(),
                (int) cert.device_id, Base64.encode(cert.marshal()), (long) cert.created_at, cert.flags);
            if (stream != null) {
                module.publish_current_state.begin((!) stream);
                module.publish_add_device_audit_entry.begin((!) stream, cert);
                // §11.8: the newcomer is admitted now — retract its queued
                // enrollment request (if any) so it stops being re-surfaced as
                // still-pending on this or any other authorized device's next
                // refresh_pair_hello.
                module.retract_enrollment_request.begin((!) stream);
            }
        });
        dialog.present();
    }

    // §10.6.2 "new device presents the code" direction, invoked on the
    // pending side: generate + display this device's own code, then join the
    // account exactly as PairToExistingDialog's typed-code path does.
    private void launch_show_own_code_dialog(Account account, Gtk.Widget anchor) {
        StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            warning("x3dhpq: no StreamModule for account; cannot open show-own-code dialog");
            return;
        }
        XmppStream? stream = plugin.app.stream_interactor.get_stream(account);

        Gtk.Root? root = anchor.get_root();
        Gtk.Window? parent = (root as Gtk.Window);

        var dialog = new UI.PairToExistingDialog(parent, plugin.db, account, module, stream, true);
        dialog.pairing_completed.connect((result) => {
            plugin.db.apply_paired_identity(account, result);
            plugin.db.store_local_device_certificate(account, (int) result.cert.device_id, Base64.encode(result.cert.marshal()));
            if (stream != null) {
                module.publish_current_state.begin((!) stream);
            }
        });
        dialog.present();
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
