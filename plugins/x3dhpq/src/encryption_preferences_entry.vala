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

        // §10.6.2 "pair this device to an existing account" is offered only via
        // the pending-enrollment banner's "Show this device's code" action (the
        // single tested direction: this new device presents its code, an existing
        // authorized device enters it). No separate enter-the-other-device's-code
        // row here — one direction keeps the flow unambiguous.

        // §10.6.6/§12 Account reset — available on every account (not only inside the
        // pending-enrollment banner), so a primary/authorized device can rekey and
        // restart from genesis. Destructive: mints a new AIK, de-associates all
        // devices, forces per-contact re-verification. Guarded by a confirm dialog.
        var reset_row = new ActionRow() {
            title = "Reset this account's identity",
            subtitle = "Destructive — creates a brand-new identity from scratch, de-associates ALL devices, and forces every contact to re-verify you. Use this to start over."
        };
        var reset_button = new Gtk.Button.with_label("Account reset") {
            valign = Gtk.Align.CENTER
        };
        reset_button.add_css_class("destructive-action");
        reset_button.clicked.connect(() => confirm_account_reset(account, reset_row, devices_widget));
        reset_row.add_suffix(reset_button);
        reset_row.activatable_widget = reset_button;
        group.add(reset_row);

        // Task #58 recovery: a device that currently holds its OWN account AIK
        // (thinks it's primary — including one that self-promoted after a fork) has
        // no other way to discard that identity and JOIN the account's existing
        // manifest. The associate/pair-as-secondary flow only surfaces in the
        // pending-enrollment banner, so offer it here whenever this device is NOT
        // pending (i.e. it holds its own AIK). Non-destructive to the account: it
        // discards THIS device's local identity and re-pairs as a secondary.
        if (!plugin.db.is_pending_enrollment(account)) {
            var join_row = new ActionRow() {
                title = "Join an existing identity",
                subtitle = "This device currently has its own x3dhpq identity. Discard it and re-join the identity your other devices already use — you'll confirm this device from one of them using “Confirm a waiting device”. Your account's key is unchanged."
            };
            var join_button = new Gtk.Button.with_label("Join an existing identity") {
                valign = Gtk.Align.CENTER
            };
            join_button.clicked.connect(() => confirm_join_existing_identity(account, join_row, devices_widget));
            join_row.add_suffix(join_button);
            join_row.activatable_widget = join_button;
            group.add(join_row);
        }

        return group;
    }

    // Task #58: confirm discarding THIS device's local identity and re-joining the
    // account's existing one as a secondary. Unlike account reset this does NOT
    // touch the account's key or other devices — only this device's local state.
    private void confirm_join_existing_identity(Account account, Gtk.Widget anchor, UI.SelfDevicesWidget? devices_widget = null) {
        var dialog = new Adw.AlertDialog(
            "Discard this device's identity and join the existing one?",
            "This device currently holds its OWN x3dhpq identity (key). This will:\n\n" +
            " • Discard THIS device's current identity/key locally. This device stops acting as " +
            "its own identity and becomes a pending device waiting to be confirmed.\n" +
            " • Re-detect the account's existing identity. If your other devices already have an " +
            "identity, this device will wait to be confirmed from one of them (choose “Confirm a " +
            "waiting device” there) and then rejoin as a secondary.\n" +
            " • If NO existing identity is found, this device simply becomes primary again.\n\n" +
            "Your account's key and your OTHER devices are NOT changed. Contacts do not have to " +
            "re-verify you. Use this if this device wrongly thinks it is a separate identity."
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("join", "Discard and join");
        dialog.set_response_appearance("join", Adw.ResponseAppearance.DESTRUCTIVE);
        dialog.default_response = "cancel";
        dialog.close_response = "cancel";
        dialog.response.connect((id) => {
            if (id != "join") return;
            perform_join_existing_identity(account, devices_widget);
        });
        dialog.present(anchor);
    }

    // Task #58: discard the local account AIK this device holds, drop to pending,
    // wipe the local manifest/devicelist/peer state, then re-run pending-enrollment
    // resolution so the device re-detects the account's existing identity (staying
    // quiet as pending if found, self-correcting to primary if none). Must NOT
    // publish a devicelist/manifest as primary while pending.
    private void perform_join_existing_identity(Account account, UI.SelfDevicesWidget? devices_widget) {
        string own_bare = account.bare_jid.to_string();
        // Discard the held AIK + drop to pending (KEEPS DIK + device_id).
        plugin.db.demote_to_pending(account);
        // Local state that was rooted under the discarded identity is meaningless
        // now — clear the manifest version/blob store, the own devicelist snapshot,
        // any own-account sibling/peer rows, revocation tombstones, and the cached
        // self DC (so nothing stale lingers or leaks into a re-detected identity).
        plugin.db.clear_trust_manifest(account, own_bare);
        plugin.db.clear_own_device_list_snapshot(account);
        plugin.db.prune_remote_devices_not_in(account, own_bare, new Gee.HashSet<int>());
        plugin.db.clear_revoked_devices(account);
        plugin.db.invalidate_local_device_certificate(account);

        StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        XmppStream? stream = plugin.app.stream_interactor.get_stream(account);
        if (module == null || stream == null) {
            // Offline: the demote is local; resolution happens on next connect via
            // the normal bootstrap. Reflect the pending state in the UI now.
            if (devices_widget != null) ((!) devices_widget).refresh();
            return;
        }
        // Re-run resolution: publish_current_state resolves pending FIRST (device is
        // no longer authorized), and only publishes a devicelist/manifest if that
        // resolution promotes it to primary (no existing account found). If an
        // existing identity IS found the device stays pending and goes quiet —
        // the pending-enrollment banner's Associate flow then takes over.
        ((!) module).publish_current_state.begin((!) stream, (o, r) => {
            ((!) module).publish_current_state.end(r);
            if (devices_widget != null) {
                Idle.add(() => { ((!) devices_widget).refresh(); return false; });
            }
        });
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
            ? "This device is disabled — removed from the account"
            : "This device is disabled — waiting for sync") {
            halign = Gtk.Align.START,
            wrap = true
        };
        title.add_css_class("heading");
        inner.append(title);

        var subtitle = new Gtk.Label(revoked
            ? ("Another device removed this one's access. It cannot send or receive messages as this " +
                "account while disabled. If this was not you, treat this device as compromised. If it " +
                "was, choose “Pair this device” below, then on one of your remaining devices open its " +
                "device list and choose “Confirm a waiting device” to rejoin — or start an Account reset " +
                "if you have no other working device left.")
            : ("This account already has an identity on another device. This device cannot send messages " +
                "until it is confirmed. Choose “Pair this device” below to show its code, then on one of " +
                "your existing devices open its device list and choose “Confirm a waiting device” — your " +
                "prior messages, groups and contacts' trust are preserved. Only start an Account reset if " +
                "you have no working device left.")
        ) {
            halign = Gtk.Align.START,
            wrap = true
        };
        subtitle.add_css_class("dim-label");
        inner.append(subtitle);

        var button_box = new Gtk.Box(Gtk.Orientation.HORIZONTAL, 6) { halign = Gtk.Align.START, margin_top = 6 };

        // §10.6.2 (single tested direction): this new device PRESENTS its code;
        // an existing authorized device enters it via "Confirm a device…".
        var show_code_button = new Gtk.Button.with_label("Pair this device");
        show_code_button.add_css_class("suggested-action");
        show_code_button.clicked.connect(() => {
            // §11.8 queued enrollment request: persist a signed request to our
            // own pair-hello node so an authorized device that is offline RIGHT
            // NOW still discovers it on its next connect, in addition to the live
            // handshake the shown code enables (which completes immediately if an
            // authorized device is already online and enters the code).
            StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
            XmppStream? stream = plugin.app.stream_interactor.get_stream(account);
            if (module != null && stream != null) {
                module.publish_enrollment_request.begin((!) stream);
            }
            launch_show_own_code_dialog(account, box);
        });
        button_box.append(show_code_button);

        var new_identity_button = new Gtk.Button.with_label("Account reset");
        new_identity_button.add_css_class("destructive-action");
        new_identity_button.clicked.connect(() => confirm_account_reset(account, box));
        button_box.append(new_identity_button);

        inner.append(button_box);
        box.append(inner);
        return box;
    }

    // §10.6.6/§12: Account reset — the only device-lifecycle operation that
    // disturbs peers. Mints a brand-new AIK (a new ratchet root), explicitly
    // de-associating every previously associated device — MUST be presented as
    // destructive per the XEP.
    private void confirm_account_reset(Account account, Gtk.Widget anchor, UI.SelfDevicesWidget? devices_widget = null) {
        var dialog = new Adw.AlertDialog(
            "Reset this account's identity?",
            "This performs an ACCOUNT RESET: it creates a brand-new post-quantum identity for " +
            "this account instead of joining the one your other devices already use.\n\n" +
            "This is DESTRUCTIVE and CANNOT BE UNDONE:\n" +
            " • Your current identity (key) is permanently lost. The old private key is wiped " +
            "from this device and cannot be recovered, and every other device of yours is " +
            "de-associated from it — they will no longer be trusted as this account.\n" +
            " • Every contact will have to re-verify you. They will see your identity change and " +
            "MUST manually re-verify you out-of-band before trusting you again — messaging with " +
            "them does not resume until they do.\n" +
            " • You will lose ALL message history from ALL groups. This account is removed from " +
            "every group it belongs to (your old identity is no longer a journal member), and " +
            "that history stays inaccessible until this account is re-invited to each group " +
            "individually.\n\n" +
            "Only do this if you have no other working device for this account."
        );
        dialog.add_response("cancel", "Cancel");
        dialog.add_response("reset", "Reset account");
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE);
        dialog.default_response = "cancel";
        dialog.close_response = "cancel";
        dialog.response.connect((id) => {
            if (id != "reset") return;
            perform_account_reset(account, devices_widget);
        });
        dialog.present(anchor);
    }

    // §10.6.6/§12: performs the account reset. Captures the OLD AIK_priv (if
    // still held) BEFORE mint_fresh_identity() wipes it, then — after minting —
    // best-effort signals the OLD chain with a RotateAIK entry signed by the
    // OLD AIK (§12.1 step 3) and publishes a fresh devicelist containing ONLY
    // the new device. Wrapped defensively at every step so a failure here can
    // never crash bootstrap or leave the account without a usable local
    // identity: mint_fresh_identity() always succeeds locally regardless of
    // whether the (best-effort, network-dependent) RotateAIK signal does.
    private void perform_account_reset(Account account, UI.SelfDevicesWidget? devices_widget) {
        Bytes? old_aik_priv_ed = null;
        Bytes? old_aik_priv_mldsa = null;
        if (plugin.db.has_local_identity(account)) {
            try {
                string old_priv_ed_b64 = plugin.db.get_local_identity_string(account, plugin.db.account_identity.aik_priv_ed25519_base64);
                string old_priv_ml_b64 = plugin.db.get_local_identity_string(account, plugin.db.account_identity.aik_priv_mldsa_base64);
                if (old_priv_ed_b64 != "" && old_priv_ml_b64 != "") {
                    old_aik_priv_ed = bytes_from_base64(old_priv_ed_b64);
                    old_aik_priv_mldsa = bytes_from_base64(old_priv_ml_b64);
                }
            } catch (GLib.Error e) {
                // Missing/corrupt old key material: skip the old-sig RotateAIK
                // step below (§12: "where the old AIK_priv is still held") —
                // the reset itself still proceeds.
                old_aik_priv_ed = null;
                old_aik_priv_mldsa = null;
            }
        }

        // Wipe any own-account sibling rows learned under the OLD identity
        // (pending or confirmed) — they are meaningless once the AIK changes; a
        // stale row here would otherwise resurrect a phantom "sibling" in the
        // devices-list UI, or leak into the fresh devicelist union, under the
        // new identity. Also drop the locally-cached device-audit DAG (§11.7)
        // so it re-bootstraps under the new AIK instead of permanently failing
        // to resolve against entries signed by the now-revoked old one.
        plugin.db.prune_remote_devices_not_in(account, account.bare_jid.to_string(), new Gee.HashSet<int>());
        plugin.db.clear_device_audit_entries(account);
        // Also wipe the v1 account-audit chain: its entries are signed by the OLD AIK
        // and would otherwise (a) fail verification under the new AIK and (b) leave the
        // chain non-empty so the fresh primary skips its self-genesis AddDevice (§11).
        plugin.db.clear_account_audit_entries(account);
        // §8.6 exception "back to genesis": drop the OWN devicelist snapshot so the
        // shrink guard treats the fresh single-device list as a first publish rather
        // than an (illegal) unrevoked shrink of the OLD identity's list.
        plugin.db.clear_own_device_list_snapshot(account);
        // Fresh AIK/genesis: the new identity's device set starts empty, so old
        // revocation tombstones (device ids of the prior identity's devices) no
        // longer apply and would otherwise linger forever.
        plugin.db.clear_revoked_devices(account);
        // Trust Manifest Phase 2 account reset (task #55, RESET-only, STRICT):
        // mint a NEW AIK while KEEPING this device's DIK + device_id, invalidate the
        // cached self DC so it re-issues under the new AIK, and clear the manifest
        // version/blob store so the fresh version=1 genesis is accepted as a new AIK
        // lineage (not a rollback of the old one — the receiver branches on AIK
        // mismatch BEFORE the version guard).
        plugin.db.reset_account_identity_new_aik(account);
        plugin.db.invalidate_local_device_certificate(account);
        plugin.db.clear_trust_manifest(account, account.bare_jid.to_string());

        StreamModule? module = plugin.app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        XmppStream? stream = plugin.app.stream_interactor.get_stream(account);
        if (module == null || stream == null) {
            // Offline: the new identity is minted locally; the devicelist publish +
            // self-genesis happen on next connect via the normal bootstrap path. The
            // local device set is already fresh, so reflect it in the UI now.
            if (devices_widget != null) ((!) devices_widget).refresh();
            return;
        }

        // NOTE: we deliberately do NOT publish a best-effort RotateAIK entry to the
        // account-audit chain on reset. Because the reset clears the local chain first
        // (so the fresh primary can re-record its self-genesis AddDevice(self)@0), a
        // RotateAIK published here would compute seq=0 and land — signed by the OLD,
        // now-revoked AIK — as item "0" on the audit node, becoming a bogus genesis
        // that fails signature verification under the new AIK on EVERY device
        // (fail-closed: no sibling ever trusted). Peers still chain-detect the
        // reconstruction from the AIK change on the devicelist itself (§8.5/§10.6.5).
        // (old_aik_priv_ed/_mldsa remain captured above for a future, seq-safe signal.)

        // Publishes the fresh, self-signed devicelist under the new AIK —
        // containing ONLY this device, every prior device having just been
        // pruned above — so contacts observe the reconstruction event
        // (§10.6.5), plus a fresh bundle so PQXDH can proceed with the new
        // identity.
        // Genesis reset (§8.6 back-to-genesis / §12): PURGE the server's own PEP nodes
        // first so no item signed by the now-revoked AIK lingers (those fail verification
        // under the new AIK and re-seed stale/forked devices). Then republish the fresh
        // devicelist + bundle and re-record the self-genesis AddDevice(self)@0 under the
        // new AIK, and finally refresh the UI. Chained so each step observes the prior.
        // §1338 node purge: overwrite/retract every stale PEP node signed by the
        // now-dead AIK so nothing lingers to be re-verified under the new one —
        // devtracker:0, devicelist:0, audit:0, trustmanifest:0 and pair:0 (and the
        // bundle, republished by publish_current_state). Then root the FRESH,
        // self-only Trust Manifest genesis (version=1) under the new AIK, republish
        // the derived devicelist cache + bundle, and refresh the UI. Chained so each
        // step observes the prior.
        StreamModule m = (!) module;
        XmppStream s = (!) stream;
        m.purge_own_node.begin(s, Protocol.NS_DEVTRACKER, (o0, r0) => {
            m.purge_own_node.end(r0);
            m.purge_own_node.begin(s, Protocol.NS_DEVICELIST, (o1, r1) => {
                m.purge_own_node.end(r1);
                m.purge_own_node.begin(s, Protocol.NS_AUDIT, (o2, r2) => {
                    m.purge_own_node.end(r2);
                    m.purge_own_node.begin(s, Protocol.NS_TRUSTMANIFEST, (ot, rt) => {
                        m.purge_own_node.end(rt);
                        // Also purge the pairing rendezvous node: stale <pair-hello>/
                        // <enroll-request> items there (from prior devices/attempts,
                        // possibly signed by the now-revoked AIK) otherwise linger and
                        // mislead the next pairing's rendezvous.
                        m.purge_own_node.begin(s, Protocol.NS_PAIR, (op, rp) => {
                            m.purge_own_node.end(rp);
                            // Root the fresh self-only manifest genesis (version=1)
                            // under the new AIK BEFORE publish_current_state, so
                            // ensure_trust_manifest (inside it) sees a current manifest
                            // and stays a no-op instead of computing a different version.
                            m.publish_reset_genesis_manifest.begin(s, (og, rg) => {
                                m.publish_reset_genesis_manifest.end(rg);
                                m.publish_current_state.begin(s, (o3, r3) => {
                                    m.publish_current_state.end(r3);
                                    m.ensure_account_audit_genesis.begin(s, (o4, r4) => {
                                        m.ensure_account_audit_genesis.end(r4);
                                        // Fresh genesis + self device published;
                                        // refresh the devices list (main-loop hop).
                                        if (devices_widget != null) {
                                            Idle.add(() => { ((!) devices_widget).refresh(); return false; });
                                        }
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
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

        // §10.6.2 "Confirm a device" (the existing/authorized side of the single
        // tested direction): the code is entered/scanned here as shown on the
        // pending device, rather than generated by this device.
        var dialog = new UI.PairNewDeviceDialog(parent, plugin.db, account, module, stream, true);
        dialog.pairing_completed.connect((cert) => {
            warning("X3DHPQ-PAIR: CONFIRMER pairing_completed device=%u — appending ADD to manifest", cert.device_id);
            plugin.db.store_remote_device(account, account.bare_jid.to_string(),
                (int) cert.device_id, Base64.encode(cert.marshal()), (long) cert.created_at, cert.flags);
            if (stream != null) {
                // Trust Manifest Phase 2 (§D2): the newcomer is admitted by
                // appending a DIK-signed ADD entry to the account's trust manifest
                // (this device authors it). This replaces the AddDevice audit-entry
                // publish that used to confer trust. publish_current_state still
                // runs to republish the devicelist cache (= fold output). The
                // manifest append also re-publishes the manifest itself.
                module.append_device_add_to_manifest.begin((!) stream, cert, (o, r) => {
                    module.append_device_add_to_manifest.end(r);
                    module.publish_current_state.begin((!) stream);
                });
                // §11.8: the newcomer is admitted now — retract its queued
                // enrollment request (if any) so it stops being re-surfaced as
                // still-pending on this or any other authorized device's next
                // refresh_pair_hello.
                module.retract_enrollment_request.begin((!) stream);
            }
            // Reflect the just-confirmed device in the open Encryption page
            // immediately (pairing_completed fires off the main thread).
            Idle.add(() => {
                (anchor as UI.SelfDevicesWidget)?.refresh();
                return false;
            });
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
                // Trust Manifest Phase 2 (§D3): adopt the account manifest so this
                // newcomer sees itself + siblings once the confirmer's ADD lands.
                module.fetch_and_apply_own_manifest.begin((!) stream);
            }
        });
        dialog.present();
    }

}

}
