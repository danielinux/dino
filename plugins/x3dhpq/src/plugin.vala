using Gee;
using Dino.Entities;

namespace Dino.Plugins.X3dhpq {

public class Plugin : RootInterface, Object {
    public static Plugin? instance;
    public static Dino.Plugins.X3dhpq.Manager manager { get; private set; }

    public Dino.Application app;
    public Database db;

    private EncryptionListEntry list_entry;
    private ContactDetailsProvider contact_details_provider;

    // §10.6.4/§11.8 UX: accounts for which the "pair this device" screen has
    // already been auto-opened (or attempted) once during THIS pending state,
    // this app session. Purely in-memory/transient — reset on restart, and
    // explicitly cleared below whenever an account leaves the pending state,
    // so a LATER disable (e.g. a fresh revocation, §11.8) is offered again.
    // This is what makes on_stream_negotiated's auto-open fire once per
    // pending state rather than on every reconnect.
    private Gee.HashSet<int> pending_pair_prompt_shown = new Gee.HashSet<int>();

    public void registered(Dino.Application app) {
        instance = this;
        this.app = app;
        this.db = new Database(Path.build_filename(Application.get_storage_dir(), "x3dhpq.db"));
        Plugin.manager = new Manager(app, db);
        app.plugin_registry.x3dhpq_group_manager = Plugin.manager;
        this.list_entry = new EncryptionListEntry(this);
        this.contact_details_provider = new ContactDetailsProvider(this);

        app.plugin_registry.register_encryption_list_entry(list_entry);
        app.plugin_registry.register_encryption_preferences_entry(new X3dhpqPreferencesEntry(this));
        app.plugin_registry.register_contact_details_entry(contact_details_provider);
        // WS7: encrypted media (aesgcm:// XEP-0454) for x3dhpq conversations.
        app.stream_interactor.get_module(FileManager.IDENTITY).add_file_decryptor(new X3dhpqFileDecryptor());
        app.stream_interactor.get_module(FileManager.IDENTITY).add_file_encryptor(new X3dhpqFileEncryptor());
        app.stream_interactor.module_manager.initialize_account_modules.connect(on_initialize_account_modules);
        app.stream_interactor.stream_negotiated.connect(on_stream_negotiated);
        app.stream_interactor.get_module(ChatInteraction.IDENTITY).focused_in.connect((conversation) => {
            prefetch_and_refresh(conversation);
        });
        app.stream_interactor.get_module(ConversationManager.IDENTITY).conversation_forgotten.connect((conversation) => {
            if (conversation.type_ == Conversation.Type.CHAT || conversation.type_ == Conversation.Type.GROUPCHAT_PM) {
                db.forget_peer(conversation.account, conversation.counterpart.bare_jid.to_string());
            }
        });
        // Surface a peer AIK change (rotation/reset) as a user notification so it
        // is not silently stuck in "needs review". The change is not trusted
        // here — the notification prompts the user to review and accept it.
        db.peer_identity_rotated.connect(on_peer_identity_rotated);
    }

    private void on_peer_identity_rotated(Account account, string bare_jid, string? fingerprint) {
        Xmpp.Jid jid;
        try {
            jid = new Xmpp.Jid(bare_jid);
        } catch (Xmpp.InvalidJidError e) {
            return;
        }
        Dino.NotificationEvents events = app.stream_interactor.get_module(Dino.NotificationEvents.IDENTITY);
        events.notify_identity_change.begin(account, jid, bare_jid, fingerprint ?? "");
    }

    public void shutdown() { }

    private void on_initialize_account_modules(Account account, ArrayList<Xmpp.XmppStreamModule> modules) {
        db.ensure_local_identity(account);
        db.ensure_local_prekeys(account);
        modules.add(new StreamModule(account, db));
    }

    private void on_stream_negotiated(Account account, Xmpp.XmppStream stream) {
        StreamModule module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module != null) {
            module.publish_current_state.begin(stream);
        }
        maybe_prompt_pairing(account, stream);
    }

    // §10.6.4 UX: a disabled (not-yet-authorized) device only ever showed a
    // passive banner on the encryption-preferences page, which a user could
    // easily never open. Once this account has actually logged in while still
    // pending, surface the "pair this device" screen directly instead of
    // waiting for the user to stumble onto the banner — dismissible (Cancel is
    // right there in the dialog's header bar), fired at most once per pending
    // state (see pending_pair_prompt_shown above), and NEVER for an account
    // that is already authorized.
    private void maybe_prompt_pairing(Account account, Xmpp.XmppStream stream) {
        if (!db.is_pending_enrollment(account)) {
            // Authorized (or resolved either way) — never prompt, and clear the
            // guard so a LATER disable (e.g. a fresh §11.8 revocation) is
            // offered the auto-open again exactly once.
            pending_pair_prompt_shown.remove(account.id);
            return;
        }
        if (pending_pair_prompt_shown.contains(account.id)) {
            return;
        }

        // No main window yet (e.g. this account finished its very first
        // handshake before the UI finished starting up) — do NOT mark the
        // guard as consumed; the passive banner still covers this case, and
        // we'll retry the auto-open on the account's next reconnect.
        Gtk.Application? gtk_app = GLib.Application.get_default() as Gtk.Application;
        Gtk.Window? parent = gtk_app != null ? ((!) gtk_app).get_active_window() : null;
        if (parent == null) {
            return;
        }

        StreamModule? module = app.stream_interactor.module_manager.get_module(account, StreamModule.IDENTITY);
        if (module == null) {
            return;
        }

        pending_pair_prompt_shown.add(account.id);

        // Mirror the pending-enrollment banner's "Associate" button: also
        // persist a queued enrollment request (§11.8) so an authorized device
        // that is offline right now still discovers it on its next connect, in
        // addition to the live handshake the dialog itself attempts.
        module.publish_enrollment_request.begin(stream);

        var dialog = new UI.PairToExistingDialog((!) parent, db, account, module, stream);
        dialog.pairing_completed.connect((result) => {
            db.apply_paired_identity(account, result);
            db.store_local_device_certificate(account, (int) result.cert.device_id, Base64.encode(result.cert.marshal()));
            module.publish_current_state.begin(stream);
        });
        dialog.present();
    }

    private void prefetch_and_refresh(Conversation conversation) {
        manager.prefetch_for_conversation.begin(conversation, (_, res) => {
            manager.prefetch_for_conversation.end(res);
            if (conversation.encryption == Encryption.X3DHPQ) {
                conversation.notify_property("encryption");
            }
        });
    }

    public bool contact_supports_x3dhpq(Conversation conversation) {
        if (conversation.type_ != Conversation.Type.CHAT) {
            return false;
        }

        // Fast pre-check: Entity Caps advertises the x3dhpq feature.
        Dino.EntityInfo entity_info = app.stream_interactor.get_module(Dino.EntityInfo.IDENTITY);
        if (entity_info.has_feature_offline(conversation.account, conversation.counterpart, Protocol.NS_X3DHPQ)) {
            return true;
        }

        // Definitive capability signal (XEP §15.3, matching the reference):
        // the presence of a published, usable devicelist. Entity Caps can be
        // absent or stale (peer offline, caps not yet fetched, disco cache miss)
        // even when the peer actively publishes x3dhpq keys, so a cached
        // devicelist carrying at least one device is authoritative.
        string bare = conversation.counterpart.bare_jid.to_string();
        return db.has_remote_device_list(conversation.account, bare)
            && db.get_remote_device_ids(conversation.account, bare).size > 0;
    }
}

}
