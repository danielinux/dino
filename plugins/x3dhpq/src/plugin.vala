using Gee;
using Dino.Entities;

namespace Dino.Plugins.X3dhpq {

public class Plugin : RootInterface, Object {
    public Dino.Application app;
    public Database db;
    public Manager manager;

    private EncryptionListEntry list_entry;
    private ContactDetailsProvider contact_details_provider;

    public void registered(Dino.Application app) {
        this.app = app;
        this.db = new Database(Path.build_filename(Application.get_storage_dir(), "x3dhpq.db"));
        this.manager = new Manager(app, db);
        this.list_entry = new EncryptionListEntry(this);
        this.contact_details_provider = new ContactDetailsProvider(this);

        app.plugin_registry.register_encryption_list_entry(list_entry);
        app.plugin_registry.register_encryption_preferences_entry(new X3dhpqPreferencesEntry(this));
        app.plugin_registry.register_contact_details_entry(contact_details_provider);
        app.stream_interactor.module_manager.initialize_account_modules.connect(on_initialize_account_modules);
        app.stream_interactor.stream_negotiated.connect(on_stream_negotiated);
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
    }

    public bool contact_supports_x3dhpq(Conversation conversation) {
        if (conversation.type_ != Conversation.Type.CHAT) {
            return false;
        }

        Dino.EntityInfo entity_info = app.stream_interactor.get_module(Dino.EntityInfo.IDENTITY);
        return entity_info.has_feature_offline(conversation.account, conversation.counterpart, Protocol.NS_X3DHPQ);
    }
}

}
