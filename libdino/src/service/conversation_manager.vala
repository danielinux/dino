using Gee;

using Xmpp;
using Dino.Entities;

namespace Dino {
public class ConversationManager : StreamInteractionModule, Object {
    public static ModuleIdentity<ConversationManager> IDENTITY = new ModuleIdentity<ConversationManager>("conversation_manager");
    public string id { get { return IDENTITY.id; } }

    public signal void conversation_activated(Conversation conversation);
    public signal void conversation_deactivated(Conversation conversation);
    public signal void conversation_forgotten(Conversation conversation);

    private StreamInteractor stream_interactor;
    private Database db;

    private HashMap<Account, HashMap<Jid, Gee.List<Conversation>>> conversations = new HashMap<Account, HashMap<Jid, Gee.List<Conversation>>>(Account.hash_func, Account.equals_func);

    public static void start(StreamInteractor stream_interactor, Database db) {
        ConversationManager m = new ConversationManager(stream_interactor, db);
        stream_interactor.add_module(m);
    }

    private ConversationManager(StreamInteractor stream_interactor, Database db) {
        this.db = db;
        this.stream_interactor = stream_interactor;
        stream_interactor.add_module(this);
        stream_interactor.account_added.connect(on_account_added);
        stream_interactor.account_removed.connect(on_account_removed);
        stream_interactor.get_module(MessageProcessor.IDENTITY).received_pipeline.connect(new MessageListener(stream_interactor));
        stream_interactor.get_module(MessageProcessor.IDENTITY).message_sent.connect(handle_sent_message);
        stream_interactor.get_module(Calls.IDENTITY).call_incoming.connect(handle_new_call);
        stream_interactor.get_module(Calls.IDENTITY).call_outgoing.connect(handle_new_call);
    }

    public Conversation create_conversation(Jid jid, Account account, Conversation.Type? type = null) {
        assert(conversations.has_key(account));
        Jid store_jid = type == Conversation.Type.GROUPCHAT ? jid.bare_jid : jid;

        // Do we already have a conversation for this jid?
        if (conversations[account].has_key(store_jid)) {
            foreach (var conversation in conversations[account][store_jid]) {
                if (conversation.type_ == type) {
                    return conversation;
                }
            }
        }

        // Create a new converation
        Conversation conversation = new Conversation(jid, account, type);
        // Set encryption for conversation
        if (type == Conversation.Type.CHAT ||
                (type == Conversation.Type.GROUPCHAT && stream_interactor.get_module(MucManager.IDENTITY).is_private_room(account, jid))) {
            conversation.encryption = Application.get_default().settings.get_default_encryption(account);
        } else {
            conversation.encryption = Encryption.NONE;
        }

        add_conversation(conversation);
        conversation.persist(db);
        return conversation;
    }

    public Conversation? get_conversation_for_message(Entities.Message message) {
        if (conversations.has_key(message.account)) {
            if (message.type_ == Entities.Message.Type.CHAT) {
                return create_conversation(message.counterpart.bare_jid, message.account, Conversation.Type.CHAT);
            } else if (message.type_ == Entities.Message.Type.GROUPCHAT) {
                return create_conversation(message.counterpart.bare_jid, message.account, Conversation.Type.GROUPCHAT);
            } else if (message.type_ == Entities.Message.Type.GROUPCHAT_PM) {
                return create_conversation(message.counterpart, message.account, Conversation.Type.GROUPCHAT_PM);
            }
        }
        return null;
    }

    public Gee.List<Conversation> get_conversations(Jid jid, Account account) {
        Gee.List<Conversation> ret = new ArrayList<Conversation>(Conversation.equals_func);
        Conversation? bare_conversation = get_conversation(jid, account);
        if (bare_conversation != null) ret.add(bare_conversation);
        Conversation? full_conversation = get_conversation(jid.bare_jid, account);
        if (full_conversation != null) ret.add(full_conversation);
        return ret;
    }

    public Conversation? get_conversation(Jid jid, Account account, Conversation.Type? type = null) {
        if (conversations.has_key(account)) {
            if (conversations[account].has_key(jid)) {
                foreach (var conversation in conversations[account][jid]) {
                    if (type == null || conversation.type_ == type) {
                        return conversation;
                    }
                }
            }
        }
        return null;
    }

    public Conversation? approx_conversation_for_stanza(Jid from, Jid to, Account account, string msg_ty) {
        if (msg_ty == Xmpp.MessageStanza.TYPE_GROUPCHAT) {
            return get_conversation(from.bare_jid, account, Conversation.Type.GROUPCHAT);
        }

        Jid counterpart = from.equals_bare(account.bare_jid) ? to : from;

        if (msg_ty == Xmpp.MessageStanza.TYPE_CHAT && counterpart.is_full() &&
                get_conversation(counterpart.bare_jid, account, Conversation.Type.GROUPCHAT) != null) {
            var pm = get_conversation(counterpart, account, Conversation.Type.GROUPCHAT_PM);
            if (pm != null) return pm;
        }

        return get_conversation(counterpart.bare_jid, account, Conversation.Type.CHAT);
    }

    public Conversation? get_conversation_by_id(int id) {
        foreach (HashMap<Jid, Gee.List<Conversation>> hm in conversations.values) {
            foreach (Gee.List<Conversation> hm2 in hm.values) {
                foreach (Conversation conversation in hm2) {
                    if (conversation.id == id) {
                        return conversation;
                    }
                }
            }
        }
        return null;
    }

    public Gee.List<Conversation> get_active_conversations(Account? account = null) {
        Gee.List<Conversation> ret = new ArrayList<Conversation>(Conversation.equals_func);
        foreach (Account account_ in conversations.keys) {
            if (account != null && !account_.equals(account)) continue;
            foreach (Gee.List<Conversation> list in conversations[account_].values) {
                foreach (var conversation in list) {
                    if(conversation.active) ret.add(conversation);
                }
            }
        }
        return ret;
    }

    public void start_conversation(Conversation conversation) {
        if (conversation.last_active == null) {
            conversation.last_active = new DateTime.now_utc();
            if (conversation.active) conversation_activated(conversation);
        }
        if (!conversation.active) {
            conversation.active = true;
            conversation_activated(conversation);
        }
    }

    public void close_conversation(Conversation conversation) {
        if (!conversation.active) return;

        conversation.active = false;
        conversation_deactivated(conversation);
    }

    public void forget_contact(Conversation conversation) {
        if (conversation.active) {
            conversation.active = false;
            conversation_deactivated(conversation);
        }

        purge_conversation_rows(conversation);
        conversation_forgotten(conversation);
        remove_conversation(conversation);
    }

    private void on_account_added(Account account) {
        conversations[account] = new HashMap<Jid, ArrayList<Conversation>>(Jid.hash_func, Jid.equals_func);
        foreach (Conversation conversation in db.get_conversations(account)) {
            add_conversation(conversation);
        }
    }

    private void on_account_removed(Account account) {
        foreach (Gee.List<Conversation> list in conversations[account].values) {
            foreach (var conversation in list) {
                if(conversation.active) conversation_deactivated(conversation);
            }
        }
        conversations.unset(account);
    }

    private class MessageListener : Dino.MessageListener {

        public string[] after_actions_const = new string[]{ "DEDUPLICATE", "FILTER_EMPTY" };
        public override string action_group { get { return "MANAGER"; } }
        public override string[] after_actions { get { return after_actions_const; } }

        private StreamInteractor stream_interactor;

        public MessageListener(StreamInteractor stream_interactor) {
            this.stream_interactor = stream_interactor;
        }

        public override async bool run(Entities.Message message, Xmpp.MessageStanza stanza, Conversation conversation) {
            conversation.last_active = message.time;

            if (stanza != null) {
                bool is_mam_message = Xmpp.MessageArchiveManagement.MessageFlag.get_flag(stanza) != null;
                bool is_recent = message.time.compare(new DateTime.now_utc().add_days(-3)) > 0;
                if (is_mam_message && !is_recent) return false;
            }
            stream_interactor.get_module(ConversationManager.IDENTITY).start_conversation(conversation);
            return false;
        }
    }

    private void handle_sent_message(Entities.Message message, Conversation conversation) {
        conversation.last_active = message.time;

        bool is_recent = message.time.compare(new DateTime.now_utc().add_hours(-24)) > 0;
        if (is_recent) {
            start_conversation(conversation);
        }
    }

    private void handle_new_call(Call call, CallState state, Conversation conversation) {
        conversation.last_active = call.time;
        start_conversation(conversation);
    }

    private void add_conversation(Conversation conversation) {
        if (!conversations[conversation.account].has_key(conversation.counterpart)) {
            conversations[conversation.account][conversation.counterpart] = new ArrayList<Conversation>(Conversation.equals_func);
        }

        conversations[conversation.account][conversation.counterpart].add(conversation);

        if (conversation.active) {
            conversation_activated(conversation);
        }
    }

    private void remove_conversation(Conversation conversation) {
        Gee.List<Conversation>? conversation_list = conversations[conversation.account][conversation.counterpart];
        if (conversation_list == null) {
            return;
        }

        conversation_list.remove(conversation);
        if (conversation_list.size == 0) {
            conversations[conversation.account].unset(conversation.counterpart);
        }
    }

    private void purge_conversation_rows(Conversation conversation) {
        Gee.ArrayList<int> message_ids = new Gee.ArrayList<int>();
        Gee.ArrayList<int> file_ids = new Gee.ArrayList<int>();
        Gee.ArrayList<int> call_ids = new Gee.ArrayList<int>();
        Gee.ArrayList<int> content_item_ids = new Gee.ArrayList<int>();

        foreach (Qlite.Row row in db.content_item.select().with(db.content_item.conversation_id, "=", conversation.id)) {
            int content_item_id = row[db.content_item.id];
            int content_type = row[db.content_item.content_type];
            int foreign_id = row[db.content_item.foreign_id];
            content_item_ids.add(content_item_id);
            switch (content_type) {
                case 1:
                    message_ids.add(foreign_id);
                    break;
                case 2:
                    file_ids.add(foreign_id);
                    break;
                case 3:
                    call_ids.add(foreign_id);
                    break;
            }
        }

        foreach (int content_item_id in content_item_ids) {
            db.reaction.delete()
                .with(db.reaction.content_item_id, "=", content_item_id)
                .perform();
        }

        foreach (int message_id in message_ids) {
            db.message_occupant_id.delete()
                .with(db.message_occupant_id.message_id, "=", message_id)
                .perform();
            db.body_meta.delete()
                .with(db.body_meta.message_id, "=", message_id)
                .perform();
            db.message_correction.delete()
                .with(db.message_correction.message_id, "=", message_id)
                .perform();
            db.reply.delete()
                .with(db.reply.message_id, "=", message_id)
                .perform();
            db.real_jid.delete()
                .with(db.real_jid.message_id, "=", message_id)
                .perform();
            db.message.delete()
                .with(db.message.id, "=", message_id)
                .perform();
        }

        foreach (int file_id in file_ids) {
            db.file_hashes.delete()
                .with(db.file_hashes.id, "=", file_id)
                .perform();
            db.file_thumbnails.delete()
                .with(db.file_thumbnails.id, "=", file_id)
                .perform();
            db.sfs_sources.delete()
                .with(db.sfs_sources.file_transfer_id, "=", file_id)
                .perform();
            db.file_transfer.delete()
                .with(db.file_transfer.id, "=", file_id)
                .perform();
        }

        foreach (int call_id in call_ids) {
            db.call_counterpart.delete()
                .with(db.call_counterpart.call_id, "=", call_id)
                .perform();
            db.call.delete()
                .with(db.call.id, "=", call_id)
                .perform();
        }

        db.content_item.delete()
            .with(db.content_item.conversation_id, "=", conversation.id)
            .perform();
        db.conversation_settings.delete()
            .with(db.conversation_settings.conversation_id, "=", conversation.id)
            .perform();
        db.avatar.delete()
            .with(db.avatar.account_id, "=", conversation.account.id)
            .with(db.avatar.jid_id, "=", db.get_jid_id(conversation.counterpart))
            .perform();
        db.entity.delete()
            .with(db.entity.account_id, "=", conversation.account.id)
            .with(db.entity.jid_id, "=", db.get_jid_id(conversation.counterpart))
            .perform();
        db.conversation.delete()
            .with(db.conversation.id, "=", conversation.id)
            .perform();

        stream_interactor.get_module(MessageStorage.IDENTITY).forget_conversation(conversation);
    }
}

}
