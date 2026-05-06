using Gee;
using Gtk;

using Dino.Entities;

namespace Dino.Ui.ConversationSummary {

public class SubscriptionNotitication : Object {

    private StreamInteractor stream_interactor;
    private Conversation conversation;
    private ConversationView conversation_view;
    private Widget? current_notification;

    public SubscriptionNotitication(StreamInteractor stream_interactor) {
        this.stream_interactor = stream_interactor;

        stream_interactor.get_module(PresenceManager.IDENTITY).received_subscription_request.connect((jid, account) => {
            Conversation relevant_conversation = stream_interactor.get_module(ConversationManager.IDENTITY).create_conversation(jid, account, Conversation.Type.CHAT);
            stream_interactor.get_module(ConversationManager.IDENTITY).start_conversation(relevant_conversation);
            if (conversation != null && account.equals(conversation.account) && jid.equals(conversation.counterpart)) {
                refresh();
            }
        });
        stream_interactor.get_module(PresenceManager.IDENTITY).received_subscription_approval.connect((jid, account) => {
            if (conversation != null && account.equals(conversation.account) && jid.equals_bare(conversation.counterpart)) {
                refresh();
            }
        });
        stream_interactor.get_module(RosterManager.IDENTITY).updated_roster_item.connect((account, jid, roster_item) => {
            if (conversation != null && account.equals(conversation.account) && jid.equals_bare(conversation.counterpart)) {
                refresh();
            }
        });
        stream_interactor.get_module(RosterManager.IDENTITY).removed_roster_item.connect((account, jid, roster_item) => {
            if (conversation != null && account.equals(conversation.account) && jid.equals_bare(conversation.counterpart)) {
                refresh();
            }
        });
    }

    public void init(Conversation conversation, ConversationView conversation_view) {
        this.conversation = conversation;
        this.conversation_view = conversation_view;

        refresh();
    }

    private void refresh() {
        clear_notification();

        if (conversation.type_ != Conversation.Type.CHAT) return;

        if (stream_interactor.get_module(PresenceManager.IDENTITY).exists_subscription_request(conversation.account, conversation.counterpart)) {
            // Show a notification of a pending subscription request
            show_pending_subscription_request();
        } else if (!conversation.counterpart.equals_bare(conversation.account.bare_jid)) {
            // Show a suggestion to request subscription if: We don't have subscription yet and didn't yet request it
            // Don't show this notification for chats with ourselves
            var roster_item = stream_interactor.get_module(RosterManager.IDENTITY).get_roster_item(conversation.account, conversation.counterpart);
            if (roster_item == null ||
                    (roster_item.subscription == Xmpp.Roster.Item.SUBSCRIPTION_NONE || roster_item.subscription == Xmpp.Roster.Item.SUBSCRIPTION_FROM) &&
                    !roster_item.subscription_requested) {
                show_no_subscription(roster_item != null);
            }
        }
    }

    private void clear_notification() {
        if (current_notification != null && conversation_view != null) {
            conversation_view.remove_notification((!) current_notification);
            current_notification = null;
        }
    }

    private void show_no_subscription(bool already_in_roster) {
        Box box = new Box(Orientation.HORIZONTAL, 5);
        Button accept_button = new Button.with_label(_("Send request"));
        GLib.Application app = GLib.Application.get_default();
        accept_button.clicked.connect(() => {
            if (!already_in_roster) {
                stream_interactor.get_module(RosterManager.IDENTITY).add_jid(conversation.account, conversation.counterpart, null);
            }
            stream_interactor.get_module(PresenceManager.IDENTITY).request_subscription(conversation.account, conversation.counterpart);
            ((Dino.Ui.Application) app).window.conversation_view.chat_input.chat_text_view.text_view.grab_focus();
            clear_notification();
        });
        box.append(new Label(_("You do not receive status updates from this contact yet.")) { margin_end=10 });
        box.append(accept_button);
        current_notification = box;
        conversation_view.add_notification(box);
    }

    private void show_pending_subscription_request() {
        Box box = new Box(Orientation.HORIZONTAL, 5);
        Button accept_button = new Button.with_label(_("Accept"));
        Button deny_button = new Button.with_label(_("Deny"));
        GLib.Application app = GLib.Application.get_default();
        accept_button.clicked.connect(() => {
            stream_interactor.get_module(PresenceManager.IDENTITY).approve_subscription(
                conversation.account, conversation.counterpart);
            stream_interactor.get_module(PresenceManager.IDENTITY).request_subscription(
                conversation.account, conversation.counterpart);
            ((Dino.Ui.Application) app).window.conversation_view.chat_input.chat_text_view.text_view.grab_focus();
            clear_notification();
        });
        deny_button.clicked.connect(() => {
            stream_interactor.get_module(PresenceManager.IDENTITY).deny_subscription(
                conversation.account, conversation.counterpart);
            ((Dino.Ui.Application) app).window.conversation_view.chat_input.chat_text_view.text_view.grab_focus();
            clear_notification();
        });
        box.append(new Label(_("This contact would like to add you to their contact list")) { margin_end=10 });
        box.append(accept_button);
        box.append(deny_button);
        current_notification = box;
        conversation_view.add_notification(box);
    }
}

}
