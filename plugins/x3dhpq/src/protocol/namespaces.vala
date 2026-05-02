namespace Dino.Plugins.X3dhpq.Protocol {

public const string NS_X3DHPQ = "urn:xmppqr:x3dhpq:0";
public const string NS_DEVICELIST = "urn:xmppqr:x3dhpq:devicelist:0";
public const string NS_BUNDLE = "urn:xmppqr:x3dhpq:bundle:0";
public const string NS_ENVELOPE = "urn:xmppqr:x3dhpq:envelope:0";
public const string NS_PAIR = "urn:xmppqr:x3dhpq:pair:0";
public const string NS_AUDIT = "urn:xmppqr:x3dhpq:audit:0";
public const string NS_RECOVERY = "urn:xmppqr:x3dhpq:recovery:0";

public string[] get_disco_features() {
    return {
        NS_X3DHPQ,
        NS_DEVICELIST,
        NS_BUNDLE,
        NS_ENVELOPE,
        NS_PAIR,
        NS_AUDIT,
        NS_RECOVERY,
    };
}

}
