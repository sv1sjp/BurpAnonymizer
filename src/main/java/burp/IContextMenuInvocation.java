package burp;

/**
 * Burp Suite Extender API - IContextMenuInvocation interface.
 */
public interface IContextMenuInvocation {
    static final byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
    static final byte CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
    static final byte CONTEXT_MESSAGE_VIEWER_REQUEST = 2;
    static final byte CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;
    static final byte CONTEXT_TARGET_SITE_MAP_TABLE = 4;
    static final byte CONTEXT_TARGET_SITE_MAP_TREE = 5;
    static final byte CONTEXT_PROXY_HISTORY = 6;
    static final byte CONTEXT_SCANNER_RESULTS = 7;
    static final byte CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;
    static final byte CONTEXT_INTRUDER_ATTACK_RESULTS = 9;
    static final byte CONTEXT_SEARCH_RESULTS = 10;

    byte getInvocationContext();
    IHttpRequestResponse[] getSelectedMessages();
    int[] getSelectionBounds();
}
