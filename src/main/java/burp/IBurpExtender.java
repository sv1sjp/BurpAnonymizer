package burp;

/**
 * Burp Suite Extender API - IBurpExtender interface.
 * This is provided by Burp Suite at runtime. Included here for compilation only.
 */
public interface IBurpExtender {
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
}
