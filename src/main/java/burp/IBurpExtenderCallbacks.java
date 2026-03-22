package burp;

import java.io.OutputStream;

/**
 * Burp Suite Extender API - IBurpExtenderCallbacks interface.
 * Minimal interface for compilation. Full API is provided by Burp at runtime.
 */
public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    IExtensionHelpers getHelpers();
    void registerContextMenuFactory(IContextMenuFactory factory);
    void printOutput(String output);
    void printError(String error);
    OutputStream getStdout();
    OutputStream getStderr();
}
