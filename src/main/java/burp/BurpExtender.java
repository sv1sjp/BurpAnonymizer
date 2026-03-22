// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Dimitris Vagiakakos @sv1sjp <https://www.tuxhouse.eu>
package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

/**
 * Burp Request Anonymizer 
 *
 * Developed by Dimitris Vagiakakos @sv1sjp
 * https://www.tuxhouse.eu
 *
 *A Burp Suite extension that automatically redacts **PII, credentials, and sensitive identifiers** from HTTP traffic.   
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {

    private static final String VERSION       = "1.0.3";
    private static final String EXTENSION_NAME = "Burp Anonymizer";
    private static final String AUTHOR         = "Dimitris Vagiakakos @sv1sjp";
    private static final String WEBSITE        = "https://www.tuxhouse.eu";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerContextMenuFactory(this);
        callbacks.printOutput("==============================================");
        callbacks.printOutput(" " + EXTENSION_NAME);
        callbacks.printOutput(" A Burp Suite extension that automatically redacts PII, credentials, and other sensitive data from HTTP traffic, enabling secure sharing of requests and responses in reports, team reviews, or AI workflows.");
        callbacks.printOutput(" Developed by " + AUTHOR);
        callbacks.printOutput(" " + WEBSITE);
        callbacks.printOutput(" License: GPL-3.0-only");
        callbacks.printOutput("==============================================");
        callbacks.printOutput("Loaded successfully. v" + VERSION);
        callbacks.printOutput("Right-click any request --> 'Copy Anonymized Request'");
        callbacks.printOutput("Right-click any request --> 'Copy Anonymized Response'");
        callbacks.printOutput("Right-click any request --> 'Copy Anonymized Request + Response'");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        byte ctx = invocation.getInvocationContext();
        if (ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            ctx == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            ctx == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE ||
            ctx == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE ||
            ctx == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS ||
            ctx == IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS ||
            ctx == IContextMenuInvocation.CONTEXT_SEARCH_RESULTS) {

            JMenuItem item = new JMenuItem("Copy Anonymized Request");
            item.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    handleAnonymize(messages[0]);
                }
            });
            menuItems.add(item);

            JMenuItem itemResponse = new JMenuItem("Copy Anonymized Response");
            itemResponse.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    handleAnonymizeResponse(messages[0]);
                }
            });
            menuItems.add(itemResponse);

            JMenuItem itemBoth = new JMenuItem("Copy Anonymized Request + Response");
            itemBoth.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    handleAnonymizeBoth(messages[0]);
                }
            });
            menuItems.add(itemBoth);
        }

        return menuItems;
    }

    private void handleAnonymize(IHttpRequestResponse messageInfo) {
        try {
            byte[] request = messageInfo.getRequest();
            if (request == null) {
                callbacks.printError("No request data available.");
                return;
            }

            IHttpService service = messageInfo.getHttpService();
            String originalHost = service != null ? service.getHost() : "unknown";
            int port = service != null ? service.getPort() : 443;
            String protocol = service != null ? service.getProtocol() : "https";

            RequestAnonymizer anonymizer = new RequestAnonymizer(helpers, originalHost, port, protocol);
            String anonymized = anonymizer.anonymizeRequest(request);

            StringBuilder sb = new StringBuilder();
            sb.append("REQUEST\n");
            sb.append("------------\n");
            sb.append(anonymized);

            String result = sb.toString();
            copyToClipboard(result);
            callbacks.printOutput("Anonymized request copied to clipboard (" + result.length() + " chars).");

        } catch (Exception ex) {
            callbacks.printError("Error anonymizing request: " + ex.getMessage());
            ex.printStackTrace(new java.io.PrintStream(callbacks.getStderr()));
        }
    }

    private void handleAnonymizeResponse(IHttpRequestResponse messageInfo) {
        try {
            byte[] response = messageInfo.getResponse();
            if (response == null) {
                callbacks.printError("No response data available.");
                return;
            }

            IHttpService service = messageInfo.getHttpService();
            String originalHost = service != null ? service.getHost() : "unknown";
            int port = service != null ? service.getPort() : 443;
            String protocol = service != null ? service.getProtocol() : "https";

            RequestAnonymizer anonymizer = new RequestAnonymizer(helpers, originalHost, port, protocol);
            String anonymizedResponse = anonymizer.anonymizeResponse(response);

            StringBuilder sb = new StringBuilder();
            sb.append("RESPONSE\n");
            sb.append("------------\n");
            sb.append(anonymizedResponse);

            String result = sb.toString();
            copyToClipboard(result);
            callbacks.printOutput("Anonymized response copied to clipboard (" + result.length() + " chars).");

        } catch (Exception ex) {
            callbacks.printError("Error anonymizing response: " + ex.getMessage());
            ex.printStackTrace(new java.io.PrintStream(callbacks.getStderr()));
        }
    }

    private void handleAnonymizeBoth(IHttpRequestResponse messageInfo) {
        try {
            byte[] request = messageInfo.getRequest();
            if (request == null) {
                callbacks.printError("No request data available.");
                return;
            }

            IHttpService service = messageInfo.getHttpService();
            String originalHost = service != null ? service.getHost() : "unknown";
            int port = service != null ? service.getPort() : 443;
            String protocol = service != null ? service.getProtocol() : "https";

            RequestAnonymizer anonymizer = new RequestAnonymizer(helpers, originalHost, port, protocol);
            String anonymizedRequest = anonymizer.anonymizeRequest(request);

            StringBuilder sb = new StringBuilder();
            sb.append("REQUEST\n");
            sb.append("--------------\n");
            sb.append(anonymizedRequest);

            byte[] response = messageInfo.getResponse();
            if (response != null) {
                String anonymizedResponse = anonymizer.anonymizeResponse(response);
                sb.append("\n\n\nRESPONSE\n");
                sb.append("--------------\n");
                sb.append(anonymizedResponse);
            }

            String result = sb.toString();
            copyToClipboard(result);
            callbacks.printOutput("Anonymized request+response copied to clipboard (" + result.length() + " chars).");

        } catch (Exception ex) {
            callbacks.printError("Error anonymizing request+response: " + ex.getMessage());
            ex.printStackTrace(new java.io.PrintStream(callbacks.getStderr()));
        }
    }

    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }
}
