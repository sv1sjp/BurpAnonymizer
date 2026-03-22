package burp;

import javax.swing.JMenuItem;
import java.util.List;

/**
 * Burp Suite Extender API - IContextMenuFactory interface.
 */
public interface IContextMenuFactory {
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}
