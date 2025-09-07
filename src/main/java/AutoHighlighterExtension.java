import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.regex.*;

public class AutoHighlighterExtension implements BurpExtension, HttpHandler, ContextMenuItemsProvider {

    private Logging logging;
    private List<Pattern> patterns;
    private List<String> ignoreList;
    private HighlightColor highlightColor = HighlightColor.RED;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Auto Highlighter");
        this.logging = api.logging();

        // Fixed regex (removed redundant escape)
        this.patterns = List.of(
                Pattern.compile("(?i)password\\s*[:=]\\s*['\"]?([A-Za-z0-9!@#\\-_$%^&*]+)['\"]?"),
                Pattern.compile("(?i)passwd\\s*[:=]\\s*['\"]?([A-Za-z0-9!@#\\-_$%^&*]+)['\"]?"),
                Pattern.compile("(?i)token\\s*[:=]\\s*['\"]?([A-Za-z0-9-_.]{6,})['\"]?"),
                Pattern.compile("(?i)auth\\s*[:=]\\s*['\"]?([A-Za-z0-9-_.]{6,})['\"]?"),
                Pattern.compile("(?i)apikey\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]{8,})['\"]?"),
                Pattern.compile("(?i)api[-_]?key\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]{8,})['\"]?"),
                Pattern.compile("(?i)secret\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)admin\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)flag\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)key\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)jwt\\s*[:=]\\s*['\"]?([A-Za-z0-9-_.]+)['\"]?"),
                Pattern.compile("(?i)bearer\\s*[:=]\\s*['\"]?([A-Za-z0-9-_.]+)['\"]?"),
                Pattern.compile("(?i)sessionid\\s*[:=]\\s*([A-Za-z0-9-_]+)"),
                Pattern.compile("(?i)csrftoken\\s*[:=]\\s*([A-Za-z0-9-_]+)"),
                Pattern.compile("(?i)refresh[-_]?token\\s*[:=]\\s*([A-Za-z0-9-_]+)"),
                Pattern.compile("(?i)access[-_]?token\\s*[:=]\\s*([A-Za-z0-9-_]+)"),
                Pattern.compile("(?i)authorization\\s*[:=]\\s*['\"]?([A-Za-z0-9-_.]+)['\"]?"),
                Pattern.compile("(?i)private[-_]?key\\s*[:=]\\s*([-A-Za-z0-9+/=]+)"),
                Pattern.compile("(?i)public[-_]?key\\s*[:=]\\s*([-A-Za-z0-9+/=]+)"),
                Pattern.compile("(?i)ssh[-_]?key\\s*[:=]\\s*([-A-Za-z0-9+/=]+)"),
                Pattern.compile("(?i)client[-_]?secret\\s*[:=]\\s*([A-Za-z0-9-_]+)"),
                Pattern.compile("(?i)connection[-_]?string\\s*[:=]\\s*(['\"]?.+['\"]?)"),
                Pattern.compile("(?i)db[-_]?password\\s*[:=]\\s*['\"]?([A-Za-z0-9!@#\\-_$%^&*]+)['\"]?"),
                Pattern.compile("(?i)mysql\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)postgres\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)mongo\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)ftp\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)aws[-_]?secret\\s*[:=]\\s*([A-Za-z0-9/+=]+)"),
                Pattern.compile("(?i)aws[-_]?key\\s*[:=]\\s*([A-Za-z0-9/+=]+)"),
                Pattern.compile("(?i)azure\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)gcp\\s*[:=]\\s*['\"]?([A-Za-z0-9-_]+)['\"]?"),
                Pattern.compile("(?i)slack[-_]?token\\s*[:=]\\s*(xox[baprs]-[A-Za-z0-9-]+)"),
                Pattern.compile("(?i)github[-_]?token\\s*[:=]\\s*([A-Za-z0-9_]+)"),
                Pattern.compile("(?i)gitlab[-_]?token\\s*[:=]\\s*([A-Za-z0-9_]+)")

        );

        this.ignoreList = Arrays.asList("reset_password", "forgot_password", "change_password");

        Http http = api.http();
        http.registerHttpHandler(this);

        api.userInterface().registerContextMenuItemsProvider(this);

        logging.logToOutput("Auto Highlighter loaded, watching responses...");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        JMenu submenu = new JMenu("Auto Highlighter Color");

        for (HighlightColor color : HighlightColor.values()) {
            JMenuItem item = new JMenuItem(color.name());
            item.addActionListener(e -> {
                highlightColor = color;
                logging.logToOutput("Highlight color changed to: " + color);

                // Apply to selected HTTP messages
                for (HttpRequestResponse msg : event.selectedRequestResponses()) {
                    Annotations ann = msg.annotations();
                    ann.setHighlightColor(color); // direct update
                }
            });
            submenu.add(item);
        }

        items.add(submenu);
        return items;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            StringBuilder dataToCheck = new StringBuilder();
            // Check headers
            responseReceived.headers().forEach(h -> dataToCheck.append(h.name()).append(": ").append(h.value()).append("\n"));

            // Check body
            dataToCheck.append(responseReceived.bodyToString());
            String combined = dataToCheck.toString();
            boolean matched = false;
            StringBuilder findings = new StringBuilder();

            for (Pattern p : patterns) {
                Matcher m = p.matcher(combined);
                while (m.find()) {
                    String match = m.groupCount() >= 1 ? m.group(m.groupCount()) : m.group();
                    if (ignoreList.stream().noneMatch(match.toLowerCase()::contains)) {
                        matched = true;
                        findings.append("Sensitive value detected: ").append(match).append("\n");
                    }
                }
            }

            if (matched) {
                Annotations ann = responseReceived.annotations();
                ann.setHighlightColor(highlightColor);
                String existing = ann.notes();
                ann.setNotes((existing == null ? "" : existing + "\n") +
                        "AutoHighlighter detected:\n" + findings);
            }

            return ResponseReceivedAction.continueWith(responseReceived);

        } catch (Exception e) {
            if (logging != null) {
                logging.logToError("Error in AutoHighlighter: " + e.getMessage());
            }
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}
