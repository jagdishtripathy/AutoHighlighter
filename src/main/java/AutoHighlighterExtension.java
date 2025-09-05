
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AutoHighlighterExtension implements BurpExtension, HttpHandler {

    private Logging logging;
    private List<Pattern> patterns;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Auto Highlighter");

        this.logging = api.logging();

        this.patterns = List.of(
                Pattern.compile("(?i)password"),
                Pattern.compile("(?i)passwd"),
                Pattern.compile("(?i)token"),
                Pattern.compile("(?i)auth"),
                Pattern.compile("(?i)apikey"),
                Pattern.compile("(?i)api[-_]?key"),
                Pattern.compile("(?i)secret"),
                Pattern.compile("(?i)admin"),
                Pattern.compile("(?i)flag"),
                Pattern.compile("(?i)key"),
                Pattern.compile("(?i)jwt"),
                Pattern.compile("(?i)bearer"),
                Pattern.compile("(?i)sessionid"),
                Pattern.compile("(?i)csrftoken"),
                Pattern.compile("(?i)refresh[-_]?token"),
                Pattern.compile("(?i)access[-_]?token"),
                Pattern.compile("(?i)authorization"),
                Pattern.compile("(?i)private[-_]?key"),
                Pattern.compile("(?i)public[-_]?key"),
                Pattern.compile("(?i)ssh[-_]?key"),
                Pattern.compile("(?i)client[-_]?secret"),
                Pattern.compile("(?i)connection[-_]?string"),
                Pattern.compile("(?i)db[-_]?password"),
                Pattern.compile("(?i)mysql"),
                Pattern.compile("(?i)postgres"),
                Pattern.compile("(?i)mongo"),
                Pattern.compile("(?i)ftp"),
                Pattern.compile("(?i)aws[-_]?secret"),
                Pattern.compile("(?i)aws[-_]?key"),
                Pattern.compile("(?i)azure"),
                Pattern.compile("(?i)gcp"),
                Pattern.compile("(?i)slack[-_]?token"),
                Pattern.compile("(?i)github[-_]?token"),
                Pattern.compile("(?i)gitlab[-_]?token")
        );

        Http http = api.http();
        http.registerHttpHandler(this);

        logging.logToOutput("Auto Highlighter loaded, watching responses...");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            String body = responseReceived.bodyToString();
            boolean matched = false;
            StringBuilder findings = new StringBuilder();

            for (Pattern p : patterns) {
                Matcher m = p.matcher(body);
                if (m.find()) {
                    matched = true;
                    findings.append("Matched: ").append(p.pattern()).append("\n");
                }
            }

            if (matched) {
                Annotations ann = responseReceived.annotations();
                ann.setHighlightColor(HighlightColor.RED);

                String existing = ann.notes();
                String newNotes = (existing == null ? "" : existing + "\n") +
                        "[Response Highlighter] Potential keywords found:\n" +
                        findings;

                ann.setNotes(newNotes);

                return ResponseReceivedAction.continueWith(responseReceived, ann);
            }

            return ResponseReceivedAction.continueWith(responseReceived);

        } catch (Exception e) {
            if (logging != null) {
                logging.logToError("Error in Response Highlighter: " + e.getMessage());
            }
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}
