package com.crypticburp.editor;

import static burp.api.montoya.core.ByteArray.byteArray;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.crypticburp.config.BodyCodec;
import com.crypticburp.config.Configuration;
import com.crypticburp.config.ConfigStore;
import com.crypticburp.config.LocationConfig;
import java.awt.Component;

/**
 * The "Decrypted" tab for requests. Shows the plaintext of the encrypted query
 * string and/or request body. If you edit it, {@link #getRequest()} re-encrypts
 * it on the way out so Repeater and Proxy send valid ciphertext. There's no marker
 * header and no HTTP listener involved.
 */
public class DecryptedRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private static final String QUERY_HEADER = "===== QUERY =====";
    private static final String BODY_HEADER = "===== BODY =====";
    // One AES block is 16 bytes, which comes to 24 characters once it is Base64
    // encoded. Shorter than that and it cannot be ciphertext, so skip the tab
    // instead of showing a failed decrypt on every short request.
    private static final int MIN_QUERY = 24;
    private static final int MIN_BODY = 16;

    private final MontoyaApi api;
    private final ConfigStore store;
    private final RawEditor editor;

    private HttpRequestResponse requestResponse;
    private boolean showQuery;
    private boolean showBody;
    private String basePath = "";

    public DecryptedRequestEditor(MontoyaApi api, ConfigStore store, EditorCreationContext ctx) {
        this.api = api;
        this.store = store;
        this.editor = ctx.editorMode() == EditorMode.READ_ONLY
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            Configuration cfg = store.get();
            HttpRequest req = requestResponse.request();
            if (req == null) {
                return false;
            }
            String host = req.httpService() != null ? req.httpService().host() : null;
            if (!cfg.hostPathMatches(host, req.pathWithoutQuery())) {
                return false;
            }
            boolean q = cfg.query().enabled() && req.query() != null && req.query().length() >= MIN_QUERY;
            boolean b = cfg.requestBody().enabled() && req.body() != null && req.body().length() >= MIN_BODY;
            return q || b;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        this.showQuery = false;
        this.showBody = false;

        Configuration cfg = store.get();
        HttpRequest req = requestResponse.request();
        this.basePath = req.pathWithoutQuery();

        String plainQuery = null;
        String plainBody = null;

        if (cfg.query().enabled() && req.query() != null && !req.query().isEmpty()) {
            plainQuery = tryDecryptRaw(req.query(), cfg.query());
            showQuery = true;
        }
        if (cfg.requestBody().enabled() && req.body() != null && req.body().length() > 0) {
            plainBody = tryDecryptBody(req.bodyToString(), cfg.requestBody());
            showBody = true;
        }

        String text;
        if (showQuery && showBody) {
            text = QUERY_HEADER + "\n" + plainQuery + "\n\n" + BODY_HEADER + "\n" + plainBody;
        } else if (showQuery) {
            text = plainQuery;
        } else if (showBody) {
            text = plainBody;
        } else {
            text = "[No encrypted content in scope]";
        }
        editor.setContents(byteArray(text));
    }

    @Override
    public HttpRequest getRequest() {
        if (requestResponse == null) {
            return null;
        }
        HttpRequest original = requestResponse.request();
        if (!editor.isModified()) {
            return original;
        }

        Configuration cfg = store.get();
        String text = editor.getContents().toString();

        String editedQuery = null;
        String editedBody = null;
        if (showQuery && showBody) {
            String[] parts = splitSections(text);
            editedQuery = parts[0];
            editedBody = parts[1];
        } else if (showQuery) {
            editedQuery = text;
        } else if (showBody) {
            editedBody = text;
        }

        HttpRequest req = original;
        try {
            if (showQuery && editedQuery != null) {
                String enc = store.crypto().encrypt(editedQuery.trim(), cfg.query().padding());
                req = req.withPath(basePath + "?" + enc);
            }
            if (showBody && editedBody != null) {
                String enc = BodyCodec.encryptBody(store.crypto(), editedBody.trim(),
                        cfg.requestBody().type(), cfg.requestBody().field(), cfg.requestBody().padding());
                req = req.withBody(enc);
            }
        } catch (Exception e) {
            api.logging().logToError("CrypticBurp: re-encryption failed: " + e.getMessage());
            return original;
        }
        return req;
    }

    private String tryDecryptRaw(String ciphertext, LocationConfig loc) {
        try {
            return store.crypto().decrypt(ciphertext, loc.padding());
        } catch (Exception e) {
            return ciphertext;
        }
    }

    private String tryDecryptBody(String body, LocationConfig loc) {
        try {
            return BodyCodec.decryptBody(store.crypto(), body, loc.type(), loc.field(), loc.padding(), true);
        } catch (Exception e) {
            return body;
        }
    }

    private static String[] splitSections(String text) {
        int bodyIdx = text.indexOf(BODY_HEADER);
        String beforeBody = bodyIdx >= 0 ? text.substring(0, bodyIdx) : text;
        String afterBody = bodyIdx >= 0 ? text.substring(bodyIdx + BODY_HEADER.length()) : null;

        String query = null;
        int queryIdx = beforeBody.indexOf(QUERY_HEADER);
        if (queryIdx >= 0) {
            query = beforeBody.substring(queryIdx + QUERY_HEADER.length()).trim();
        }
        String body = afterBody != null ? afterBody.trim() : null;
        return new String[]{query, body};
    }

    @Override
    public String caption() {
        return "Decrypted";
    }

    @Override
    public Component uiComponent() {
        return editor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return editor.selection().orElse(null);
    }

    @Override
    public boolean isModified() {
        return editor.isModified();
    }
}
