package com.crypticburp.editor;

import static burp.api.montoya.core.ByteArray.byteArray;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.crypticburp.config.BodyCodec;
import com.crypticburp.config.Configuration;
import com.crypticburp.config.ConfigStore;
import java.awt.Component;

/**
 * The "Decrypted" tab for responses. Read-only: it decrypts the response body so
 * you can read it in plaintext. Responses are never re-encrypted or sent, so
 * {@link #getResponse()} just hands back the original.
 */
public class DecryptedResponseEditor implements ExtensionProvidedHttpResponseEditor {

    // One AES block is 16 bytes. A body shorter than that cannot be ciphertext,
    // so skip the tab instead of showing a failed decrypt.
    private static final int MIN_BODY = 16;

    private final ConfigStore store;
    private final RawEditor editor;

    private HttpRequestResponse requestResponse;

    public DecryptedResponseEditor(MontoyaApi api, ConfigStore store, EditorCreationContext ctx) {
        this.store = store;
        this.editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            Configuration cfg = store.get();
            if (!cfg.responseBody().enabled()) {
                return false;
            }
            HttpRequest req = requestResponse.request();
            String host = (req != null && req.httpService() != null) ? req.httpService().host() : null;
            String path = req != null ? req.pathWithoutQuery() : null;
            if (!cfg.hostPathMatches(host, path)) {
                return false;
            }
            HttpResponse resp = requestResponse.response();
            return resp != null && resp.body() != null && resp.body().length() >= MIN_BODY;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        Configuration cfg = store.get();
        HttpResponse resp = requestResponse.response();
        String text;
        try {
            text = BodyCodec.decryptBody(store.crypto(), resp.bodyToString(),
                    cfg.responseBody().type(), cfg.responseBody().field(), cfg.responseBody().padding(), true);
        } catch (Exception e) {
            text = "[Decryption failed: " + e.getMessage() + "]";
        }
        editor.setContents(byteArray(text));
    }

    @Override
    public HttpResponse getResponse() {
        return requestResponse != null ? requestResponse.response() : null;
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
        return false;
    }
}
