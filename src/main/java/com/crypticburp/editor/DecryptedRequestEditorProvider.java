package com.crypticburp.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import com.crypticburp.config.ConfigStore;

public class DecryptedRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final ConfigStore store;

    public DecryptedRequestEditorProvider(MontoyaApi api, ConfigStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new DecryptedRequestEditor(api, store, creationContext);
    }
}
