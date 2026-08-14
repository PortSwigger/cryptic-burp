package com.crypticburp.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.crypticburp.config.ConfigStore;

public class DecryptedResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final ConfigStore store;

    public DecryptedResponseEditorProvider(MontoyaApi api, ConfigStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new DecryptedResponseEditor(api, store, creationContext);
    }
}
