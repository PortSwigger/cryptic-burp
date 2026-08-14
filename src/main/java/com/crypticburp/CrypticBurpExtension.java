package com.crypticburp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.crypticburp.config.ConfigStore;
import com.crypticburp.editor.DecryptedRequestEditorProvider;
import com.crypticburp.editor.DecryptedResponseEditorProvider;
import com.crypticburp.ui.ConfigTab;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Entry point. Shows encrypted request/response traffic as plaintext in a
 * "Decrypted" editor tab and re-encrypts anything you change before it's sent.
 *
 * <p>All the crypto happens inside the editor tabs, not in an HTTP listener, so
 * the bytes on the wire only change when you actually edit the decrypted view.
 * There's one background thread for the config tab's decrypt tester, and it gets
 * stopped when the extension is unloaded.
 */
public class CrypticBurpExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CrypticBurp, Encrypted Traffic Editor");

        ConfigStore store = new ConfigStore(api.persistence().preferences());

        ExecutorService background = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "crypticburp-worker");
            thread.setDaemon(true);
            return thread;
        });

        ConfigTab configTab = new ConfigTab(api, store, background);

        api.userInterface().registerSuiteTab("CrypticBurp", configTab.component());
        api.userInterface().registerHttpRequestEditorProvider(new DecryptedRequestEditorProvider(api, store));
        api.userInterface().registerHttpResponseEditorProvider(new DecryptedResponseEditorProvider(api, store));

        api.extension().registerUnloadingHandler(() -> {
            background.shutdownNow();
            api.logging().logToOutput("CrypticBurp unloaded");
        });

        api.logging().logToOutput("CrypticBurp loaded");
    }
}
