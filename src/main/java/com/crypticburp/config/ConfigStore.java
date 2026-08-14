package com.crypticburp.config;

import burp.api.montoya.persistence.Preferences;
import com.crypticburp.crypto.CryptoService;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the one active {@link Configuration} and the {@link CryptoService} built
 * from it. Reads don't lock (they go through an atomic reference); when you update
 * it, the crypto service gets the new key and the config is saved so it survives a
 * restart (if saving fails, we just carry on).
 */
public final class ConfigStore {

    private static final String PREF_KEY = "crypticburp.configuration";

    private final Preferences preferences;
    private final AtomicReference<Configuration> ref = new AtomicReference<>();
    private final CryptoService crypto = new CryptoService();

    public ConfigStore(Preferences preferences) {
        this.preferences = preferences;
        apply(load());
    }

    public Configuration get() {
        return ref.get();
    }

    public CryptoService crypto() {
        return crypto;
    }

    public void update(Configuration configuration) {
        apply(configuration);
        persist(configuration);
    }

    private void apply(Configuration cfg) {
        ref.set(cfg);
        crypto.configure(cfg.cipher(), cfg.encoding(), cfg.keyFormat(), cfg.key(), cfg.iv(), cfg.ivSameAsKey(), cfg.ivMode());
    }

    private Configuration load() {
        if (preferences != null) {
            try {
                String stored = preferences.getString(PREF_KEY);
                if (stored != null && !stored.isEmpty()) {
                    return Configuration.fromJson(stored);
                }
            } catch (Exception ignored) {
                // Anything goes wrong, just use the defaults.
            }
        }
        return Configuration.defaults();
    }

    private void persist(Configuration cfg) {
        if (preferences != null) {
            try {
                preferences.setString(PREF_KEY, cfg.toJson());
            } catch (Exception ignored) {
                // Saving is a nice-to-have, so don't let it hold up a config change.
            }
        }
    }
}
