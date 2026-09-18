package com.crypticburp.ui;

import static burp.api.montoya.core.ByteArray.byteArray;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import com.crypticburp.config.BodyType;
import com.crypticburp.config.Configuration;
import com.crypticburp.config.ConfigStore;
import com.crypticburp.config.LocationConfig;
import com.crypticburp.crypto.CipherSpec;
import com.crypticburp.crypto.CryptoException;
import com.crypticburp.crypto.Encoding;
import com.crypticburp.crypto.IvMode;
import com.crypticburp.crypto.KeyFormat;
import com.crypticburp.crypto.Padding;
import com.crypticburp.util.JsonPretty;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.ExecutorService;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * The "CrypticBurp" tab where you set the scope, cipher, key, per-location
 * settings, save and load profiles, and try out a quick decrypt. The decrypt
 * tester runs on a background thread so it can't freeze the UI, and dialogs open
 * attached to Burp's window.
 */
public final class ConfigTab {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ExecutorService background;

    private final JComponent root;

    private final JTextField hostField = new JTextField(24);
    private final JTextField pathField = new JTextField(16);

    private final JComboBox<CipherSpec> cipherCombo = new JComboBox<>(CipherSpec.values());
    private final JTextField keyField = new JTextField(32);
    private final JComboBox<KeyFormat> keyFormatCombo = new JComboBox<>(KeyFormat.values());
    private final JTextField ivField = new JTextField(32);
    private final JCheckBox ivSameCheck = new JCheckBox("Same as key", true);
    private final JComboBox<IvMode> ivModeCombo = new JComboBox<>(IvMode.values());
    private final JComboBox<Encoding> encodingCombo = new JComboBox<>(Encoding.values());

    private final JCheckBox queryEnabled = new JCheckBox("Query string", true);
    private final JComboBox<Padding> queryPadding = new JComboBox<>(Padding.values());

    private final JCheckBox reqEnabled = new JCheckBox("Request body", false);
    private final JComboBox<BodyType> reqType = new JComboBox<>(BodyType.values());
    private final JTextField reqField = new JTextField(12);
    private final JComboBox<Padding> reqPadding = new JComboBox<>(Padding.values());

    private final JCheckBox respEnabled = new JCheckBox("Response body", true);
    private final JComboBox<BodyType> respType = new JComboBox<>(BodyType.values());
    private final JTextField respField = new JTextField(12);
    private final JComboBox<Padding> respPadding = new JComboBox<>(Padding.values());

    private final JComboBox<Padding> testPadding = new JComboBox<>(Padding.values());
    private final RawEditor testInput;
    private final RawEditor testOutput;

    private final JLabel statusLabel = new JLabel(" ");

    public ConfigTab(MontoyaApi api, ConfigStore store, ExecutorService background) {
        this.api = api;
        this.store = store;
        this.background = background;
        this.testInput = api.userInterface().createRawEditor();
        this.testOutput = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        this.root = build();
        loadIntoUi(store.get());
        refreshStatus();
    }

    public JComponent component() {
        return root;
    }

    private JComponent build() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        content.add(buildScopePanel());
        content.add(buildCryptoPanel());
        content.add(buildLocationsPanel());
        content.add(buildButtonsPanel());
        content.add(buildTestPanel());

        JPanel main = new JPanel(new BorderLayout());
        main.add(new JScrollPane(content), BorderLayout.CENTER);

        statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        main.add(statusLabel, BorderLayout.SOUTH);
        return main;
    }

    private JPanel buildScopePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Scope"));
        GridBagConstraints c = gbc();

        c.gridx = 0; c.gridy = 0;
        panel.add(new JLabel("Host:"), c);
        c.gridx = 1;
        hostField.setToolTipText("Exact host, e.g. api.example.com (empty = all hosts)");
        panel.add(hostField, c);
        c.gridx = 2;
        panel.add(new JLabel("Path prefix:"), c);
        c.gridx = 3;
        pathField.setToolTipText("e.g. /api/  (trailing * allowed; empty = all paths)");
        panel.add(pathField, c);
        return panel;
    }

    private JPanel buildCryptoPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Cipher & key"));
        GridBagConstraints c = gbc();

        c.gridx = 0; c.gridy = 0;
        panel.add(new JLabel("Cipher/mode:"), c);
        c.gridx = 1;
        panel.add(cipherCombo, c);
        c.gridx = 2;
        panel.add(new JLabel("Encoding:"), c);
        c.gridx = 3;
        panel.add(encodingCombo, c);

        c.gridx = 0; c.gridy = 1;
        panel.add(new JLabel("Key:"), c);
        c.gridx = 1; c.gridwidth = 2; c.fill = GridBagConstraints.HORIZONTAL;
        panel.add(keyField, c);
        c.gridwidth = 1; c.fill = GridBagConstraints.NONE;
        c.gridx = 3;
        panel.add(keyFormatCombo, c);

        c.gridx = 0; c.gridy = 2;
        panel.add(new JLabel("IV:"), c);
        c.gridx = 1; c.gridwidth = 2; c.fill = GridBagConstraints.HORIZONTAL;
        panel.add(ivField, c);
        c.gridwidth = 1; c.fill = GridBagConstraints.NONE;
        c.gridx = 3;
        panel.add(ivSameCheck, c);

        c.gridx = 0; c.gridy = 3;
        panel.add(new JLabel("IV mode:"), c);
        c.gridx = 1;
        ivModeCombo.setToolTipText("Fixed: use the IV field. Prepended: random IV per message, "
                + "prepended to the ciphertext (encode(IV||ciphertext)).");
        panel.add(ivModeCombo, c);

        ivSameCheck.addActionListener(e -> updateIvFieldsEnabled());
        ivModeCombo.addActionListener(e -> updateIvFieldsEnabled());
        updateIvFieldsEnabled();
        return panel;
    }

    private void updateIvFieldsEnabled() {
        boolean prepended = ivModeCombo.getSelectedItem() == IvMode.PREPENDED;
        ivSameCheck.setEnabled(!prepended);
        ivField.setEnabled(!prepended && !ivSameCheck.isSelected());
    }

    private JPanel buildLocationsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Locations (per-location padding)"));
        GridBagConstraints c = gbc();

        c.gridx = 0; c.gridy = 0;
        panel.add(queryEnabled, c);
        c.gridx = 3;
        panel.add(new JLabel("Padding:"), c);
        c.gridx = 4;
        panel.add(queryPadding, c);

        c.gridx = 0; c.gridy = 1;
        panel.add(reqEnabled, c);
        c.gridx = 1;
        panel.add(labelled("Type:", reqType), c);
        c.gridx = 2;
        panel.add(labelled("Field:", reqField), c);
        c.gridx = 3;
        panel.add(new JLabel("Padding:"), c);
        c.gridx = 4;
        panel.add(reqPadding, c);

        c.gridx = 0; c.gridy = 2;
        panel.add(respEnabled, c);
        c.gridx = 1;
        panel.add(labelled("Type:", respType), c);
        c.gridx = 2;
        panel.add(labelled("Field:", respField), c);
        c.gridx = 3;
        panel.add(new JLabel("Padding:"), c);
        c.gridx = 4;
        panel.add(respPadding, c);
        return panel;
    }

    private JPanel buildButtonsPanel() {
        JPanel panel = new JPanel();
        JButton apply = new JButton("Apply config");
        apply.addActionListener(e -> apply());
        JButton save = new JButton("Save profile");
        save.addActionListener(e -> saveProfile());
        JButton load = new JButton("Load profile");
        load.addActionListener(e -> loadProfile());
        panel.add(apply);
        panel.add(save);
        panel.add(load);
        return panel;
    }

    private JPanel buildTestPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Decrypt tester"));
        GridBagConstraints c = gbc();
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0;
        c.weighty = 1.0;

        c.gridx = 0; c.gridy = 0;
        panel.add(sized(testInput.uiComponent()), c);

        c.gridx = 1; c.weightx = 0; c.weighty = 0; c.fill = GridBagConstraints.NONE;
        JPanel mid = new JPanel();
        mid.setLayout(new BoxLayout(mid, BoxLayout.Y_AXIS));
        mid.add(new JLabel("Padding:"));
        mid.add(testPadding);
        JButton run = new JButton("Decrypt \u2192");
        run.addActionListener(e -> runTest());
        mid.add(run);
        panel.add(mid, c);

        c.gridx = 2; c.weightx = 1.0; c.weighty = 1.0; c.fill = GridBagConstraints.BOTH;
        panel.add(sized(testOutput.uiComponent()), c);
        return panel;
    }

    /**
     * Burp's editor does not report a useful preferred size, and the tab stacks
     * its panels with a BoxLayout that sizes each one by preference. Without this
     * the whole tester panel collapses to a sliver.
     */
    private static JComponent sized(Component component) {
        JPanel holder = new JPanel(new BorderLayout());
        holder.add(component, BorderLayout.CENTER);
        holder.setPreferredSize(new Dimension(320, 120));
        return holder;
    }

    private void apply() {
        store.update(buildConfiguration());
        refreshStatus();
    }

    private void refreshStatus() {
        String msg = store.crypto().status();
        statusLabel.setText(store.crypto().isReady() ? "Status: " + msg : "Status: " + msg + "  (not ready)");
    }

    private Configuration buildConfiguration() {
        return new Configuration(
                hostField.getText().trim(),
                pathField.getText().trim(),
                (CipherSpec) cipherCombo.getSelectedItem(),
                keyField.getText(),
                ivField.getText(),
                (KeyFormat) keyFormatCombo.getSelectedItem(),
                ivSameCheck.isSelected(),
                (IvMode) ivModeCombo.getSelectedItem(),
                (Encoding) encodingCombo.getSelectedItem(),
                new LocationConfig(queryEnabled.isSelected(), BodyType.RAW, "", (Padding) queryPadding.getSelectedItem()),
                new LocationConfig(reqEnabled.isSelected(), (BodyType) reqType.getSelectedItem(),
                        reqField.getText().trim(), (Padding) reqPadding.getSelectedItem()),
                new LocationConfig(respEnabled.isSelected(), (BodyType) respType.getSelectedItem(),
                        respField.getText().trim(), (Padding) respPadding.getSelectedItem()));
    }

    private void loadIntoUi(Configuration cfg) {
        hostField.setText(cfg.targetHost());
        pathField.setText(cfg.targetPath());
        cipherCombo.setSelectedItem(cfg.cipher());
        keyField.setText(cfg.key());
        ivField.setText(cfg.iv());
        keyFormatCombo.setSelectedItem(cfg.keyFormat());
        ivSameCheck.setSelected(cfg.ivSameAsKey());
        ivModeCombo.setSelectedItem(cfg.ivMode());
        updateIvFieldsEnabled();
        encodingCombo.setSelectedItem(cfg.encoding());

        queryEnabled.setSelected(cfg.query().enabled());
        queryPadding.setSelectedItem(cfg.query().padding());

        reqEnabled.setSelected(cfg.requestBody().enabled());
        reqType.setSelectedItem(cfg.requestBody().type());
        reqField.setText(cfg.requestBody().field());
        reqPadding.setSelectedItem(cfg.requestBody().padding());

        respEnabled.setSelected(cfg.responseBody().enabled());
        respType.setSelectedItem(cfg.responseBody().type());
        respField.setText(cfg.responseBody().field());
        respPadding.setSelectedItem(cfg.responseBody().padding());
    }

    private void saveProfile() {
        apply();
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save CrypticBurp profile");
        chooser.setFileFilter(new FileNameExtensionFilter("CrypticBurp profile (*.json)", "json"));
        if (chooser.showSaveDialog(parentFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".json")) {
            file = new java.io.File(file.getParentFile(), file.getName() + ".json");
        }
        try {
            Files.write(file.toPath(), buildConfiguration().toJson().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            JOptionPane.showMessageDialog(parentFrame(), "Could not save profile: " + e.getMessage(),
                    "CrypticBurp", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadProfile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Load CrypticBurp profile");
        chooser.setFileFilter(new FileNameExtensionFilter("CrypticBurp profile (*.json)", "json"));
        if (chooser.showOpenDialog(parentFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            String text = new String(Files.readAllBytes(chooser.getSelectedFile().toPath()), StandardCharsets.UTF_8);
            Configuration cfg = Configuration.fromJson(text);
            loadIntoUi(cfg);
            store.update(cfg);
            refreshStatus();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(parentFrame(), "Could not load profile: " + e.getMessage(),
                    "CrypticBurp", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void runTest() {
        apply();
        String input = testInput.getContents().toString().trim();
        Padding padding = (Padding) testPadding.getSelectedItem();
        if (input.isEmpty()) {
            testOutput.setContents(byteArray("[No input]"));
            return;
        }
        testOutput.setContents(byteArray("Working..."));
        background.submit(() -> {
            String result;
            try {
                result = JsonPretty.format(store.crypto().decrypt(input, padding));
            } catch (CryptoException e) {
                result = "[Decryption failed: " + e.getMessage() + "]";
            } catch (Exception e) {
                result = "[Error: " + e.getMessage() + "]";
            }
            String finalResult = result;
            SwingUtilities.invokeLater(() -> testOutput.setContents(byteArray(finalResult)));
        });
    }

    /**
     * The window to attach dialogs to. First choice is the window this tab is
     * actually sitting in, so pop-ups follow the tab if you drag it out onto a
     * second monitor. If that isn't available yet, we fall back to Burp's main
     * window.
     */
    private Component parentFrame() {
        try {
            java.awt.Window window = api.userInterface().swingUtils().windowForComponent(root);
            if (window != null) {
                return window;
            }
        } catch (Exception ignored) {
            // Couldn't get the tab's window, so use the main Burp window instead.
        }
        try {
            return api.userInterface().swingUtils().suiteFrame();
        } catch (Exception e) {
            return root;
        }
    }

    private static JPanel labelled(String label, JComponent field) {
        JPanel p = new JPanel();
        p.add(new JLabel(label));
        p.add(field);
        return p;
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }
}
