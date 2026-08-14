# CrypticBurp, Encrypted Traffic Editor

A Burp Suite extension for dealing with apps that encrypt their HTTP traffic on top of TLS.

CrypticBurp decrypts the application-layer ciphertext in requests and responses into a new tab (**Decrypted**), lets you edit the decrypted plaintext, and re-encrypts the requests on their way to the server.

Originally built for mobile app pentesting where the target was encrypting its API traffic in AES on top of HTTPS, which made Repeater effectively useless. No more though! :)

Shoutout to [sparky23172](https://github.com/sparky23172) for the amazing support with this!

[CrypticBurp config panel photo - adding soon!]

## Features

- Decrypt/encrypt **query strings**, **request bodies**, and **response bodies**
- Works with raw data or with a specific **JSON**/**form field** that contains ciphertext
- **Per-location padding**: one profile can handle (for e.g.) a Tab-padded query string *and* a PKCS7-padded body with the same key, in a single request
- **IV modes**: a fixed IV (field or same-as-key), or a fresh **random IV prepended to the ciphertext** (`encode(IV ‖ ciphertext)`), a common pattern for apps that use per-message IV
- Pretty-prints JSON in the Decrypted tab, and minifies it back down on re-encrypt so the bytes stay clean
- Save and load different configs as **JSON profiles**
- Multiple algorithms, encodings, paddings, and key formats supported
- Per-host/path scoping to not interfere with unrelated traffic

## Requirements

- Burp Suite Community or Pro (duh)

## Building CrypticBurp

You only need this if you want to build from source. Grab a JDK 17+ and run:

```bash
./gradlew clean test jar
```

The loadable extension is written to `build/libs/crypticburp-1.1.jar`. `montoya-api` is a `compileOnly` dependency and all crypto uses the JDK's `javax.crypto`, so the jar carries **no bundled third-party dependencies**.

## Installing CrypticBurp

1. Grab `crypticburp-1.1.jar` (build it, or pull from here)
2. In Burp: **Extensions → Installed → Add**
3. Extension type: **Java**
4. Extension file: select `crypticburp-1.1.jar`
5. Enjoy **CrypticBurp**!

## Using CrypticBurp

1. Obtain the target app's encryption key and IV. Common approaches:
   - Frida hooks on `EVP_EncryptUpdate` / `EVP_DecryptUpdate` (native OpenSSL)
   - Frida hooks on `javax.crypto.Cipher` (Java)
   - Static analysis of the decompiled APK for hardcoded keys
2. Open the **CrypticBurp** tab in Burp
3. Fill in target host, path, cipher, key, encoding, padding, and (if the app uses a per-message IV) set **IV mode** to *Prepended to ciphertext*
4. Click **Apply Config** (and **Save Profile** to save to a JSON config file)
5. Observe Proxy/Repeater traffic in the **Decrypted** tab. This will appear whenever the request matches your host/path filter

### Finding the key with Frida

A ready-to-run hook is bundled at [`frida/crypto_hook.js`](frida/crypto_hook.js). It hooks both native `libcrypto` (`EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_DecryptUpdate`, …) and Java `javax.crypto.Cipher`, and prints the cipher type, key, IV, and plaintext for every call, being perhaps too verbose (feel free to edit to only show on intial calls if needed).

```bash
frida -U -l frida/crypto_hook.js -f com.target.app
```

Typical output you'd paste into CrypticBurp:

```
[CIPHER]     aes-128-cbc
[KEY LEN]    16 bytes (128 bits)
[IV LEN]     16 bytes
[ENC KEY]    54 65 73 74 4b 65 79 31 32 33 34 35 36 37 38 39
[ENC IV ]    54 65 73 74 4b 65 79 31 32 33 34 35 36 37 38 39
[ENCRYPT]    {"user":"alice","action":"login"}
```

**Note:** there is no SSL pinning bypass in this script. If the app pins certs, try to run a pinning bypass (like the one by Maurizio Siddu) alongside this script, or combine it with this one (what I did). Figure it out!

## Configuration Profiles

Reusable JSON config files to make your workflow with multiple applications easier. Load with **Load Profile** and save with **Save Profile**.

A blank [`profiles/template.json`](profiles/template.json) is included to copy and fill in, and [`profiles/`](profiles) also has ready-made examples for each scenario in the test harness. Here's the shape:

```json
{
  "targetHost": "127.0.0.1",
  "targetPath": "/api/",
  "cipher": "AES/CBC",
  "key": "!YeahIS@wSpark5!",
  "iv": "",
  "keyFormat": "ASCII",
  "ivSameAsKey": true,
  "ivMode": "Fixed",
  "encoding": "Base64",
  "query":        { "enabled": true, "padding": "Tab (0x09)" },
  "requestBody":  { "enabled": false,  "type": "Raw", "field": "", "padding": "PKCS7" },
  "responseBody": { "enabled": true,  "type": "Raw", "field": "", "padding": "PKCS7" }
}
```

Your own profiles are gitignored (`*.local.json`) so you don't accidentally commit client keys.

## Screenshots (coming soon!)

**Decrypted message editor tab:** Edit plaintext, re-encryption happens on Send:

![Decrypted tab](screenshots/02_decrypted_tab.png)

**Before/after:** Gobbledegook ciphertext response vs. the decrypted view:

![Encrypted vs decrypted](screenshots/03_encrypted_vs_decrypted.png)

## Supported Formats (currently!)

| Category    | Options                                                                                  |
|-------------|------------------------------------------------------------------------------------------|
| Ciphers     | `AES/CBC`, `AES/CTR`, `AES/ECB`, `AES/GCM`, `DES/CBC`, `DESede/CBC`                       |
| Key formats | `ASCII`, `Hex`, `Base64`                                                                  |
| Encodings   | `Base64`, `Base64-URLSafe`, `Hex`, `None`                                                 |
| Paddings    | `Tab (0x09)`, `Space (0x20)`, `Null (0x00)`, `PKCS7`, `None` (chosen per location)        |
| IV modes    | `Fixed`, `Prepended to ciphertext`                                                        |

## Profile Config Options

| Option        | Description                                                        |
|---------------|-------------------------------------------------------------------|
| Target Host   | Only process requests to this host                                |
| Target Path   | Optional path filter (e.g. `/api/`, trailing `*` allowed)         |
| Query String  | Decrypt/encrypt the query string                                  |
| Request Body  | Decrypt/encrypt the request body                                  |
| Response Body | Decrypt the response for viewing                                  |
| Body Type     | `Raw`, `JSON field`, or `Form field`                              |
| Body Field    | If JSON/Form, which field contains the encrypted blob             |
| Padding       | Chosen **per location**, so query and body can differ            |
| IV Mode       | `Fixed`, or `Prepended` for a random IV carried in the ciphertext |

## Troubleshooting

**Decryption shows garbage**
- Wrong key or IV
- Wrong cipher (try CBC vs ECB, or GCM), padding type, or encoding (Base64 vs Hex vs URL-safe Base64)
- If the app uses a per-message IV, set **IV mode** to *Prepended to ciphertext*

**Decrypted tab doesn't appear**
- Host/path filter doesn't match the request
- You didn't click **Apply Config**
- Query/body is empty or below the trigger threshold

**Extension won't load**
- Make sure you picked extension type **Java** and selected the `.jar`
- Check **Extensions → Errors** tab for the traceback

## Disclaimers

This tool is for **authorized security testing and research only**. The author is not liable for **ANY** misuse.

For transparency, Claude Opus was used to aid in the development of this tool.

## License

MIT. See [LICENSE](LICENSE).
