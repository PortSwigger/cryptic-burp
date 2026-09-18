# CrypticBurp demo app

A small server to test the extension without a real target. This utilizes the crypto profile saved in the [`template.json`](template.json) file.

## Run

```
cd demo
npm install
npm start     # or: node server.js
```

Listens on `http://127.0.0.1:3000` and logs every request in plaintext and ciphertext.

## Set up Burp

Load [`template.json`](template.json) in the **CrypticBurp** tab and click **Apply**.

## Test requests

Paste each into Repeater. A **Decrypted** tab appears on the request and the response.

**1, 2 and 3.** Encrypted query string:

```
GET /api?7Ql7NP5AYWX/izarH0Khi5fY9J8Lz17EUwIm+Fj0MgXWA6zIZmjpMBdupEehgoBz HTTP/1.1
Host: 127.0.0.1:3000
Connection: close


```

```
GET /api?l8zS69BgL6pEBk3VBLy3t8Yt8lqm76oe7L7UjPGiW5tQ1b2IsTr+TOz8WekiJKPx HTTP/1.1
Host: 127.0.0.1:3000
Connection: close


```

```
GET /api?vWZRcAToPct0vvuOc1M60/R7NEOJutLx1ghyyOiSeqjSVtcHMnbf/F2nQeKmEMng0h7LV0+td0O5eILssXILCQ== HTTP/1.1
Host: 127.0.0.1:3000
Connection: close


```

**4 and 5.** Encrypted request body:

```
POST /api/message HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: text/plain
Content-Length: 172
Connection: close

v9Z4ijlWQDp0Wm0DzQaCNL/kdT+p3XfWuo/suHl+4BNRqui/PszQkgszf+OPajCcEYBt7Ps0vAzhhsVEKeWdggOLmn99s6ODMdybsDnCsTol8SLyUbp4X9uwAxISvZN86jmjns0YnlTsq3j8Jrg9JmCRkdXkVko8RA6hpUK+Ww8=
```

```
POST /api/message HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: text/plain
Content-Length: 128
Connection: close

Tm0+GKd+Dk0r4EgPR+mKdmExDj9ChzXJj+xwXSmieRQoTMl/w5ETYpowcwmMzae9GpJLtoUF88ZrT07S2N6MHcHYDMhkAnn8UEceu2+5AJldK02P1FWRqeo94e9C9y1Q
```

## Expected output

For confirming successful decryption.

| # | Decrypts to |
|---|---|
| 1 | `user=obiwan&action=connect&greeting=hello_there` |
| 2 | `user=chris&action=play&song=yellow` |
| 3 | `user=stavros&action=eat&food=40jimmydeanbreakfastsandwiches` |
| 4 | `{"user":"anakin","action":"disconnect","reason":"i dont like sand. its coarse and rough and irritating and it gets everywhere"}` |
| 5 | `{"user":"obiwan","action":"shutdown","msg":"these arent the params youre looking for"}` |

## Also worth trying

Edit a value in the Decrypted tab and send. It gets re-encrypted on its way out and the server echoes the new value back.

Change a path to `/other` in the crypto profile and the Decrypted tab disappears. This is because the profile is scoped to `/api`.
