**Technical Writeup**
We succeeded when we stopped treating the phone as “sending weird DESFire bytes” and treated the Flipper as what iOS needed it to be: an ISO14443-4A / ISO-DEP card that can carry ISO7816 APDUs reliably.

**What Stock Firmware Was Missing**
The stock public Flipper ISO14443-4A listener surface was not enough for this app. Its public listener header exposes receive-side events like `Halted`, `FieldOff`, and `ReceivedData`, but not a public card-side “send ISO-DEP block” API. That means an app can see reader traffic, but cannot cleanly respond at the same abstraction layer.

That was the core missing piece. FIDO over NFC is not just “receive bytes, return bytes.” The reader and card exchange ISO-DEP I/R/S blocks with PCB block numbers, optional chaining, ACK/NAK recovery, PPS, deselect, CID/NAD handling, and ATS negotiation. If the app only receives raw bytes but sends raw `6A81`/`9000`-style APDU payloads without correct ISO-DEP framing, iOS will drop the transaction before WebKit ever reaches the FIDO applet.

So stock firmware gave us some listener primitives, but not a complete public APDU-card-emulation transport.

**Why We Backported Momentum-Style Logic**
Momentum had the missing direction: it added a listener send-block API and an ISO14443-4 helper layer that decodes incoming blocks and encodes outgoing responses. Its public-looking API includes `iso14443_4a_listener_send_block(...)`, while stock Flipper’s public header does not. Compare the stock Flipper header with the Momentum header:

- Stock Flipper ISO14443-4A listener header: [flipperdevices/flipperzero-firmware](https://raw.githubusercontent.com/flipperdevices/flipperzero-firmware/dev/lib/nfc/protocols/iso14443_4a/iso14443_4a_listener.h)
- Momentum ISO14443-4A listener header with send-block API: [Next-Flip/Momentum-Firmware](https://raw.githubusercontent.com/Next-Flip/Momentum-Firmware/dev/lib/nfc/protocols/iso14443_4a/iso14443_4a_listener.h)

We did not want to require building against Momentum firmware, so we pulled the useful concept into the app:

1. Use the public ISO14443-3A listener.
2. Detect RATS ourselves.
3. Send ATS ourselves.
4. Decode ISO-DEP blocks locally.
5. Dispatch only APDU payloads to the NFC application layer.
6. Encode APDU responses back into ISO-DEP I-blocks.

That is now the app’s in-process ISO-DEP boundary. The dispatcher receives APDUs; the NFC transport owns I/R/S block mechanics.

**What Momentum Got Wrong For This Use Case**
Momentum was a useful starting point, not a complete answer. The important limitation is visible in its helper implementation: the ISO14443-4 layer has TODOs around proper block chaining and R-block handling. See the Momentum helper source: [iso14443_4_layer.c](https://raw.githubusercontent.com/Next-Flip/Momentum-Firmware/dev/lib/nfc/helpers/iso14443_4_layer.c).

For our iPhone flow, those TODOs mattered.

The first gap was R-block recovery. When iOS sends an R-NAK like `B2`/`B3`, the correct practical behavior is not “invent a new NAK” or lose state. It is to replay the last transmitted ISO-DEP I-block byte-for-byte. We added an explicit raw last-TX cache for that in [nfc_iso_dep.c](../src/transport/nfc_iso_dep.c).

The second gap was response chaining. Momentum’s response encoder clears the chaining bit and treats responses as one block. That was enough for tiny responses like SELECT and getInfo, but not enough once makeCredential/getAssertion produced 180+ byte NFC responses. We added an app-owned transmit chain: large APDU response bytes plus final status word are queued, first I-block is sent with the ISO-DEP chaining bit, R-ACK advances to the next block, and R-NAK replays the previous block. That lives in [nfc_iso_dep.c](../src/transport/nfc_iso_dep.c) and is driven from [nfc_worker.c](../src/transport/nfc_worker.c).

The third gap was PPS/control tolerance. iOS sometimes sends `D9 33 63` late in the session. We ACK the PPSS byte and preserve the previous I-block replay cache, because otherwise the next `B2` R-NAK would replay the PPS ACK or nothing instead of replaying the actual CTAP response.

**How This Tied To The iOS Failures**
The early broken logs showed loops like:

```text
RATS E0 80
ATS sent
90 60 00 00 00
6A 81
field off
repeat
```

That meant iOS never reached the WebKit FIDO path. It was still in lower NFC discovery/classification. Public WebKit code confirms the WebAuthn path first tries the FIDO applet SELECT and then falls back to U2F_VERSION if SELECT fails: [NfcConnection.mm](https://raw.githubusercontent.com/WebKit/WebKit/main/Source/WebKit/UIProcess/WebAuthentication/Cocoa/NfcConnection.mm). WebKit constants also show the exact SELECT command and accepted `U2F_V2 9000` response: [FidoConstants.h](https://raw.githubusercontent.com/WebKit/WebKit/main/Source/WebCore/Modules/webauthn/fido/FidoConstants.h).

The breakthrough was seeing this in the logs:

```text
00 A4 04 00 08 A0 00 00 06 47 2F 00 01
55 32 46 5F 56 32 90 00
80 10 00 00 00 00 01 04 00 00
```

That means iOS got past classification, WebKit selected the FIDO applet, and Safari issued CTAP2 getInfo over extended APDU. After that, the failures moved from “iOS cannot classify/connect” to “our ISO-DEP recovery is not complete.”

**The iOS Sequence We Ended Up Supporting**
The practical iOS flow is now:

```text
1. iOS polls NFC-A.
2. iOS sends RATS: E0 80.
3. We send ATS: 05 78 91 E8 00.
4. iOS may probe DESFire/native classification:
   - native 60
   - or wrapped 90 60 00 00 00
5. We answer the DESFire compatibility probe without killing the field.
6. WebKit path starts:
   00 A4 04 00 08 A0 00 00 06 47 2F 00 01
7. We return:
   U2F_V2 9000
8. WebKit sends CTAP2 getInfo as extended APDU:
   80 10 00 00 00 00 01 04 00 00
9. We return CTAP status byte + CBOR + 9000.
10. WebKit sends makeCredential/getAssertion over extended APDU.
11. We answer with CTAP response + 9000, now with ISO-DEP response chaining when needed.
12. If iOS sends R-NAK, we replay the previous I-block.
13. If iOS sends R-ACK during an active response chain, we send the next I-block.
```

WebKit’s CTAP NFC driver also has an explicit FIXME for `NFCCTAP_GETRESPONSE`, so avoiding APDU-level `9100`/GET_RESPONSE dependence was the right call for Safari. The driver sends CTAP2 with CLA `0x80`, INS `0x10`, parses the APDU status word, and expects `9000` for success: [CtapNfcDriver.cpp](https://raw.githubusercontent.com/WebKit/WebKit/main/Source/WebKit/UIProcess/WebAuthentication/fido/CtapNfcDriver.cpp).

**Why It Works Now**
The final architecture is layered correctly:

```text
Flipper public NFC listener
  -> app-owned RATS/ATS handling
  -> app-owned ISO-DEP block decode/encode
  -> APDU parser
  -> FIDO/NFC dispatcher
  -> CTAP core
```

The important part is that we stopped mixing layers. APDU code returns APDU payload/status. ISO-DEP code frames it. Recovery code replays or advances ISO-DEP blocks. iOS no longer sees random raw APDU status bytes where it expects an ISO-DEP block.

The implementation is still not a certified full ISO14443-4 stack, but the fragile areas that blocked iOS are now covered: RATS/ATS, DESFire classification tolerance, FIDO SELECT, WebKit extended APDUs, R-NAK replay, R-ACK response chaining, and PPS tolerance.
