# HWBP

Credential Manager passkey provider for Android 16+ (API 36). Keys are generated in StrongBox,
never leave it unencrypted, and **can NOT be synced or backed up**. See [Why](#why).

- `app/`: Kotlin. Provider service, Keystore, BiometricPrompt, UI.
- `rust/`: WebAuthn encoding, attestation policy, signature checks. Never sees private keys.
- `proto/hwbp/v1/core.proto`: the interface between them. One JNI call,
  `NativeCore.invoke(Request): Response`. WebAuthn JSON stays JSON inside the messages.

## Guarantees

- P-256 keys with `setIsStrongBoxBacked(true)`. No TEE or software fallback.
- The attestation challenge is the `clientDataHash`. The leaf must attest StrongBox (attestation
  and KeyMint level), `origin = GENERATED`, P-256 `SIGN`-only, and hardware-enforced per-use
  user auth.
- The chain must verify to a pinned Google root (`rust/data/roots`), contain no revoked serial,
  have CA issuers only, and carry the attestation extension in the leaf only.
- Every signature needs its own BiometricPrompt, on an unlocked device, and is verified against
  the attested key before a response is returned.
- BE/BS flags are never set. `direct`/`indirect`/`enterprise` attestation returns `android-key`;
  anything else returns `none`.
- No backup or device transfer (`allowBackup=false`, `dataExtractionRules`, `noBackupFilesDir`).
  No `INTERNET` permission.
- All credentials are discoverable. Re-registering the same RP + user handle replaces the old one.

AAGUID: `81ba41af-6f45-49e5-92fd-2b88324adbc2`, in `rust/src/webauthn.rs`.

## Key storage

StrongBox wraps each key under a root secret that never leaves the chip. keystore2 stores the
resulting blob on `/data` and hands it back to the chip for each signature.

```
            StrongBox                                  /data (keystore2)
         ┌──────────────────────┐
generate │ create key, wrap it  │ ── blob ──────────────▶ uid/alias → blob
         │ under root secret    │
         │                      │
sign     │ unwrap, check auth,  │ ◀── blob + data + auth token
         │ sign, discard        │ ── signature ─────────▶ app
         └──────────────────────┘
          root secret and plaintext key never leave the chip
```

- A blob is useless on any other device.
- Root on the same device can submit the blob, but the chip still requires a real user-auth token.
- Deletion removes the blob, but a `/data` copy taken earlier would still work on this chip.
  Whether apps can request rollback-resistant keys is unverified.
- Factory reset destroys the root secrets. Removing the screen lock invalidates auth-bound keys.
- On resume, the app drops records without a key and deletes keys without a record that are
  older than 1 h.

Lose the device, lose its passkeys. Keep a second authenticator on every account.

## Build

Requires JDK 17–25, SDK platform 37 with build-tools 37.0.0, NDK `30.0.16248370`, Rust targets
`aarch64-linux-android` and `x86_64-linux-android`, `cargo-ndk`, and `cargo-about`
(`cargo install --locked cargo-about --features cli`).

```sh
./gradlew installDebug
(cd rust && cargo test)
```

Each build downloads and embeds Google's attestation revocation list, and fails if it can't.

| Property | Effect |
|---|---|
| `hwbp.verifyChain=false` | No chain verification, for unpinned roots. The UI warns. |
| `hwbp.revocationStatus=<file>` | Use a local revocation list (offline builds). |
| `hwbp.cargo=<path>` | `cargo` location if not on the daemon's `PATH`. |

Enable the provider via **Enable provider** in the app. **Run self-test** checks a throwaway
StrongBox key against the full policy; debug builds log its chain under `HwbpSelfTest`.

R8 keep rules (`app/proguard-rules.pro`) preserve the JNI entry point and protobuf-lite fields.

## Limitations

- No Digital Asset Links check for native-app callers. RPs must verify the
  `android:apk-key-hash:` origin.
- The privileged-browser allowlist (`assets/privileged_browsers.json`) and the revocation list
  are only as fresh as their last update.
- Certificate validity periods are not checked.
- Doesn't protect against a compromised OS misusing a genuine StrongBox key.
- Only the `credProps` extension. No Signal API.
- No release signing config. Changing an installed app's signing key requires an uninstall,
  which destroys its passkeys.

## Why

Android has no built-in device-bound passkey provider. Google Password Manager, the default, syncs
passkeys to the user's Google account by default. They are end-to-end encrypted, but they end up
on every device signed in to that account. Third-party password managers keep passkeys in their
own encrypted vaults or files. None we checked (Bitwarden, KeePassDX) uses StrongBox or binds
passkeys to the device in any way.

Yet device binding was half the point of passkeys: a credential that can't be copied or
social-engineered out of someone, because using it requires the physical hardware it lives on.
That is how an EMV bank card, a SIM card or a European eID card (eIDAS) works. Passkeys on YubiKeys and other
external security keys already have this property. HWBP gives it to passkeys stored on the phone.

## License

Licensed under the [EUPL-1.2](LICENSE).
