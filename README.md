# ZygiskCore

<div align="center">
  <h1>ZygiskCore</h1>
  <p><strong>Zygisk-Based CorePatch & Package Manager Hook Module for Android</strong></p>
  <p>Seamlessly combines all functionality from <em>LSPosed CorePatch</em> and <em>PMPatch</em> into an autonomous, pure Zygisk module.</p>
</div>

---

## 📋 Overview

**ZygiskCore** combines the full suite of CorePatch features with PMPatch's native Zygisk runtime hooking architecture. It removes Android signature verification restrictions, allows app downgrades, enables shared user IDs across differing certificates, removes resource constraints, and disables verification agent barriers without requiring an Xposed framework or LSPosed manager.

### 🌟 Key Capabilities

1. **Signature Verification Bypass (Bypass Verification)**:
   - Bypasses signature checking in `ApkSignatureVerifier` (`verifyV1Signature`) with fallbacks.
   - Disables minimum signature scheme restrictions (Android 11+ / API 30+).
   - Bypasses `ApkSigningBlockUtils` digest and integrity checks.
   - Bypasses `StrictJarVerifier` message digest, certificate chains, and rollback protections.
   - Hooked `java.security.Signature` and `OpenSSLSignature.engineVerify`.

2. **Application Downgrade Bypass (Bypass Downgrade)**:
   - Allows installing older versions over newer ones without data wipe.
   - Handles `PackageManagerService.checkDowngrade` and `PackageManagerServiceUtils.checkDowngrade`.
   - Special compatibility handling for Flyme OS and Android 8–16+.

3. **Digest & Mismatch Tolerance (Bypass Digest)**:
   - Allows updating apps when signatures differ without conflicting with system signature privileges.
   - Hooks `KeySetManagerService.shouldCheckUpgradeKeySetLocked` and `checkUpgradeKeySetLocked`.
   - Bypasses `SigningDetails.checkCapability` and `checkCapabilityRecover`.
   - Enables `SigningDetails.signaturesMatchExactly`.

4. **Shared User ID Bypass (Bypass Shared User)**:
   - Enables apps signed with different keys to use the same `sharedUserId`.
   - Dynamic reconciliation via `SharedUserSetting` and `ReconcilePackageUtils`.

5. **Verification Agent & Play Protect Bypass**:
   - Disables installation verification blocking via `PackageManagerService.isVerificationEnabled`.
   - Bypasses `VerificationParams.isVerificationEnabled` (API 33).
   - Sets `INSTALL_DISABLE_VERIFICATION` in `VerifyingSession.handleStartVerify` (API 34+).

6. **System Enhancements & OEM Compatibility**:
   - Grants hidden API access to system applications (`ApplicationInfo.isPackageWhitelistedForHiddenApis`).
   - Bypasses uncompressed/unaligned `resources.arsc` restrictions (`AssetManager.containsAllocatedTable`).
   - Bypasses Nothing OS app installation/launch blacklist (`NtConfigListServiceImpl`).

---

## 🛠️ Technical Specifications & Compatibility

- **Android Versions Supported**: Android 8.0 (Oreo / API 26) through Android 16+ (API 36).
- **Zygisk Frameworks Supported**:
  - Magisk (v24.0+) with Zygisk enabled.
  - KernelSU (with Zygisk Next).
  - APatch (with Zygisk Next).
- **Engineering Standard**: Engineered and documented in accordance with ISO/IEC/IEEE 12207:2017 & ISO/IEC 25010 standards.

---

## 📦 Building

To build the flashable Magisk/KernelSU module locally:

```bash
./gradlew assembleRelease
```

Generated flashable zips will be located in:
`module/build/outputs/magisk/full/release/ZygiskCore.zip`

---

## 📄 License & Credits

- Based on [LSPosed/CorePatch](https://github.com/LSPosed/CorePatch) by LSPosed team.
- Built on top of [PMPatch](https://github.com/vova7878-modules/PMPatch) and [AndroidVMTools](https://github.com/vova7878/AndroidVMTools) by v7878.
- Maintained by [faisalwildanhabibi](https://github.com/faisalwildanhabibi).
