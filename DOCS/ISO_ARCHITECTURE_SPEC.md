# ISO Engineering Specification: ZygiskCore Architecture & Traceability

**Standard Compliance**:
- **ISO/IEC/IEEE 12207:2017**: Systems and software engineering — Software life cycle processes.
- **ISO/IEC 25010:2011/2023**: Systems and software engineering — Systems and software Quality Requirements and Evaluation (SQuaRE) — System and software quality models.

---

## 1. System Scope & Objective

ZygiskCore is an autonomous Android framework augmentation module operating via Zygisk (Zygote In-Process Framework). It provides runtime bytecode manipulation and ART hook injection into `zygote` and `system_server` processes to remove package installation constraints without requiring LSPosed / Xposed runtime daemons.

---

## 2. Requirements Traceability Matrix (RTM)

| Requirement ID | Feature Specification | CorePatch Source Reference | ZygiskCore Target Implementation | Verification Method |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-CORE-001** | Signature Verification Bypass | `ApkSignatureVerifierHook.kt`, `StrictJarVerifierHook.kt`, `ApkSigningBlockUtilsHook.kt` | `CorePatchHooks.initApkSignatureVerifierHooks` | Automated Build & Lint Verification |
| **REQ-CORE-002** | Application Downgrade Allowance | `PackageManagerServiceHook.kt`, `PackageManagerServiceUtilsHook.kt` | `CorePatchHooks.initDowngradeHooks` | Automated Build & Version Guarding |
| **REQ-CORE-003** | KeySet & Digest Mismatch Toleration | `KeySetManagerServiceHook.kt`, `SigningDetailsHook.kt` | `CorePatchHooks.initKeySetHooks`, `initSigningDetailsHooks` | Automated Build & Stack Trace Inspection |
| **REQ-CORE-004** | Shared User ID Collision Resolution | `SharedUserSettingHook.kt`, `ReconcilePackageUtilsHook.kt` | `CorePatchHooks.initSharedUserHooks` | Automated Build & Reflection Guarding |
| **REQ-CORE-005** | Package Verification Agent Suppression | `VerificationParamsHook.kt`, `VerifyingSessionHook.kt`, `PackageManagerServiceHook.kt` | `CorePatchHooks.initVerificationAgentHooks` | Automated Build & Bitwise Flag Verification |
| **REQ-CORE-006** | System Hidden API Whitelist | `ApplicationInfoHook.kt` | `CorePatchHooks.initSystemAppAndResourceHooks` | Automated Build & Type Inspection |
| **REQ-CORE-007** | Resource ARSC Unaligned Bypass | `AssetManagerHook.kt` | `CorePatchHooks.initSystemAppAndResourceHooks` | Automated Build & API Guarding |
| **REQ-CORE-008** | OEM Restriction Bypass (Nothing OS) | `NtConfigListServiceImplHook.kt` | `CorePatchHooks.initSystemAppAndResourceHooks` | Automated Build & Class Resilience |
| **REQ-CORE-009** | Permission Matching Fallback | `InstallPackageHelperHook.kt`, `PackageManagerServiceHook.kt` | `CorePatchHooks.initPermissionAndSignatureMatchHooks` | Automated Build & Method Interception |
| **REQ-CORE-010** | Continuous Integration & Artifact Generation | GitHub Actions (`.github/workflows/build.yml`) | Automated Matrix Workflow on GitHub Actions | Continuous Pipeline Monitoring (`gh run watch`) |

---

## 3. Architecture & Reliability Design (ISO/IEC 25010)

1. **Fault Tolerance**:
   - Every hook leverages defensive reflection and exception absorption (`catch (Throwable)`). In the event an OEM vendor alters a proprietary or internal API name, system services continue executing without triggering uncaught exceptions or kernel panics.
2. **Compatibility Range**:
   - Supports Android API 26 (Android 8.0) up to API 36 (Android 16+). Conditional SDK version switching handles shifts across Android 10 (Q), Android 11 (R), Android 12 (S), Android 13 (Tiramisu), Android 14 (Upside Down Cake), Android 15 (Vanilla Ice Cream), and Android 16 (Baklava).
3. **Traceability & Maintainability**:
   - Modular hook separation ensures each functional concern is cleanly encapsulated within `CorePatchHooks.java` and `HookList.java`.
