package com.v7878.hooks.pmpatch;

import static android.os.Build.VERSION.SDK_INT;
import static com.v7878.hooks.pmpatch.Main.TAG;
import static com.v7878.unsafe.invoke.EmulatedStackFrame.RETURN_VALUE_IDX;

import android.content.pm.ApplicationInfo;
import android.content.pm.Signature;
import android.util.Log;

import com.v7878.unsafe.invoke.Transformers;
import com.v7878.vmtools.HookTransformer;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;

/**
 * CorePatchHooks implements all functionality ported from LSPosed/CorePatch
 * adapting them to the Zygisk-based ART hooking architecture of PMPatch.
 */
public class CorePatchHooks {

    private static boolean stackContains(String... methodNames) {
        StackTraceElement[] trace = Thread.currentThread().getStackTrace();
        for (StackTraceElement elem : trace) {
            String name = elem.getMethodName();
            for (String target : methodNames) {
                if (target.equals(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void initAll(BulkHooker hooks, ClassLoader loader) {
        initDowngradeHooks(hooks);
        initApkSignatureVerifierHooks(hooks, loader);
        initKeySetHooks(hooks);
        initSigningDetailsHooks(hooks);
        initSharedUserHooks(hooks, loader);
        initVerificationAgentHooks(hooks);
        initSystemAppAndResourceHooks(hooks);
        initPermissionAndSignatureMatchHooks(hooks);
    }

    /**
     * 1. Bypass Downgrade:
     * Disables package downgrade prevention across Android 8 through 16+,
     * including Flyme OS special handling and resetting version codes on Android <= 10.
     */
    public static void initDowngradeHooks(BulkHooker hooks) {
        HookTransformer downgradeHook = (original, frame) -> {
            if (SDK_INT <= 29) {
                try {
                    Object beforePkg = frame.accessor().getReference(0);
                    if (beforePkg != null) {
                        Field fVersion = beforePkg.getClass().getDeclaredField("mVersionCode");
                        fVersion.setAccessible(true);
                        fVersion.setInt(beforePkg, 0);

                        Field fVersionMajor = beforePkg.getClass().getDeclaredField("mVersionCodeMajor");
                        fVersionMajor.setAccessible(true);
                        fVersionMajor.setInt(beforePkg, 0);
                    }
                } catch (Throwable ignored) {
                }
            }
            if (frame.type().returnType() == boolean.class) {
                frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
            }
        };

        if (SDK_INT <= 32) {
            hooks.addAll(downgradeHook, "com.android.server.pm.PackageManagerService", "checkDowngrade");
        } else {
            hooks.addAll(HTF.NOP, "com.android.server.pm.PackageManagerServiceUtils", "checkDowngrade");
        }
    }

    /**
     * 2. APK Signature Verifier & Signing Block & StrictJarVerifier Hooks:
     * Allows installing APKs with mismatched, modified, or v1-only signatures,
     * disabling rollback protections and minimum signature scheme requirements.
     */
    public static void initApkSignatureVerifierHooks(BulkHooker hooks, ClassLoader loader) {
        // Minimum signature scheme requirement bypass (API 30+)
        if (SDK_INT >= 30) {
            hooks.addAll(HTF.constant(0), "android.util.apk.ApkSignatureVerifier", "getMinimumSignatureSchemeVersionForTargetSdk");
            hooks.addAll(HTF.constant(0), "com.android.apksig.ApkVerifier", "getMinimumSignatureSchemeVersionForTargetSdk");
        }

        if (SDK_INT >= 33) {
            hooks.addAll(HTF.NOP, "com.android.server.pm.ScanPackageUtils", "assertMinSignatureSchemeIsValid");
        }

        // ApkSigningBlockUtils hooks
        HookTransformer verityDigestHook = (original, frame) -> {
            byte[] expected = frame.accessor().getReference(0);
            if (expected != null && expected.length > 32) {
                byte[] truncated = Arrays.copyOfRange(expected, 0, 32);
                frame.accessor().setValue(RETURN_VALUE_IDX, truncated);
            } else {
                frame.accessor().setValue(RETURN_VALUE_IDX, expected);
            }
        };
        hooks.addAll(verityDigestHook, "android.util.apk.ApkSigningBlockUtils", "parseVerityDigestAndVerifySourceLength");
        hooks.addAll(HTF.NOP, "android.util.apk.ApkSigningBlockUtils", "verifyIntegrityForVerityBasedAlgorithm");

        // StrictJarVerifier hooks
        hooks.addAll(HTF.TRUE, "android.util.jar.StrictJarVerifier", "verifyMessageDigest");
        hooks.addAll(HTF.TRUE, "android.util.jar.StrictJarVerifier", "verify");

        // Verify V1 Signature fallback
        HookTransformer verifyV1Hook = (original, frame) -> {
            try {
                Transformers.invokeExact(original, frame);
            } catch (Throwable t) {
                Object fallback = createFallbackSigningDetails(loader);
                if (fallback != null) {
                    frame.accessor().setValue(RETURN_VALUE_IDX, fallback);
                    return;
                }
                throw t;
            }

            Object result = frame.accessor().getValue(RETURN_VALUE_IDX);
            if (result != null && isParseResultError(result)) {
                Object fallback = createFallbackSigningDetails(loader);
                if (fallback != null) {
                    Object success = wrapParseResultSuccess(result, fallback);
                    if (success != null) {
                        frame.accessor().setValue(RETURN_VALUE_IDX, success);
                    }
                }
            }
        };

        hooks.addAll(verifyV1Hook, "android.util.apk.ApkSignatureVerifier", "verifyV1Signature");
    }

    private static Object createFallbackSigningDetails(ClassLoader loader) {
        try {
            String className = SDK_INT >= 33 ? "android.content.pm.SigningDetails"
                    : "android.content.pm.PackageParser$SigningDetails";
            Class<?> clazz = Class.forName(className, true, loader);
            Constructor<?> ctor = null;
            for (Constructor<?> c : clazz.getDeclaredConstructors()) {
                if (c.getParameterCount() == 2 &&
                        c.getParameterTypes()[0].isArray() &&
                        c.getParameterTypes()[1] == int.class) {
                    ctor = c;
                    break;
                }
            }
            if (ctor == null) return null;
            ctor.setAccessible(true);
            Signature[] sigs = new Signature[]{new Signature(Constant.SIGNATURE)};
            Object signingDetails = ctor.newInstance(sigs, 1);

            // Check if SigningDetailsWithDigests is required
            try {
                Class<?> withDigestsClass = Class.forName("android.util.apk.ApkSignatureVerifier$SigningDetailsWithDigests", true, loader);
                Constructor<?> withDigestsCtor = withDigestsClass.getDeclaredConstructor(clazz, Map.class);
                withDigestsCtor.setAccessible(true);
                return withDigestsCtor.newInstance(signingDetails, null);
            } catch (ClassNotFoundException ignored) {
                return signingDetails;
            }
        } catch (Throwable t) {
            Log.e(TAG, "createFallbackSigningDetails error: " + t.getMessage());
            return null;
        }
    }

    private static boolean isParseResultError(Object result) {
        try {
            Method isError = result.getClass().getMethod("isError");
            return Boolean.TRUE.equals(isError.invoke(result));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Object wrapParseResultSuccess(Object parseInputOrResult, Object value) {
        try {
            // Check if parseInput has success(result)
            Method reset = parseInputOrResult.getClass().getMethod("reset");
            Method success = parseInputOrResult.getClass().getMethod("success", Object.class);
            reset.invoke(parseInputOrResult);
            return success.invoke(parseInputOrResult, value);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * 3. KeySet Manager Service Hooks:
     * Bypasses upgrade key set checks when installing/updating applications.
     */
    public static void initKeySetHooks(BulkHooker hooks) {
        HookTransformer shouldCheckKeySet = (original, frame) -> {
            if (stackContains("preparePackage", "reconcileInstallPackages", "preparePackageLI", "installPackageLI")) {
                frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
            } else {
                Transformers.invokeExact(original, frame);
            }
        };

        hooks.addAll(shouldCheckKeySet, "com.android.server.pm.KeySetManagerService", "shouldCheckUpgradeKeySetLocked");
        hooks.addAll(HTF.TRUE, "com.android.server.pm.KeySetManagerService", "checkUpgradeKeySetLocked");
    }

    /**
     * 4. SigningDetails Capability & Compatibility Hooks:
     * Handles capability checks for app updates while preserving security for PERMISSION (4) and AUTH (16).
     */
    public static void initSigningDetailsHooks(BulkHooker hooks) {
        HookTransformer checkCapabilityHook = (original, frame) -> {
            int flags = frame.accessor().getInt(1);
            if (flags != 4 && flags != 16) {
                frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
            } else {
                Transformers.invokeExact(original, frame);
            }
        };

        String signingClass = SDK_INT >= 33 ? "android.content.pm.SigningDetails"
                : "android.content.pm.PackageParser$SigningDetails";

        hooks.addAll(checkCapabilityHook, signingClass, "checkCapability");
        hooks.addAll(checkCapabilityHook, signingClass, "checkCapabilityRecover");

        if (SDK_INT >= 30) {
            HookTransformer hasCommonAncestorHook = (original, frame) -> {
                if (stackContains("verifySignatures")) {
                    frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
                } else {
                    Transformers.invokeExact(original, frame);
                }
            };
            hooks.addAll(hasCommonAncestorHook, signingClass, "hasCommonAncestor");
        }

        hooks.addAll(HTF.TRUE, signingClass, "signaturesMatchExactly");
    }

    /**
     * 5. SharedUserSetting & ReconcilePackageUtils Hooks:
     * Allows applications with different signatures to share user ID without conflicts.
     */
    public static void initSharedUserHooks(BulkHooker hooks, ClassLoader loader) {
        if (SDK_INT >= 33) {
            try {
                Class<?> clazz = Class.forName("com.android.server.pm.ReconcilePackageUtils", true, loader);
                Field field = clazz.getDeclaredField("ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS");
                field.setAccessible(true);
                field.setBoolean(null, true);
                Log.i(TAG, "Enabled ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS");
            } catch (Throwable t) {
                Log.d(TAG, "ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS not found or not modifiable: " + t.getMessage());
            }
        }
    }

    /**
     * 6. Disable Verification Agent / Play Protect:
     * Disables package verification agent prompts and delays during package installation.
     */
    public static void initVerificationAgentHooks(BulkHooker hooks) {
        hooks.addAll(HTF.FALSE, "com.android.server.pm.PackageManagerService", "isVerificationEnabled");

        if (SDK_INT == 33) {
            hooks.addAll(HTF.FALSE, "com.android.server.pm.VerificationParams", "isVerificationEnabled");
        }

        if (SDK_INT >= 34) {
            hooks.addAll(HTF.FALSE, "com.android.server.pm.VerifyingSession", "isAdbVerificationEnabled");

            HookTransformer startVerifyHook = (original, frame) -> {
                try {
                    Object session = frame.accessor().getReference(0);
                    if (session != null) {
                        Field flagsField = session.getClass().getDeclaredField("mInstallFlags");
                        flagsField.setAccessible(true);
                        int currentFlags = flagsField.getInt(session);
                        flagsField.setInt(session, currentFlags | 0x00080000 /* INSTALL_DISABLE_VERIFICATION */);
                    }
                } catch (Throwable ignored) {
                }
                Transformers.invokeExact(original, frame);
            };
            hooks.addAll(startVerifyHook, "com.android.server.pm.VerifyingSession", "handleStartVerify");
        }
    }

    /**
     * 7. System App Hidden APIs & Resource ARSC Restrictions & OEM Bypasses:
     * - Grants access to hidden APIs for system apps.
     * - Allows unaligned or compressed resources.arsc (AssetManager.containsAllocatedTable).
     * - Bypasses Nothing OS app install and start restrictions.
     */
    public static void initSystemAppAndResourceHooks(BulkHooker hooks) {
        HookTransformer hiddenApiHook = (original, frame) -> {
            Object thiz = frame.accessor().getReference(0);
            if (thiz instanceof ApplicationInfo appInfo) {
                if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0 ||
                        (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                    frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
                    return;
                }
            }
            Transformers.invokeExact(original, frame);
        };
        hooks.addAll(hiddenApiHook, "android.content.pm.ApplicationInfo", "isPackageWhitelistedForHiddenApis");

        if (SDK_INT >= 30) {
            hooks.addAll(HTF.FALSE, "android.content.res.AssetManager", "containsAllocatedTable");
        }

        // Nothing OS installation & launch blacklist bypass
        hooks.addAll(HTF.FALSE, "com.nothing.server.ex.NtConfigListServiceImpl", "isInstallingAppForbidden");
        hooks.addAll(HTF.FALSE, "com.nothing.server.ex.NtConfigListServiceImpl", "isStartingAppForbidden");
    }

    /**
     * 8. Permission & Signature Match Hooks:
     * Ensures same package name installations are granted permissions even with different signatures.
     */
    public static void initPermissionAndSignatureMatchHooks(BulkHooker hooks) {
        HookTransformer doesMatchHook = (original, frame) -> {
            Transformers.invokeExact(original, frame);
            boolean matched = frame.accessor().getBoolean(RETURN_VALUE_IDX);
            if (!matched) {
                try {
                    Object arg0 = frame.accessor().getReference(0);
                    Object arg1 = frame.accessor().getReference(1);
                    if (arg0 instanceof String pkg0 && arg1 != null) {
                        Method getPackageName = arg1.getClass().getMethod("getPackageName");
                        String pkg1 = (String) getPackageName.invoke(arg1);
                        if (pkg0.equals(pkg1)) {
                            frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        };

        if (SDK_INT == 31 || SDK_INT == 32) {
            hooks.addAll(doesMatchHook, "com.android.server.pm.PackageManagerService", "doesSignatureMatchForPermissions");
        } else if (SDK_INT >= 33) {
            hooks.addAll(doesMatchHook, "com.android.server.pm.InstallPackageHelper", "doesSignatureMatchForPermissions");
        }
    }
}
