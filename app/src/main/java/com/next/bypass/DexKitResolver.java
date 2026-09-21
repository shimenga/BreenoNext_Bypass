package com.next.bypass;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.enums.StringMatchType;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.ClassData;
import org.luckypray.dexkit.result.ClassDataList;
import org.luckypray.dexkit.result.FieldData;
import org.luckypray.dexkit.result.MethodData;
import org.luckypray.dexkit.result.MethodDataList;

import java.util.Arrays;
import java.util.Collections;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Locates the beta-verification classes of newer (170073+) BreenoNext builds at
 * runtime with DexKit.
 *
 * Every release renames its obfuscated classes, but the string literals inside
 * the verification state machine are stable. Each lookup below anchors on a
 * literal that occurs in exactly one class of interest, and all searches are
 * confined to the {@code com.oplus.claw.welcome} package.
 *
 * Reference layout for 170073 (from static analysis of classes5.dex):
 *
 *   w2    LlmAccessGate          gate singleton; static AtomicReference b, AtomicLong c
 *                                e() "DUID access gate granted", d(String) "...denied: "
 *   h2    BetaDeviceAccessPolicy static AtomicReference b; "device access check source="
 *                                c(String, Boolean, cr.a, kotlinx.coroutines.w, ContinuationImpl)
 *   t     access-state cache     t.b(Context) -> i2(long, String, String, boolean)
 *   z3    boot/integrity probe   z3.i(Context), "ro.boot.flash.locked"
 *   ei/b  root probe             ei.b.f() invoked from z3.i
 *   q1    AccessViewModel        g(String, ContinuationImpl) integrity,
 *                                i(boolean, boolean, String, boolean, ContinuationImpl) probe
 *   j1    Idle state             singleton field a of its own type
 *   t2    Granted(version)       constructor taking a single long
 *   BetaDeviceAccessPolicy$DeviceVerdict  enum Pending/Trusted/Compromised
 */
final class DexKitResolver {

    private static final String TAG = "BreenoNextBypass";
    /** All the interesting classes live in this package. */
    private static final String PKG = "com.oplus.claw.welcome";

    /**
     * DexKit does not load its own native library; doing it here (once, at class
     * initialisation) keeps the failure contained to the resolver instead of
     * taking down the whole hook entry point.
     */
    private static boolean nativeLoaded;
    private static String nativeError;

    static {
        try {
            System.loadLibrary("dexkit");
            nativeLoaded = true;
        } catch (Throwable t) {
            nativeError = t.toString();
        }
    }

    // Stable string literals (verified unique inside PKG in both APKs analysed).
    private static final String S_GATE_GRANT = "DUID access gate granted";
    private static final String S_POLICY = "device access check source=";
    private static final String S_VERDICT = "Compromised";
    private static final String S_BOOT = "ro.boot.flash.locked";
    private static final String S_GRANTED_STATE = "Granted(version=";
    private static final String S_IDLE = "Idle";
    private static final String S_PROBE_START = "access_onboarding step=probe_start source=";
    private static final String S_DECISION_CACHE = "access_dec" + "ision_duid";

    private DexKitResolver() {}

    static HookEntry.Resolved resolve(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!nativeLoaded) {
            XposedBridge.log(TAG + ": libdexkit not loaded — " + nativeError);
            return null;
        }
        String apk = lpparam.appInfo.sourceDir;
        HookEntry.Resolved out = new HookEntry.Resolved();
        DexKitBridge bridge = DexKitBridge.create(apk);
        try {
            // --- gate singleton (LlmAccessGate) + the Granted state it installs ---
            MethodData gateMethod = findMethodUsing(bridge, S_GATE_GRANT);
            out.gate = ownerClass(bridge, gateMethod);
            if (out.gate != null) {
                out.grantedState = findStateClass(bridge, S_GRANTED_STATE);
            }

            // --- BetaDeviceAccessPolicy holder (AtomicReference + 5-arg check) ---
            MethodData policyMethod = findMethodUsing(bridge, S_POLICY);
            out.policyHolder = ownerClass(bridge, policyMethod);
            if (policyMethod != null) {
                out.betaVerifyParams = paramTypeNames(policyMethod);
            }
            out.verdictEnum = findVerdictEnum(bridge);

            // --- bootloader/integrity probe and the root probe it invokes ---
            MethodData bootMethod = findMethodUsing(bridge, S_BOOT);
            out.bootCheck = ownerClass(bridge, bootMethod);
            out.rootCheck = firstAppInvoke(bootMethod);
            if (out.rootCheck != null) {
                out.rootCheckMethod = findBooleanNoArgMethod(bridge, out.rootCheck);
            }

            // --- AccessViewModel, and the Idle state it short-circuits to ---
            MethodData probeMethod = findMethodUsing(bridge, S_PROBE_START);
            out.viewModel = ownerClass(bridge, probeMethod);
            out.idleState = findIdleState(bridge);
            if (out.idleState != null) {
                out.idleField = singletonField(bridge, out.idleState);
            }

            // --- encrypted cached decision: t.b(Context) -> i2(long,String,String,boolean) ---
            out.cachedDecisionAccessor = findDecisionAccessor(bridge);
            if (out.cachedDecisionAccessor != null) {
                out.cachedDecision = decisionTypeOf(bridge, out.cachedDecisionAccessor);
            }

            // Every one of these suspend functions is Kotlin, so the trailing
            // continuation parameter is the JVM base type.
            out.continuation = "kotlin.coroutines.jvm.internal.ContinuationImpl";
        } finally {
            bridge.close();
        }

        XposedBridge.log(TAG + ": DexKit resolved"
                + " gate=" + out.gate
                + " granted=" + out.grantedState
                + " policy=" + out.policyHolder
                + " verdict=" + out.verdictEnum
                + " boot=" + out.bootCheck
                + " root=" + out.rootCheck + "#" + out.rootCheckMethod
                + " vm=" + out.viewModel
                + " idle=" + out.idleState + "#" + out.idleField
                + " cache=" + out.cachedDecisionAccessor + "->" + out.cachedDecision);
        return out;
    }

    // ==================== lookups ====================

    /** First method in the package whose body references the literal. */
    private static MethodData findMethodUsing(DexKitBridge bridge, String literal) {
        MethodDataList list = bridge.findMethod(FindMethod.create()
                .searchPackages(PKG)
                .matcher(MethodMatcher.create().usingStrings(
                        Collections.singletonList(literal), StringMatchType.Contains)));
        for (MethodData m : list) {
            if (!m.getDeclaredClassName().contains("$")) return m;
        }
        return list.firstOrNull();
    }

    /** Declaring class of a method, skipping Kotlin lambdas (name contains '$'). */
    private static String ownerClass(DexKitBridge bridge, MethodData method) {
        if (method == null) return null;
        String declared = method.getDeclaredClassName();
        if (declared == null || declared.contains("$")) return null;
        if (!declared.startsWith(PKG)) return null;
        return declared;
    }

    /** Enum whose constants include Pending/Trusted/Compromised. */
    private static String findVerdictEnum(DexKitBridge bridge) {
        ClassDataList list = bridge.findClass(FindClass.create()
                .searchPackages(PKG)
                .matcher(ClassMatcher.create().usingStrings(
                        Arrays.asList(S_VERDICT, "Trusted", "Pending"))));
        for (ClassData c : list) {
            if (c.getName().endsWith("DeviceVerdict")) return c.getName();
        }
        for (ClassData c : list) {
            if (!c.getName().contains("$")) return c.getName();
        }
        ClassData c = list.firstOrNull();
        return c != null ? c.getName() : null;
    }

    /**
     * The Granted state singleton: a top-level class whose class body references
     * the marker and that has a single-long constructor.
     */
    private static String findStateClass(DexKitBridge bridge, String marker) {
        ClassDataList list = bridge.findClass(FindClass.create()
                .searchPackages(PKG)
                .matcher(ClassMatcher.create().usingStrings(
                        Collections.singletonList(marker))));
        for (ClassData c : list) {
            if (c.getName().contains("$")) continue;
            for (MethodData m : c.getMethods()) {
                if (!"<init>".equals(m.getMethodName())) continue;
                ClassDataList p = m.getParamTypes();
                if (p.size() == 1 && "long".equals(p.get(0).getName())) return c.getName();
            }
        }
        return null;
    }

    /** The Idle state: references the literal and holds a singleton of itself. */
    private static String findIdleState(DexKitBridge bridge) {
        ClassDataList list = bridge.findClass(FindClass.create()
                .searchPackages(PKG)
                .matcher(ClassMatcher.create().usingStrings(
                        Collections.singletonList(S_IDLE))));
        for (ClassData c : list) {
            if (c.getName().contains("$")) continue;
            for (FieldData f : c.getFields()) {
                if (c.getName().equals(f.getTypeName())) return c.getName();
            }
        }
        return null;
    }

    /** Singleton static field whose type is the declaring class itself. */
    private static String singletonField(DexKitBridge bridge, String className) {
        ClassDataList list = bridge.findClass(FindClass.create()
                .searchPackages(PKG)
                .matcher(ClassMatcher.create().className(className)));
        for (ClassData c : list) {
            for (FieldData f : c.getFields()) {
                if (className.equals(f.getTypeName())) return f.getName();
            }
        }
        return null;
    }

    /** First application-owned, non-constructor type invoked from the method. */
    private static String firstAppInvoke(MethodData method) {
        if (method == null) return null;
        for (MethodData invoked : method.getInvokes()) {
            if (invoked.isConstructor()) continue;
            String owner = invoked.getDeclaredClassName();
            if (owner == null) continue;
            if (owner.startsWith("java.") || owner.startsWith("javax.")
                    || owner.startsWith("kotlin.") || owner.startsWith("android.")
                    || owner.startsWith("androidx.") || owner.startsWith("kotlinx.")) {
                continue;
            }
            return owner;
        }
        return null;
    }

    /** First no-arg boolean method of the given class (may live outside PKG). */
    private static String findBooleanNoArgMethod(DexKitBridge bridge, String className) {
        if (className == null) return null;
        ClassDataList list = bridge.findClass(FindClass.create()
                .matcher(ClassMatcher.create().className(className)));
        for (ClassData c : list) {
            for (MethodData m : c.getMethods()) {
                if (m.getParamTypes().size() == 0 && "boolean".equals(m.getReturnTypeName())) {
                    return m.getMethodName();
                }
            }
        }
        return null;
    }

    /** Fully qualified parameter type names, primitives kept as names. */
    private static Object[] paramTypeNames(MethodData method) {
        ClassDataList p = method.getParamTypes();
        Object[] out = new Object[p.size()];
        for (int i = 0; i < p.size(); i++) out[i] = p.get(i).getName();
        return out;
    }

    /**
     * The encrypted-cache accessor: the class that both references the decision
     * preference key and exposes a {@code b(Context)} returning the decision
     * holder. Several classes touch the same preference, so the return type is
     * what identifies the right one.
     */
    private static String findDecisionAccessor(DexKitBridge bridge) {
        MethodDataList list = bridge.findMethod(FindMethod.create()
                .searchPackages(PKG)
                .matcher(MethodMatcher.create().usingStrings(
                        Collections.singletonList(S_DECISION_CACHE), StringMatchType.Contains)));
        for (MethodData m : list) {
            String owner = m.getDeclaredClassName();
            if (owner == null || owner.contains("$")) continue;
            if (decisionTypeOf(bridge, owner) != null) return owner;
        }
        return null;
    }

    /**
     * Type the cached-decision accessor returns. Its b(Context) method is the
     * only one taking a Context, and it yields the holder whose constructor is
     * (long, String, String, boolean).
     */
    private static String decisionTypeOf(DexKitBridge bridge, String accessorClass) {
        ClassDataList list = bridge.findClass(FindClass.create()
                .searchPackages(PKG)
                .matcher(ClassMatcher.create().className(accessorClass)));
        for (ClassData c : list) {
            for (MethodData m : c.getMethods()) {
                if (!"b".equals(m.getMethodName())) continue;
                ClassDataList p = m.getParamTypes();
                if (p.size() != 1 || !"android.content.Context".equals(p.get(0).getName())) continue;
                String ret = m.getReturnTypeName();
                if (ret == null || !ret.startsWith(PKG)) continue;
                if (hasLongStringStringBoolCtor(bridge, ret)) return ret;
            }
        }
        return null;
    }

    /** True when the class exposes a (long, String, String, boolean) constructor. */
    private static boolean hasLongStringStringBoolCtor(DexKitBridge bridge, String className) {
        ClassDataList list = bridge.findClass(FindClass.create()
                .searchPackages(PKG)
                .matcher(ClassMatcher.create().className(className)));
        for (ClassData c : list) {
            for (MethodData m : c.getMethods()) {
                if (!"<init>".equals(m.getMethodName())) continue;
                ClassDataList p = m.getParamTypes();
                if (p.size() != 4) continue;
                if (!"long".equals(p.get(0).getName())) continue;
                if (!"java.lang.String".equals(p.get(1).getName())) continue;
                if (!"java.lang.String".equals(p.get(2).getName())) continue;
                if (!"boolean".equals(p.get(3).getName())) continue;
                return true;
            }
        }
        return false;
    }
}
