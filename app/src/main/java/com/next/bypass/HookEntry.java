package com.next.bypass;

import android.content.Context;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicReference;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Xposed module to bypass verification checks in BreenoNext (com.oplus.claw).
 *
 * Supported versions: 170066, 170068, 170069, 170070, 170071, 170072, 170073+
 *
 * Obfuscated class names change in every release. Up to 170072 the names are
 * hard-coded per version; from 170073 onwards the relevant classes are located
 * dynamically at runtime with DexKit by matching on string literals that the
 * obfuscator does not rename.
 */
public class HookEntry implements IXposedHookLoadPackage {

    private static final String TARGET = "com.oplus.claw";
    private static final String TAG = "BreenoNextBypass";
    private static final String PKG = "com.oplus.claw.welcome.";

    /** Newest version handled by the hard-coded class table. */
    private static final int V170073 = 170073;

    private ClassLoader cl;
    private int version;

    // Version identifiers (higher number = newer version)
    private static final int V170066 = 170066;
    private static final int V170068 = 170068;
    private static final int V170069 = 170069;
    private static final int V170070 = 170070;
    private static final int V170071 = 170071;
    private static final int V170072 = 170072;

    /** Populated by DexKit for versions whose names are not hard-coded. */
    private Resolved r;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals(TARGET)) return;
        cl = lpparam.classLoader;

        version = detectVersion();
        if (version == 0) {
            XposedBridge.log(TAG + ": Unknown version, skipping");
            return;
        }
        XposedBridge.log(TAG + ": Loaded into " + TARGET + " v" + version);

        if (version >= V170073) {
            // No stable names to hard-code: resolve everything with DexKit.
            try {
                r = DexKitResolver.resolve(lpparam);
            } catch (Throwable e) {
                XposedBridge.log(TAG + ": DexKit resolve failed — " + e);
                r = null;
            }
            if (r == null || r.gate == null) {
                XposedBridge.log(TAG + ": DexKit resolution incomplete, aborting");
                return;
            }
        }

        hookAccessGate();
        hookPolicyState();
        hookRootDetection();
        hookBetaVerification();
        hookBootloaderCheck();
        hookViewModelRootCheck();
        hookPrecheckBypass();
        hookCachedDecision();
    }

    /**
     * Detect app version.
     *
     * 170073 renamed every controller class but left a handful of its own
     * symbols readable (AccessFailReason, BetaDeviceAccessPolicy$DeviceVerdict,
     * ...). Those appear in no earlier build, so they identify 170073+.
     * Older builds are recognised by their gate controller class.
     */
    private int detectVersion() {
        if (classExists("com.oplus.claw.welcome.BetaDeviceAccessPolicy$DeviceVerdict")
                || classExists("com.oplus.claw.welcome.AccessFailReason")
                || classExists("com.oplus.claw.welcome.AccessSuccessReason")) {
            return V170073;
        }
        // 170071: g3 is the controller
        if (hasMethod("com.oplus.claw.welcome.g3", "d", String.class)) return V170071;
        // 170070: n3 is the controller
        if (hasMethod("com.oplus.claw.welcome.n3", "d", String.class)) return V170070;
        // k3 is the controller in 170069 and 170072
        if (hasMethod("com.oplus.claw.welcome.k3", "d", String.class)) {
            // t30.a exists only in 170072 → 170072; else 170069
            if (classExists("t30.a")) return V170072;
            return V170069;
        }
        // 170066/170068: c3 is the controller
        if (hasMethod("com.oplus.claw.welcome.c3", "d", String.class)) {
            if (classExists("com.oplus.claw.welcome.a0")) return V170066;
            return V170068;
        }
        return 0;
    }

    /**
     * Check if a class has a specific method with given parameter types.
     */
    private boolean hasMethod(String className, String methodName, Class<?>... paramTypes) {
        try {
            Class<?> cls = XposedHelpers.findClass(className, cl);
            cls.getDeclaredMethod(methodName, paramTypes);
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    // ==================== Version-specific class getters ====================

    /** Accepts either a bare name or a fully qualified one. */
    private static String fq(String name) {
        if (name == null) return null;
        return name.indexOf('.') >= 0 ? name : PKG + name;
    }

    /**
     * Gate controller class that manages access state.
     * - 170066/170068: c3
     * - 170069: k3
     * - 170070: n3
     * - 170071: g3
     * - 170072: k3
     * - 170073+: resolved by DexKit
     */
    private String gateControllerClass() {
        if (version >= V170073) return r != null ? r.gate : null;
        if (version <= V170068) return "c3";
        if (version == V170069) return "k3";
        if (version == V170070) return "n3";
        if (version == V170071) return "g3";
        return "k3";
    }

    /**
     * Granted/Ready state class with a long-only constructor.
     * - 170066/170068: z2
     * - 170069: h2(i2, Long)
     * - 170070: k2(l2, Long)
     * - 170071: d3
     * - 170072: h3
     * - 170073+: resolved by DexKit
     */
    private String grantedStateClass() {
        if (version >= V170073) return r != null ? r.grantedState : null;
        if (version <= V170068) return "z2";
        if (version == V170069) return "h2";
        if (version == V170070) return "k2";
        if (version == V170071) return "d3";
        return "h3";
    }

    /**
     * Policy state holder class with AtomicReference field 'b'.
     * - 170066/170068: k4
     * - 170069: n2
     * - 170070: q2
     * - 170071: k2
     * - 170072: n2
     * - 170073+: resolved by DexKit
     */
    private String policyHolderClass() {
        if (version >= V170073) return r != null ? r.policyHolder : null;
        if (version <= V170068) return "k4";
        if (version == V170069) return "n2";
        if (version == V170070) return "q2";
        if (version == V170071) return "k2";
        return "n2";
    }

    /**
     * Verdict enum class (Pending/Trusted/Compromised).
     * - 170066/170068: h4
     * - 170069: k2
     * - 170070: n2
     * - 170071: h2
     * - 170072: k2
     * - 170073+: resolved by DexKit
     */
    private String verdictEnumClass() {
        if (version >= V170073) return r != null ? r.verdictEnum : null;
        if (version <= V170068) return "h4";
        if (version == V170069) return "k2";
        if (version == V170070) return "n2";
        if (version == V170071) return "h2";
        return "k2";
    }

    /**
     * Bootloader/root check class with method 'i(Context)'.
     * - 170066/170068: s4
     * - 170069: w4
     * - 170070: z4
     * - 170071: s4
     * - 170072: w4
     * - 170073+: resolved by DexKit
     */
    private String bootCheckClass() {
        if (version >= V170073) return r != null ? r.bootCheck : null;
        if (version <= V170068) return "s4";
        if (version == V170069) return "w4";
        if (version == V170070) return "z4";
        if (version == V170071) return "s4";
        return "w4";
    }

    /**
     * ViewModel class hosting the integrity check and the probe.
     * - 170066/170068: m1   (f/h)
     * - 170069: n1
     * - 170070: q1
     * - 170071: k1
     * - 170072: o1
     * - 170073+: resolved by DexKit (g/i)
     */
    private String viewModelClass() {
        if (version >= V170073) return r != null ? r.viewModel : null;
        if (version <= V170068) return "m1";
        if (version == V170069) return "n1";
        if (version == V170070) return "q1";
        if (version == V170071) return "k1";
        return "o1";
    }

    /**
     * Coroutine continuation parameter type of the ViewModel methods.
     * - 170066/170068: x10.c
     * - 170069: e20.c
     * - 170070: h20.c
     * - 170071: y20.c
     * - 170072: k30.c
     * - 170073+: kotlin.coroutines.jvm.internal.ContinuationImpl
     */
    private String continuationClass() {
        if (version >= V170073) return r != null ? r.continuation : null;
        if (version <= V170068) return "x10.c";
        if (version == V170069) return "e20.c";
        if (version == V170070) return "h20.c";
        if (version == V170071) return "y20.c";
        return "k30.c";
    }

    /**
     * Idle state class used to short-circuit the precheck probe.
     * - 170066/170068: c1.f17845a
     * - 170069: e1.f15227a
     * - 170070: f1.f15998a
     * - 170071: b1.f17861a
     * - 170072: e1.f15787a
     * - 170073+: resolved by DexKit
     */
    private String idleStateClass() {
        if (version >= V170073) return r != null ? r.idleState : null;
        if (version <= V170068) return "c1";
        if (version == V170069) return "e1";
        if (version == V170070) return "f1";
        if (version == V170071) return "b1";
        return "e1";
    }

    private String idleStateField() {
        if (version >= V170073) return r != null ? r.idleField : null;
        if (version <= V170068) return "f17845a";
        if (version == V170069) return "f15227a";
        if (version == V170070) return "f15998a";
        if (version == V170071) return "f17861a";
        return "f15787a";
    }

    /**
     * Cached decision class returned by the encrypted cache accessor.
     * - 170066/170068: h2(long, String, String, boolean)
     * - 170069: o2
     * - 170070: r2
     * - 170071: l2
     * - 170072: o2
     * - 170073+: resolved by DexKit
     */
    private String cachedDecisionClass() {
        if (version >= V170073) return r != null ? r.cachedDecision : null;
        if (version <= V170068) return "h2";
        if (version == V170069) return "o2";
        if (version == V170070) return "r2";
        if (version == V170071) return "l2";
        return "o2";
    }

    /**
     * Cached decision accessor class (the one exposing b(Context)).
     * - 170066-170072: p
     * - 170073+: resolved by DexKit
     */
    private String cachedDecisionAccessorClass() {
        if (version >= V170073) return r != null ? r.cachedDecisionAccessor : null;
        return "p";
    }

    /** Policy-check coroutine method name on the policy holder. */
    private String betaVerifyMethod() {
        return version >= V170073 ? "c" : "b";
    }

    /**
     * Beta verification method parameter types.
     * Each version uses different parameter type classes.
     */
    private Object[] betaVerifyParamTypes() {
        String cont = continuationClass();
        if (version >= V170073) {
            // 170073: policy.c(String, Boolean, cr.a, kotlinx.coroutines.w, ContinuationImpl)
            return r != null ? r.betaVerifyParams : null;
        }
        if (version <= V170068) {
            // 170066: k4.b(String, Boolean, g20.a, y20.x, x10.c)
            // 170068: k4.b(String, Boolean, g20.a, y20.y, x10.c)
            String third = version == V170066 ? "y20.x" : "y20.y";
            return new Object[]{String.class, Boolean.class, findClass("g20.a"), findClass(third), findClass(cont)};
        }
        if (version == V170069) {
            // 170069: n2.b(String, Boolean, n20.a, f30.x, e20.c)
            return new Object[]{String.class, Boolean.class, findClass("n20.a"), findClass("f30.x"), findClass(cont)};
        }
        if (version == V170070) {
            // 170070: q2.b(String, Boolean, q20.a, i30.x, h20.c)
            return new Object[]{String.class, Boolean.class, findClass("q20.a"), findClass("i30.x"), findClass(cont)};
        }
        if (version == V170071) {
            // 170071: k2.b(String, Boolean, h30.a, z30.x, y20.c)
            return new Object[]{String.class, Boolean.class, findClass("h30.a"), findClass("z30.x"), findClass(cont)};
        }
        // 170072: n2.b(String, Boolean, t30.a, l40.x, k30.c)
        return new Object[]{String.class, Boolean.class, findClass("t30.a"), findClass("l40.x"), findClass(cont)};
    }

    // ==================== Hook implementations ====================

    /**
     * Hook 1: Access Gate Bypass
     *
     * Blocks the gate from being set to Denied state and forces its fallback
     * to report a Granted/Ready decision.
     *
     * Hook points:
     * - gate.d(String) → sets gate to Denied (replaced with no-op)
     * - gate.f()      → "not ready" fallback (replaced with the Granted state)
     */
    private void hookAccessGate() {
        String gate = fq(gateControllerClass());
        if (gate == null) {
            XposedBridge.log(TAG + ": hookAccessGate — gate class unresolved");
            return;
        }

        // Block gate.d(String) from setting Denied state
        boolean dOk = tryHook(gate, "d", String.class, XC_MethodReplacement.DO_NOTHING);
        XposedBridge.log(TAG + ": hookAccessGate " + gate + ".d(String) — " + (dOk ? "OK" : "FAILED"));

        // Replace gate.f() fallback with the Granted state
        try {
            final Object readyState = createReadyState();
            if (readyState != null) {
                boolean fOk = tryHook(gate, "f", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        // The fallback is typed as a failure wrapper; only override
                        // when the Granted state is actually assignable to it.
                        if (param.method instanceof Method
                                && ((Method) param.method).getReturnType().isInstance(readyState)) {
                            param.setResult(readyState);
                        }
                    }
                });
                XposedBridge.log(TAG + ": hookAccessGate " + gate + ".f() → Granted — " + (fOk ? "OK" : "FAILED"));
            } else {
                XposedBridge.log(TAG + ": hookAccessGate — could not build Granted state");
            }
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookAccessGate fallback error — " + e.getMessage());
        }
    }

    /**
     * Create a Granted/Ready state object for the current version.
     *
     * - 170066/170068: z2(long)
     * - 170069: h2(i2, Long)
     * - 170070: k2(l2, Long)
     * - 170071: d3(long)
     * - 170072: h3(long)
     * - 170073+: t2(long)
     */
    private Object createReadyState() {
        try {
            String granted = grantedStateClass();
            if (granted == null) return null;
            Class<?> cls = XposedHelpers.findClass(fq(granted), cl);

            if (version >= V170073 || version == V170071 || version == V170072 || version <= V170068) {
                return cls.getConstructor(long.class).newInstance(System.currentTimeMillis());
            }
            if (version == V170069) {
                // 170069: h2(i2, Long)
                Object src = findStaticField(PKG + "i2", "a");
                if (src == null) src = findStaticField(PKG + "i2", "f15306a");
                if (src != null) {
                    return cls.getConstructor(src.getClass(), Long.class)
                            .newInstance(src, System.currentTimeMillis());
                }
            }
            if (version == V170070) {
                // 170070: k2(l2, Long)
                Object src = findStaticField(PKG + "l2", "f16102a");
                if (src == null) src = findStaticField(PKG + "l2", "a");
                if (src != null) {
                    return cls.getConstructor(src.getClass(), Long.class)
                            .newInstance(src, System.currentTimeMillis());
                }
            }
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": createReadyState error — " + e.getMessage());
        }
        return null;
    }

    /**
     * Hook 2: Policy State Bypass
     *
     * Intercepts AtomicReference.set() on the policy reference and refuses the
     * "enforced + Pending" combination, which is what produces the
     * "access_error_model_access_not_ready" failure.
     *
     * The state object exposes enforced in field 'a' and the verdict in 'c'.
     */
    private void hookPolicyState() {
        try {
            String holder = fq(policyHolderClass());
            String verdict = fq(verdictEnumClass());
            if (holder == null || verdict == null) {
                XposedBridge.log(TAG + ": hookPolicyState — classes unresolved");
                return;
            }

            Object refObj = findStaticField(holder, "b");
            if (refObj == null) {
                XposedBridge.log(TAG + ": hookPolicyState — ref not found in " + holder);
                return;
            }

            Object pending = findStaticField(verdict, "a");
            if (pending == null) {
                XposedBridge.log(TAG + ": hookPolicyState — Pending not found in " + verdict);
                return;
            }

            final Object policyRef = refObj;
            final Object pendingVerdict = pending;

            Method setMethod = AtomicReference.class.getDeclaredMethod("set", Object.class);
            XposedBridge.hookMethod(setMethod, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.thisObject != policyRef) return;
                    Object state = param.args[0];
                    if (state == null) return;

                    boolean enforced = getBoolField(state, "a");
                    Object v = getObjField(state, "c");
                    if (enforced && v == pendingVerdict) {
                        param.setResult(null);
                        XposedBridge.log(TAG + ": Blocked policy → enforced+pending");
                    }
                }
            });
            XposedBridge.log(TAG + ": hookPolicyState " + holder + " — OK");
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookPolicyState error — " + e.getMessage());
        }
    }

    /**
     * Hook 3: Root Detection Bypass
     *
     * Returns false for the root probe invoked by the integrity check.
     *
     * Hook points (tried in order):
     * - 170073+: DexKit-resolved root probe
     * - 170072: a00.b.f()
     * - 170071: as.b.g()
     * - 170070: az.b.e()
     * - 170069: ap.b.g()
     * - 170068: com.oplus.anim.w.e()
     * - 170066: aq.e6.f()
     */
    private void hookRootDetection() {
        XC_MethodHook hook = setResultHook(false);

        if (version >= V170073) {
            String root = r != null ? r.rootCheck : null;
            String method = r != null ? r.rootCheckMethod : null;
            if (root != null) {
                if (method != null && tryHook(root, method, hook)) return;
                if (tryHook(root, "f", hook)) return;
                if (tryHook(root, "g", hook)) return;
                if (tryHook(root, "e", hook)) return;
            }
        }
        if (version >= V170072) {
            if (tryHook("a00.b", "f", hook)) return;
        }
        if (version >= V170071) {
            if (tryHook("as.b", "g", hook)) return;
        }
        if (version >= V170070) {
            if (tryHook("az.b", "e", hook)) return;
        }
        if (version >= V170069) {
            if (tryHook("ap.b", "g", hook)) return;
        }
        if (version >= V170068) {
            if (tryHook("com.oplus.anim.w", "e", hook)) return;
        }
        tryHook("aq.e6", "f", hook);
    }

    /**
     * Hook 4: Beta Verification Bypass
     *
     * Returns false for the device access policy check.
     *
     * Hook points:
     * - 170066: k4.b(String, Boolean, g20.a, y20.x, x10.c)
     * - 170068: k4.b(String, Boolean, g20.a, y20.y, x10.c)
     * - 170069: n2.b(String, Boolean, n20.a, f30.x, e20.c)
     * - 170070: q2.b(String, Boolean, q20.a, i30.x, h20.c)
     * - 170071: k2.b(String, Boolean, h30.a, z30.x, y20.c)
     * - 170072: n2.b(String, Boolean, t30.a, l40.x, k30.c)
     * - 170073+: h2.c(String, Boolean, cr.a, kotlinx.coroutines.w, ContinuationImpl)
     */
    private void hookBetaVerification() {
        String cls = fq(policyHolderClass());
        Object[] params = betaVerifyParamTypes();
        if (cls == null || params == null) {
            XposedBridge.log(TAG + ": hookBetaVerification — unresolved");
            return;
        }

        String methodName = betaVerifyMethod();
        Object[] args = new Object[params.length + 1];
        System.arraycopy(params, 0, args, 0, params.length);
        args[params.length] = setResultHook(false);

        boolean ok = tryHookParams(cls, methodName, args);
        XposedBridge.log(TAG + ": hookBetaVerification " + cls + "." + methodName + "(...) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 5: Bootloader/Root Check Bypass
     *
     * Returns false for the combined root + bootloader integrity check.
     *
     * Hook points:
     * - 170066/170068: s4.i(Context)
     * - 170069: w4.i(Context)
     * - 170070: z4.i(Context)
     * - 170071: s4.i(Context)
     * - 170072: w4.i(Context)
     * - 170073+: z3.i(Context)
     */
    private void hookBootloaderCheck() {
        String cls = fq(bootCheckClass());
        if (cls == null) {
            XposedBridge.log(TAG + ": hookBootloaderCheck — unresolved");
            return;
        }
        boolean ok = tryHook(cls, "i", Context.class, setResultHook(false));
        XposedBridge.log(TAG + ": hookBootloaderCheck " + cls + ".i(Context) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 6: ViewModel Device-Integrity Check Bypass
     *
     * Returns null so the integrity verdict is never produced.
     *
     * Hook points:
     * - 170066/170068: m1.f(String, x10.c)
     * - 170069: n1.f(String, e20.c)
     * - 170070: q1.f(String, h20.c)
     * - 170071: k1.f(String, y20.c)
     * - 170072: o1.f(String, k30.c)
     * - 170073+: q1.g(String, ContinuationImpl)
     */
    private void hookViewModelRootCheck() {
        String vm = viewModelClass();
        String cont = continuationClass();
        if (vm == null || cont == null) {
            XposedBridge.log(TAG + ": hookViewModelRootCheck — unresolved");
            return;
        }
        String cls = fq(vm);
        String methodName = version >= V170073 ? "g" : "f";
        Object paramType = version >= V170073 ? cont : findClass(cont);
        boolean ok = tryHookParams(cls, methodName, String.class, paramType, setResultHook((Object) null));
        XposedBridge.log(TAG + ": hookViewModelRootCheck " + cls + "." + methodName + "(String, c) — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 7: Precheck Bypass
     *
     * Returns the Idle state to skip the /precheck network probe.
     *
     * Hook points:
     * - 170066/170068: m1.h(boolean, boolean, String, boolean, x10.c)
     * - 170069: n1.h(boolean, boolean, String, boolean, e20.c)
     * - 170070: q1.h(boolean, boolean, String, boolean, h20.c)
     * - 170071: k1.h(boolean, boolean, String, boolean, y20.c)
     * - 170072: o1.h(boolean, boolean, String, boolean, k30.c)
     * - 170073+: q1.i(boolean, boolean, String, boolean, ContinuationImpl)
     */
    private void hookPrecheckBypass() {
        String idleShort = idleStateClass();
        String idleField = idleStateField();
        if (idleShort == null) {
            XposedBridge.log(TAG + ": hookPrecheckBypass — idle state unresolved");
            return;
        }
        Class<?> idleCls = findClass(idleShort);
        Object idle = idleField != null ? findStaticField(fq(idleShort), idleField) : null;
        String usedField = idleField;
        if (idle == null) {
            // Obfuscators rename fields between builds; the Idle state is always
            // the singleton static field whose type is its own class.
            for (Field f : idleCls.getDeclaredFields()) {
                if (f.getType() == idleCls && java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    try {
                        f.setAccessible(true);
                        idle = f.get(null);
                        usedField = f.getName();
                    } catch (Throwable ignored) {
                    }
                    if (idle != null) break;
                }
            }
        }
        if (idle == null) {
            XposedBridge.log(TAG + ": hookPrecheckBypass — idle state not found in " + idleCls.getName());
            return;
        }

        final Object idleState = idle;
        String vm = viewModelClass();
        String cont = continuationClass();
        if (vm == null || cont == null) return;
        String cls = fq(vm);
        String methodName = version >= V170073 ? "i" : "h";
        Object paramType = version >= V170073 ? cont : findClass(cont);

        boolean ok = tryHookParams(cls, methodName,
                boolean.class, boolean.class, String.class, boolean.class,
                paramType, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(idleState);
                    }
                });
        XposedBridge.log(TAG + ": hookPrecheckBypass " + cls + "." + methodName + "(...) [idle="
                + idleCls.getSimpleName() + "." + usedField + "] — " + (ok ? "OK" : "FAILED"));
    }

    /**
     * Hook 8: Cached Decision Bypass
     *
     * Makes the encrypted cache report an allowed decision.
     *
     * Hook points:
     * - 170066/170068: p.b(Context) -> h2(long, String, String, boolean)
     * - 170069: p.b(Context) -> o2
     * - 170070: p.b(Context) -> r2
     * - 170071: p.b(Context) -> l2
     * - 170072: p.b(Context) -> o2
     * - 170073+: t.b(Context)  -> i2
     */
    private void hookCachedDecision() {
        try {
            String clsShort = cachedDecisionClass();
            String accessor = cachedDecisionAccessorClass();
            if (clsShort == null || accessor == null) {
                XposedBridge.log(TAG + ": hookCachedDecision — unresolved");
                return;
            }
            final String clsName = fq(clsShort);
            final Class<?> cls = XposedHelpers.findClass(clsName, cl);

            XC_MethodHook hook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    try {
                        param.setResult(cls.getConstructor(long.class, String.class, String.class, boolean.class)
                                .newInstance(System.currentTimeMillis(), "", "", true));
                    } catch (Throwable ignored) {}
                }
            };

            boolean ok = tryHook(fq(accessor), "b", Context.class, hook);
            XposedBridge.log(TAG + ": hookCachedDecision " + clsName + " — " + (ok ? "OK" : "FAILED"));
        } catch (Throwable e) {
            XposedBridge.log(TAG + ": hookCachedDecision error — " + e.getMessage());
        }
    }

    // ==================== Utility methods ====================

    private boolean classExists(String className) {
        try {
            XposedHelpers.findClass(className, cl);
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    private boolean tryHook(String className, String methodName, XC_MethodHook hook) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, hook);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean tryHook(String className, String methodName, Class<?> p1, XC_MethodHook hook) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, p1, hook);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean tryHookParams(String className, String methodName, Object... paramTypesAndCallback) {
        try {
            XposedHelpers.findAndHookMethod(findClass(className), methodName, paramTypesAndCallback);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private Class<?> findClass(String name) {
        return XposedHelpers.findClass(fq(name), cl);
    }

    private Object findStaticField(String className, String fieldName) {
        try {
            return XposedHelpers.getStaticObjectField(findClass(className), fieldName);
        } catch (Throwable e) {
            return null;
        }
    }

    private static boolean getBoolField(Object obj, String name) {
        try {
            return XposedHelpers.getBooleanField(obj, name);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Object getObjField(Object obj, String name) {
        try {
            return XposedHelpers.getObjectField(obj, name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static XC_MethodHook setResultHook(final Object value) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                param.setResult(value);
            }
        };
    }

    /** Container for DexKit-resolved class and parameter names. */
    static final class Resolved {
        String gate;
        String grantedState;
        String policyHolder;
        String verdictEnum;
        String bootCheck;
        String rootCheck;
        String rootCheckMethod;
        String viewModel;
        String continuation;
        String idleState;
        String idleField;
        String cachedDecision;
        String cachedDecisionAccessor;
        Object[] betaVerifyParams;
    }
}
