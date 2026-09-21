# Xiaobu Next(Breeno Next) Bypass
It is a LSPosed module for bypass Xiaobu Next beta verify

# How to use
1. Compile the module from source by yourself
2. Install Xiaobu Next & the Bypass Module.
3. Enable the Bypass Module in LSPosed and select Xiaobu Next.
4. Force-stop Xiaobu Next and restart it.
5. Enjoy!

# Features
- Bypassed Beta Verification in 170066 & higher version

# Implementation notes
Up to **170072** the obfuscated class names are stable enough to hard-code per
version. Starting with **170073** the whole controller package was renamed, so
the module resolves its hook targets at runtime with
[DexKit](https://github.com/LuckyPray/DexKit) instead: it anchors on string
literals that the obfuscator leaves untouched (for example
`DUID access gate granted`, `device access check source=`,
`ro.boot.flash.locked`) and derives the surrounding classes and their
signatures from those.

The DexKit pass rediscovers the 170071 layout exactly (gate `g3`, policy `k2`,
verdict `h2`, boot `s4`, viewmodel `k1`, cache accessor `p` -> `l2`), which is
why the same code path serves both the hard-coded and the resolved versions.

Resolved for 170073: gate `w2`, policy `h2`, verdict
`BetaDeviceAccessPolicy$DeviceVerdict`, boot `z3`, root probe `ei.b`,
viewmodel `q1`, idle state `j1`, cache accessor `t` -> `i2`.

# FAQ

**Q: Where can I get Xiaobu Next?**  
**A:** Check [here](https://oppo-mlm-cn.heytapmobi.com/agentix/update/download?app_id=mobileclawexternal)

---

**Q: Not working on x.x.x version?**  
**A:** Please open an issue and upload the APK file.