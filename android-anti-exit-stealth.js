/* --- ALL-IN-ONE BYPASS (Crash Fix + SSL + Anti-Exit) --- */

// 1. NATIVE EXIT BLOCKER (Prevents "Process terminated")
// We run this OUTSIDE Java.perform to catch early native checks
try {
    const exitPtr = Module.findExportByName(null, "exit");
    if (exitPtr) {
        Interceptor.replace(exitPtr, new NativeCallback(function(code) {
            console.log("[!] BLOCKED NATIVE EXIT(" + code + ")");
            // We do nothing, effectively swallowing the exit command
        }, 'void', ['int']));
        console.log("[+] Native 'exit' Hooked");
    }
} catch (e) { console.log("[-] Exit Hook Error: " + e.message); }

try {
    const killPtr = Module.findExportByName(null, "kill");
    if (killPtr) {
        Interceptor.replace(killPtr, new NativeCallback(function(pid, sig) {
            console.log("[!] BLOCKED NATIVE KILL(pid=" + pid + ", sig=" + sig + ")");
        }, 'int', ['int', 'int']));
        console.log("[+] Native 'kill' Hooked");
    }
} catch (e) {}


Java.perform(function() {
    console.log("\n[*] STARTING JAVA LAYER HOOKS...");

    // ============================================================
    // 2. MAIN ACTIVITY CRASH FIX (Critical)
    // ============================================================
    try {
        const MainActivity = Java.use("com.nayifat.mobile.MainActivity");
        if (MainActivity.performRuntimeSecurityCheck) {
            MainActivity.performRuntimeSecurityCheck.implementation = function() {
                // Do nothing to prevent the SIGSEGV crash
                console.log("[!] CRASH PREVENTED: Bypassed performRuntimeSecurityCheck"); 
                return;
            };
        }
    } catch(e) { console.log("[-] Crash Fix Error: " + e.message); }

    // ============================================================
    // 3. EMULATOR SPOOFING
    // ============================================================
    try {
        const Build = Java.use("android.os.Build");
        Build.FINGERPRINT.value = "google/oriole/oriole:13/TP1A.221005.002/9012097:user/release-keys";
        Build.MODEL.value = "Pixel 6";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.DEVICE.value = "oriole";
        Build.PRODUCT.value = "oriole";
        Build.TAGS.value = "release-keys";
        console.log("[+] Emulator Fingerprint Spoofed");
    } catch(e) {}

    // ============================================================
    // 4. ROBUST SSL PINNING BYPASS (From your previous script)
    // ============================================================

    // A. Custom TrustManager (Trusts Everything)
    const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    const TrustManager = Java.registerClass({
        name: 'com.nayifat.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // B. Hook SSLContext to use our TrustManager
    try {
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        const SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            // Replace the app's TrustManager with ours
            SSLContext_init.call(this, keyManager, [TrustManager.$new()], secureRandom);
        };
        console.log("[+] SSLContext Hooked");
    } catch(e) {}

    // C. OkHttp CertificatePinner (Critical for modern apps)
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
            console.log("[+] Bypassed OkHttp Pinner: " + str);
            return; // Do nothing, allowing the connection
        };
    } catch(e) {}

    try {
        const PinnerBuilder = Java.use("okhttp3.CertificatePinner$Builder");
        PinnerBuilder.add.implementation = function(pattern, pins) {
            return this; // Ignore adding pins
        };
    } catch(e) {}

    // D. React Native Pinning (Specific to Nayifat)
    try {
        const RNPinningSsl = Java.use("com.nayifat.mobile.RNPinningSsl");
        const Promise = Java.use("com.facebook.react.bridge.Promise");

        // We override the getStatus method to always return Success/False
        RNPinningSsl.getStatus.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'com.facebook.react.bridge.Promise').implementation = function(u, f, s, promise) {
            console.log("[+] RNPinningSsl Hit");
            // Resolve the promise with FALSE (No error/No pinning issue)
            const JBoolean = Java.use("java.lang.Boolean");
            promise.resolve(JBoolean.valueOf(false)); 
            return;
        };
    } catch(e) { console.log("[-] RNPinningSsl hook error: " + e.message); }

    // E. Proxy Selector (Fixes connection drops on Emulator)
    try {
        const ProxySelector = Java.use("java.net.ProxySelector");
        const Proxy = Java.use("java.net.Proxy");
        const InetSocketAddress = Java.use("java.net.InetSocketAddress");
        const ArrayList = Java.use("java.util.ArrayList");

        const MyProxySelector = Java.registerClass({
            name: 'com.nayifat.bypass.ProxySelector',
            superClass: ProxySelector, 
            methods: {
                select: function(uri) {
                    const list = ArrayList.$new();
                    // Force direct connection or Emulator Proxy (10.0.2.2)
                    // Usually Proxy.NO_PROXY is safest for bypassing interception
                    list.add(Proxy.NO_PROXY.value);
                    return list;
                },
                connectFailed: function(uri, sa, ioe) {}
            }
        });
        ProxySelector.setDefault(MyProxySelector.$new());
        console.log("[+] ProxySelector Fixed");
    } catch(e) {}

    // ============================================================
    // 5. ROOT / FRIDA DETECTION
    // ============================================================
    try {
        const FridaDet = Java.use("com.nayifat.mobile.FridaDetectionModule");
        // Helper to resolve promises safely
        FridaDet.getFridaStatus.implementation = function(promise) {
            const JBoolean = Java.use("java.lang.Boolean");
            promise.resolve(JBoolean.valueOf(false));
        };

        // Force all boolean checks to False
        const boolMethods = [
            "isFridaRunning", "detectFridaStrings", "isFridaInLoadedLibraries",
            "isFridaInMemoryMaps", "isFridaPortOpen", "isFridaServerRunning_Process",
            "isFridaServerRunning_executable", "isFridaServerRunning_port"
        ];
        boolMethods.forEach(function(m) {
            FridaDet[m].implementation = function() { return false; };
        });
    } catch(e) {}

    try {
        const JailMonkey = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
        const HashMap = Java.use("java.util.HashMap");
        const JString = Java.use("java.lang.String");
        const JBoolean = Java.use("java.lang.Boolean");

        JailMonkey.getConstants.implementation = function() {
            var map = HashMap.$new();
            map.put(JString.$new("isJailBroken"), JBoolean.valueOf(false));
            map.put(JString.$new("canMockLocation"), JBoolean.valueOf(false));
            map.put(JString.$new("isRooted"), JBoolean.valueOf(false));
            return map;
        };
    } catch(e) {}

    console.log("[*] SCRIPT LOADED. WAITING FOR APP...");
});
