/**
* 2026 Targeted VAPT Master (Crash-Free Proxy Edition)
* Fixed: Updated Conscrypt signature based on Frida error log to stop app hanging.
*/

const forbiddenPaths = [
    "su", "magisk", "busybox", "supersu", "superuser", "ksu", "daemonsu", "logswitch",
    "9a5ba575.0", "9a5ba575.1", "9dad1a1b.0", "b9ebaf8b.0", "cacerts-removed"
];

// !!! MUST CHANGE THIS TO YOUR BURP SUITE IP !!!
const BURP_HOST = "172.16.15.67"; 
const BURP_PORT = 8081;

Java.perform(function() {
    console.log("[*] Initializing Crash-Free Proxy Master Bypass...");

    // ==========================================
    // 1. LOW-LEVEL CONSCRYPT SSL BYPASS (Fixed Signature)
    // ==========================================
    try {
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        const ArrayList = Java.use("java.util.ArrayList");

        // Fixed signature provided by your device's Frida log
        TrustManagerImpl.checkTrustedRecursive.overload(
            '[Ljava.security.cert.X509Certificate;', '[B', '[B', 'java.lang.String', 'boolean', 'java.util.ArrayList', 'java.util.ArrayList', 'java.util.Set'
        ).implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
            console.log("[+] Conscrypt: Forced OS to trust Burp certificate!");
            return ArrayList.$new(); // Returns empty list (Valid)
        };
    } catch (e) {
        console.log("[-] Conscrypt hook failed: " + e);
    }

    // Add generic TrustManager bypass just in case standard Java networking is used
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const TrustAllManager = Java.registerClass({
            name: 'com.sec.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        const tmArray = Java.array('javax.net.ssl.TrustManager', [TrustAllManager.$new()]);
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const sslInit = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        sslInit.implementation = function(km, tm, sr) {
            sslInit.call(this, km, tmArray, sr);
        };
    } catch (e) {}

    // ==========================================
    // 2. OBFUSCATED OKHTTP BYPASS (g7.C)
    // ==========================================
    try {
        const ObfuscatedBuilder = Java.use("g7.C$a");

        // Strip the Certificate Pinner
        ObfuscatedBuilder.d.overload('g7.h').implementation = function(pinner) {
            console.log("[+] Stripped Obfuscated CertificatePinner (g7.h)");
            return this; 
        };

        // Reflect the Proxy
        ObfuscatedBuilder.b.overload().implementation = function() {
            const Proxy = Java.use('java.net.Proxy');
            const ProxyType = Java.use('java.net.Proxy$Type');
            const InetSocketAddress = Java.use('java.net.InetSocketAddress');

            const burpAddress = InetSocketAddress.$new(BURP_HOST, BURP_PORT);
            const burpProxy = Proxy.$new(ProxyType.HTTP.value, burpAddress);

            try {
                const builderClass = Java.use("g7.C$a").class;

                // Inject Proxy (Field 'm')
                const proxyField = builderClass.getDeclaredField("m");
                proxyField.setAccessible(true);
                proxyField.set(this, burpProxy);

                // Clear ProxySelector (Field 'n')
                const selectorField = builderClass.getDeclaredField("n");
                selectorField.setAccessible(true);
                selectorField.set(this, null);

                console.log("[+] Proxy Reflection Success: Traffic forced to Burp!");
            } catch(err) {}

            return this.b();
        };
    } catch(e) {}

    // ==========================================
    // 3. STANDARD URL PROXY FORCER
    // ==========================================
    try {
        const URL = Java.use('java.net.URL');
        const Proxy = Java.use('java.net.Proxy');
        const ProxyType = Java.use('java.net.Proxy$Type');
        const InetSocketAddress = Java.use('java.net.InetSocketAddress');
        const burpAddress = InetSocketAddress.$new(BURP_HOST, BURP_PORT);
        const burpProxy = Proxy.$new(ProxyType.HTTP.value, burpAddress);

        URL.openConnection.overload().implementation = function() { return this.openConnection(burpProxy); };
        URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) { return this.openConnection(burpProxy); };
    } catch(e) {}

    // ==========================================
    // 4. JAVA & NATIVE STEALTH
    // ==========================================
    try {
        const File = Java.use("java.io.File");
        const exists = File.exists.overload();
        exists.implementation = function() {
            try {
                const path = this.getAbsolutePath();
                if (path && forbiddenPaths.some(p => path.toLowerCase().indexOf(p) !== -1)) return false; 
            } catch (err) {}
            return exists.call(this);
        };
    } catch(e) {}

    const fakePathPtr = Memory.allocUtf8String("/dev/null");

    try {
        const fopen = Module.findExportByName("libc.so", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    try {
                        const path = args[0].readUtf8String();
                        if (path && forbiddenPaths.some(p => path.toLowerCase().indexOf(p) !== -1)) args[0] = fakePathPtr; 
                    } catch(err) {}
                }
            });
        }
        const access = Module.findExportByName("libc.so", "access");
        if (access) {
            Interceptor.attach(access, {
                onEnter: function(args) {
                    try {
                        const path = args[0].readUtf8String();
                        if (path && forbiddenPaths.some(p => path.toLowerCase().indexOf(p) !== -1)) args[0] = fakePathPtr; 
                    } catch(err) {}
                }
            });
        }
    } catch(e) {}

    // ==========================================
    // 5. GHOST UI & APP STEALTH
    // ==========================================
    try {
        const Dialog = Java.use("android.app.Dialog");
        const showDialog = Dialog.show.overload();
        showDialog.implementation = function() {
            try {
                showDialog.call(this); 
                this.dismiss();  
            } catch(e) {}      
        };
        const Toast = Java.use("android.widget.Toast");
        Toast.show.implementation = function() { };
    } catch(e) { }

    const rootPkgs = [
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su", 
        "me.weishu.kernelsu", "com.thirdparty.superuser"
    ];
    try {
        const PM = Java.use("android.app.ApplicationPackageManager");
        const getPkgInfo = PM.getPackageInfo.overload('java.lang.String', 'int');
        getPkgInfo.implementation = function(pkg, flags) {
            if (rootPkgs.indexOf(pkg) !== -1) throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
            return getPkgInfo.call(this, pkg, flags);
        };

        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1) return this.exec("ls /dev/null");
            return this.exec(cmd);
        };
    } catch(e) {}

    console.log("[+] Setup Complete. Awaiting stable traffic...");
});
