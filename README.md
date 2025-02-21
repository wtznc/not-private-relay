#  not-so-private-relay

## Task

Investigate Apple's iCloud Private Relay by:

  - **Reverse Engineering:** Digging into Apple’s NetworkServiceProxy frameworks and analyzing Mach-O binaries.
  - **Traffic Interception:** Intercepting pinned HTTPS traffic with Frida to understand how iCloud Private Relay operates under the hood.

## Research

  - **iCloud Private Relay Whitepaper:** [Apple iCloud Private Relay Overview (Dec 2021)](https://www.apple.com/privacy/docs/iCloud_Private_Relay_Overview_Dec2021.PDF)

## Tools

  - [Frida](https://www.google.com/url?sa=E&source=gmail&q=https://frida.re/): Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
  - `frida-trace`:  Frida's tool for tracing function calls.
  - [mitmproxy](https://www.google.com/url?sa=E&source=gmail&q=https://mitmproxy.org/): Interactive HTTPS proxy.
  - [Ghidra](https://github.com/NationalSecurityAgency/ghidra): Software Reverse Engineering framework.
      - **JDK & JRE:** Required for Ghidra. NSA recommends [OpenJDK Temurin](https://adoptium.net/temurin/releases/).
  - JWT Decoder: For analyzing JSON Web Tokens.

**Note:** Apple utilizes certificate pinning to secure network traffic. To bypass this for interception, installing a custom certificate on the target device is necessary.

## Keywords

  - `AppleIDSettings`
  - `com.apple.networkserviceproxy`
  - `NSPServerCommandType`
  - `/usr/libexec/networkserviceproxy` (Mach-O binary)
  - `/System/Library/PrivateFrameworks/NetworkServiceProxy.framework`
  - `NSPConfiguration` class
  - `NSPConfiguration.proxyConfiguration`
  - `GET mask-api.icloud.com/v4_4/fetchConfigFile`
  - `x-mask-subscription-token` (JWT, ES384)

## Process

This section outlines the steps taken to analyze iCloud Private Relay.

### 1\. Disable System Integrity Protection (SIP)

To allow debugging and code injection into system processes, SIP needs to be disabled.

  - **Boot into Recovery Mode:** Restart your Mac and hold **Command + R** during startup.

  - **Run `csrutil disable` in Terminal:** Open Terminal from the Utilities menu in Recovery Mode and execute the following command:

    ```bash
    csrutil disable
    ```

    Restart your Mac after running this command.

### 2\. Enable Developer Mode

Enable Developer Mode to allow system-level debugging.

  - **Run `DevToolsSecurity -enable`:** Open Terminal and execute:

    ```bash
    sudo DevToolsSecurity -enable
    ```

### 3\. Enable Debugging for System Extensions

This step enables debugging for system extensions which might be relevant to NetworkServiceProxy.

  - **Set `boot-args` NVRAM variable:** Execute the following command in Terminal:

    ```bash
    sudo nvram boot-args=-arm64e_preview_abi
    ```

    Refer to [Apple Developer Documentation on Debugging and Testing System Extensions](https://developer.apple.com/documentation/driverkit/debugging_and_testing_system_extensions) for more context.

### 4\. Build Frida from Source with Code Signing

Building Frida from source and code signing it is crucial for attaching to protected processes.

  - **Generate a Trusted Code-Signing Certificate:** Follow instructions to [generate a code-signing certificate for GDB on macOS](https://sourceware.org/gdb/wiki/PermissionsDarwin). Ensure `gdb_codesign` (or your chosen certificate name) appears in Keychain Access as a valid certificate.

  - **Set Environment Variable and Build Frida:**

    ```bash
    export MACOS_CERTID=gdb_codesign # Replace gdb_codesign with your certificate name if different
    make && make install
    ```

  - **Verify Frida Installation:**

    ```bash
    /usr/local/bin/frida
    ```

    This command should execute without errors if Frida is installed correctly.

  - **Test Frida on a Protected Process:**

    ```bash
    ps aux | grep AppleIDSettings # Find the PID of a protected process like AppleIDSettings
    sudo frida -p <PID>          # Replace <PID> with the actual Process ID
    ```

#### `first success 🏆` Frida can now attach to system protected processes\!

### 5\. Trace XPC Calls with Frida-trace

To understand the communication within `networkserviceproxy`, trace XPC calls.

  - **Run `frida-trace`:**

    ```bash
    sudo frida-trace -p <PID of AppleIDSettings or another protected process> -i "xpc_connection*" -o trace.log
    ```

    This command traces functions matching `xpc_connection*` and saves the output to `trace.log`.

  - **Analyze `trace.log` for Interesting Calls:** Example of interesting calls observed:

    ```console
    $: xpc_connection_send_message_with_reply(connection=0x6000030bafd0, message=0x600002bbc960, targetq=0x6000021d0b80, handler=0x16bbd18b8)
    $: 0x1c5f7b464 NetworkServiceProxy!-[NSPServerClient getPrivacyProxyUserTierWithCompletionHandler:]
    ```

### 6\. Analyze `networkserviceproxy` Binary

Investigate the `networkserviceproxy` binary to understand its functionality.

  - **Locate and Identify `networkserviceproxy`:**

    ```console
    ps aux | grep networkserviceproxy
    ```

    Output:

    ```console
    wtznc 684 0.0 0.1 426972944 24304 ?? S 7:33PM 0:07.17 /usr/libexec/networkserviceproxy
    ```

  - **Copy and Inspect the Binary:**

    ```console
    file /usr/libexec/networkserviceproxy
    ```

    Output showing it's a Mach-O universal binary:

    ```console
    networkserviceproxy: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e]
    networkserviceproxy (for architecture x86_64): Mach-O 64-bit executable x86_64
    networkserviceproxy (for architecture arm64e): Mach-O 64-bit executable arm64e
    ```

  - **Ghidra Analysis (In Progress):**

      - Load `networkserviceproxy` into Ghidra for static analysis.
      - Observe imports of `PrivateFrameworks/NetworkServiceProxy.framework`.
      - Private frameworks are within the dyld cache at `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e` (on Ventura and later).
      - Enable "Load Dyld Cache" in Ghidra settings when opening the binary to resolve symbols from private frameworks.
      - Found `NSPConfiguration` class and the `proxyConfiguration` method.

### 7\. Frida Script to Inspect `NSPConfiguration.proxyConfiguration`

Use Frida to dynamically inspect the return value of the `proxyConfiguration` method.

  - **Create `inspect.js` with the following content:**

    ```js
    // inspect NSPConfiguration proxyConfiguration return value
    // usage: sudo frida -l inspect.js -n networkserviceproxy 2>&1 | tee output.log
    if (ObjC.available) {
        var NSPConfiguration = ObjC.classes.NSPConfiguration;
        Interceptor.attach(NSPConfiguration["- proxyConfiguration"].implementation, {
            onLeave: function (retval) {
                try {
                    var result = new ObjC.Object(retval);
                    console.log("=== proxyConfiguration return value ===");
                    console.log(result.toString());

                    if (result.$className === "NSDictionary") {
                        var allKeys = result.allKeys();
                        for (var i = 0; i < allKeys.count(); i++) {
                            var key = allKeys.objectAtIndex_(i);
                            var val = result.objectForKey_(key);
                            console.log(key.toString() + " : " + val.toString());
                        }
                    }
                } catch (e) {
                    console.log("Error reading retval: " + e);
                }
            }
        });
    }
    ```

  - **Execute the Frida Script:**

    ```bash
    sudo frida -l inspect.js -n networkserviceproxy 2>&1 | tee output.log
    ```

#### `second success 🏆` Frida can successfully inspect the return value of `NSPConfiguration.proxyConfiguration`\!

### 8\. Intercept HTTPS Traffic with mitmproxy

Use mitmproxy to intercept and analyze HTTPS traffic related to iCloud Private Relay.

  - **Run mitmproxy and Observe Traffic:** Configure your system to proxy traffic through mitmproxy.

  - **Analyze Captured Traffic:** Look for relevant requests, particularly those involving `mask-api.icloud.com`.

  - **JWT Analysis from Intercepted Traffic:** Example JWT extracted from traffic (ES384 encoded):

    ```console
    jwt (es384):

    header:
    {
        "vid": 2,
        "alg": "ES384",
        "kid": "ulxxxxxAT-2SxxxxxEe4TDxxxxxjpAAxxxxxZvdi5Tc"
    }

    payload (masked on purpose):
    {
        "accountId": "17xxxxxx53",
        "iss": "apple.cloud.subscriptions.p68",
        "limit": 2,
        "exp": 1740166982,
        "featureKey": "networking.privacy.subscriber",
        "deviceId": "00xx8x03-00xxxxxx3Exxx01E",
        "iat": 1740080582,
        "jti": "f3xxxx26-0xx4-4xxd-9xx7-61xxxxxxabd9"
    }
    ```

## Moar to come...

Further research and analysis are ongoing. Stay tuned for updates\!