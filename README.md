#  not-so-private-relay

task:
- Dig into Apple’s NetworkServiceProxy frameworks, analyze Mach-O binaries, and intercept pinned HTTPS traffic with Frida - reveal how iCloud Private Relay flows under the hood.

research:
- [iCloud Private Relay Whitepaper](https://www.apple.com/privacy/docs/iCloud_Private_Relay_Overview_Dec2021.PDF)


tools:
- frida
  - [build from source](https://github.com/frida/frida)
    - [generate trusted code-signing certificate](https://sourceware.org/gdb/wiki/PermissionsDarwin) - gdb_codesign in keychain
    - ```export MACOS_CERTID=gdb_codesign```
    - ```make && make install```
    - ```/usr/local/bin/frida ```
- frida-trace
- mitmproxy
  - Apple uses certificate pinning to prevent the sniffing of encrypted network traffic. To bypass this, we need to install a custom certificate on the device.
- [ghidra](https://github.com/NationalSecurityAgency/ghidra)
  - install JDK & JRE (NSA suggests [openjdk](https://adoptium.net/temurin/releases/))

keywords:
- AppleIDSettings
- com.apple.networkserviceproxy
- NSPServerCommandType
- /usr/libexec/networkserviceproxy (Mach-O binary)
- /System/Library/PrivateFrameworks/NetworkServiceProxy.framework
- NSPConfiguration class
- NSPConfiguration.proxyConfiguration
- GET mask-api.icloud.com/v4_4/fetchConfigFile
- x-mask-subscription-token (JWT), ES384

process:
- disable SIP (system integrity protection) 
  - boot into recovery mode
  - ```csrutil disable```
- enable developer mode
  - ```sudo DevToolsSecurity -enable```
- [```sudo nvram boot-args=-arm64e_preview_abi```](https://developer.apple.com/documentation/driverkit/debugging_and_testing_system_extensions)
- ```ps aux | grep AppleIDSettings```
- ```sudo frida -p $PID```

#### `first success 🏆` frida can attach to system protected processes

- trace calls: 
```sudo frida-trace -p 17107 -i "xpc_connection*" -o trace.log```
- interesting logged calls:
```console
$: xpc_connection_send_message_with_reply(connection=0x6000030bafd0, message=0x600002bbc960, targetq=0x6000021d0b80, handler=0x16bbd18b8)
$: 0x1c5f7b464 NetworkServiceProxy!-[NSPServerClient getPrivacyProxyUserTierWithCompletionHandler:]
```

- hmmm `networkserviceproxy (/usr/libexec/networkserviceproxy)` :
```console
wtznc@github ~ ps aux | grep networkserviceproxy

wtznc 684   0.0  0.1 426972944  24304   ??  S     7:33PM   0:07.17 /usr/libexec/networkserviceproxy
```
- copy bin and inspect
```console
wtznc@github ~ file networkserviceproxy

networkserviceproxy: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e]
networkserviceproxy (for architecture x86_64):	Mach-O 64-bit executable x86_64
networkserviceproxy (for architecture arm64e):	Mach-O 64-bit executable arm64e
```

- ghidra time (in progress):
  - bin networkserviceproxy imports PrivateFrameworks/NetworkServiceProxy.framework
- private frameworks cannot be directly extracted, however there's a way to analyse its content through dyld cache
- apple since Ventura keeps em here:  
```/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e```
  - actually we dont need to analyse the whole dyld cache, ghidra can load the cache when we open the binary (settings, check load dyld cache)
- found NSPConfiguration class in Ghidra, inspecting further
- there's a method `proxyConfiguration` which returns a dictionary with keys 🔑 lets print its values
  - in order to do that, we need to attach frida to the process and call the method
- frida script to inspect the method:
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
- execute the script:
```console
sudo frida -l inspect.js -n networkserviceproxy 2>&1 | tee output.log
```
#### `second success 🏆` frida can inspect the return value of NSPConfiguration.proxyConfiguration


- mitmproxy instead of frida with a script to intercept HTTPS traffic
- holy moly this is huge
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

#### moar to come...
