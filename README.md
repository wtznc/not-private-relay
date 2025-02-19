#  not-private-relay

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
- wireshark
- [frida script](https://andydavies.me/blog/2019/12/12/capturing-and-decrypting-https-traffic-from-ios-apps/) - Apple uses certificate pinning to prevent the sniffing of encrypted network traffic. I'm using this script to extract those secrets and import them into Wireshark, so I can see all requests in plain text.
- xpcspy
- ghidra

keywords:
- AppleIDSettings
- com.apple.networkserviceproxy
- NSPServerCommandType
- /usr/libexec/networkserviceproxy (Mach-O binary)
- /System/Library/PrivateFrameworks/NetworkServiceProxy.framework
- NSPConfiguration class
- NSPConfiguration.proxyConfiguration
- GET mask-api.icloud.com/v2_3/fetchConfigFile
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

```first success 🏆``` frida can attach to system protected processes
