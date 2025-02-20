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