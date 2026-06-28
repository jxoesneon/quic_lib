export 'dart:io'
    if (dart.library.js_interop) 'platform_address_stub.dart'
    if (dart.library.html) 'platform_address_stub.dart'
    show InternetAddress, InternetAddressType;
