# VM Tracker — Android client (optional)

A thin Flutter client for the same API the web console uses: sign in, see the
executive KPIs, browse and filter the register, and change a finding's status
from your phone. Everything else stays in the web console.

## Build

```bash
flutter pub get
flutter run                     # debug on a connected device
flutter build apk --release     # build/app/outputs/flutter-apk/app-release.apk
```

## Pointing it at your server

On the sign-in screen, enter the server address, e.g. `http://10.0.20.5:9797`.
It is saved on the device for next launch.

Two things to know:

- Android blocks plain HTTP by default. The manifest below sets
  `android:usesCleartextTraffic="true"`, which is fine on a trusted internal
  network. If the server is reachable from anywhere else, put it behind a reverse
  proxy with TLS and use the `https://` address instead.
- `localhost` on the phone is the phone. Use the server's LAN IP address.

Add to `android/app/src/main/AndroidManifest.xml` inside `<application>`:

```xml
android:usesCleartextTraffic="true"
```

and above `<application>`:

```xml
<uses-permission android:name="android.permission.INTERNET"/>
```
