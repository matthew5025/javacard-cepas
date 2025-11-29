## Quick start: load, install, and test the CEPAS applet

These steps use the default GlobalPlatform test keys and a Feitian contact reader. Adjust the reader name if yours differs.

### 1) Build the CAP
```bash
./gradlew buildJavaCard --rerun-tasks
```
CAP output: `applet/build/javacard/applet.cap`

### 2) (Re)install on the card
Use default selection and privileges; this works on the Feitian cards we tested.
```bash
java -jar gp.jar -uninstall applet/build/javacard/applet.cap
java -jar gp.jar -install applet/build/javacard/applet.cap -default --privs ContactlessActivation,ContactlessSelfActivation,CardReset
```
If APDUs are flaky with your reader, add a smaller block size (e.g., `--bs 32`).

### 3) Run the Python probe
Requires `pyscard` (`pip install pyscard`) and a connected reader/card.
```bash
python3 python/card_probe.py --reader "Contact"
```
Expected output ends with:
```
OK: balance roundtrip matched, card is responsive (SW=9000).
```

### Troubleshooting
- SELECT fails (6A82): reinstall with the steps above, confirm the reader name, and ensure the card is seated.
- INSTALL fails (6985/6A80): uninstall first, try `--bs 32`, and make sure you’re using the contact interface.
- Probe says “No readers found”: set the READER substring (`--reader "Contact"`) to match `pcsc_scan`/`gp -r`.
- Need the exact install recipe we validated? See the commands above (uninstall then install with `-default --privs ContactlessActivation,ContactlessSelfActivation,CardReset`).
