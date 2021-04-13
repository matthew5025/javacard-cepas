# CEPAS implementation in JavaCard

Based off the awesome JavaCard gradle template provided by ph4r05, available [here](https://github.com/ph4r05/javacard-gradle-template).

## Introductions
### What the heck is this?
This is a simple implementation of a CEPAS card, made using JavaCard.

### Can I get free rides / stuff with this?
No.

### What actually works?
Only commands that reads the purse WITHOUT authentication.  
There are some proprietary commands to change card values after the creation of the purse.

### What's the point?
I did this to learn more about JavaCard

## Build Instructions

- Run Gradle wrapper `./gradlew` on Unix-like system or `./gradlew.bat` on Windows
to build the project for the first time (Gradle will be downloaded if not installed).

- Setup your Applet ID (`AID`) in the `./applet/build.gradle`.

- Run the `buildJavaCard` task:

```bash
./gradlew buildJavaCard  --info --rerun-tasks
```

Generates a new cap file `./applet/out/cap/applet.cap`

Note: `--rerun-tasks` is to force re-run the task even though the cached input/output seems to be up to date.

Typical output:

```
[ant:cap] [ INFO: ] Converter [v3.0.5]
[ant:cap] [ INFO: ]     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:cap]     
[ant:cap]     
[ant:cap] [ INFO: ] conversion completed with 0 errors and 0 warnings.
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verifier [v3.0.5]
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO:     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:verify]     
[ant:verify]     
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verifying CAP file /Users/dusanklinec/workspace/jcard/applet/out/cap/applet.cap
[ant:verify] javacard/framework/Applet
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verification completed with 0 warnings and 0 errors.
```

