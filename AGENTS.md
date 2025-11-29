# Repository Guidelines

## Project Structure & Module Organization
- `applet/`: JavaCard source set; configure AID and CAP settings in `applet/build.gradle`. Output CAP lives under `applet/out/cap/`.
- `libs/`: vendored GlobalPlatform/Visa helper JARs resolved via the Gradle flatDir repo.
- `libs-sdks/`: local JavaCard SDK bundles (e.g., `jc304_kit`, `jc310b43_kit`); Gradle picks one via `JC_SELECTED` in `applet/build.gradle`.
- `.github/workflows/`: CI templates for publishing; keep build commands consistent with these.

## Build, Test, and Development Commands
- `./gradlew buildJavaCard --info --rerun-tasks`: compile and package the applet CAP using the selected SDK.
- `./gradlew test`: run JUnit/JUnit5/TestNG tests (platform uses JUnit Jupiter; manual-tagged tests are excluded).
- `./gradlew manualTests`: runs tests tagged `manual` defined in the Gradle test configuration.
- `./gradlew dumpClassPath`: print Gradle/IDEA classpaths to diagnose dependency issues.
Tips: ensure the Java toolchain is ≤ 1.8 when targeting JC222 or lower; upgrade `JC_SELECTED` and `cap.targetsdk` together.

## Coding Style & Naming Conventions
- Language: Java 8; use 4-space indentation and package prefix `applet`.
- AIDs: keep hex uppercase and colon-separated (`A0:00:00:03:41:00:01:01`); update both package and applet AIDs together.
- Classes: PascalCase; methods camelCase; constants UPPER_SNAKE_CASE.
- Logging: `log4j.properties` lives in `applet/src/test/resources/`; prefer SLF4J API over raw Log4j calls.

## Testing Guidelines
- Frameworks: JUnit4/5 and TestNG are available; prefer JUnit5 for new tests.
- Location: put unit tests under `applet/src/test/java`.
- Naming: mirror source package; suffix classes with `Test`; tag slow/hardware-dependent cases with `@Tag("manual")` so they only run via `manualTests`.
- Aim to cover APDU command flows and purse state transitions; include negative cases (bad CLA/INS, invalid MAC, depleted balance).

## Commit & Pull Request Guidelines
- Commit messages in this repo are short imperative lines (e.g., `Update gradlew`, `Create gradle-publish.yml`); follow that style.
- Keep changes focused; include a brief rationale in the body if behavior changes (AID switch, SDK bump, CAP format).
- PRs: describe purpose, build/test results (`buildJavaCard`, `test`, `manualTests` if relevant), and any card personalization steps. Link related issues; attach screenshots or logs only when they clarify APDU behavior or CAP generation.

## Security & Configuration Tips
- Never commit vendor SDK binaries beyond `libs-sdks/`; keep licenses in mind.
- Rotate AIDs for production cards and avoid sharing proprietary keys; store personalization keys outside the repo (env vars or local config).
- Before distributing CAPs, verify with `gradlew buildJavaCard` and run on a clean SDK to avoid leaking debug dependencies.
