@echo off
rem Native-binary launcher (Windows). `prove`/`setup` need a large heap; set AOR_JAVA_OPTS,
rem e.g.  set AOR_JAVA_OPTS=-Xmx90g   (Windows RAM auto-detection is left to the user).
rem Light commands (verify, info, import, export-r1cs) run with the default heap.
setlocal
set "DIR=%~dp0"
set "BIN=%DIR%account-ownership-recovery-cli.exe"
set "JVM="
if not "%AOR_JAVA_OPTS%"=="" set "JVM=%AOR_JAVA_OPTS%"
if "%1"=="prove" if "%JVM%"=="" set "JVM=-Xmx90g"
if "%1"=="setup" if "%JVM%"=="" set "JVM=-Xmx90g"
"%BIN%" %JVM% %*
