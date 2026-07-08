@echo off
rem Account-Ownership Proof CLI launcher (Windows).
rem `prove` and `setup --tau local` need a large heap; set AOR_JAVA_OPTS, e.g.
rem   set AOR_JAVA_OPTS=-Xmx110g
setlocal
set "DIR=%~dp0.."
for %%f in ("%DIR%\lib\account-ownership-recovery-cli-*-all.jar") do set "JAR=%%f"
if "%JAR%"=="" (
  echo fat jar not found under %DIR%\lib 1>&2
  exit /b 1
)
if "%AOR_JAVA_OPTS%"=="" set "AOR_JAVA_OPTS=-Xmx8g"
java %AOR_JAVA_OPTS% --enable-native-access=ALL-UNNAMED -jar "%JAR%" %*
