# Thin runtime image wrapping the account-ownership-recovery-cli fat jar — lets non-Java devs run
# the CLI with only Docker installed.
#
# Build the fat jar first (or drop a release *-all.jar into build/libs/):
#   ./gradlew fatJar
# Then, from the module root (the build context must see build/libs/):
#   docker build -f docker/Dockerfile -t account-ownership-recovery-cli:local .
#
# The key bundle and proofs are NOT baked in — bind-mount them at run time (see docker-compose.yml).
FROM eclipse-temurin:25-jre

WORKDIR /work
COPY build/libs/account-ownership-recovery-cli-*-all.jar /app/app.jar

# --enable-native-access: blst FFM (falls back to pure-Java if the arch lib is absent in the image).
# -Dzeroj.allowInsecureTrustedSetup: gated at the CLI by --i-understand-insecure (only `setup` uses it).
# JAVA_OPTS lets you pass -Xmx for prove/setup, e.g. -e JAVA_OPTS="-Xmx90g".
ENTRYPOINT ["sh", "-c", \
  "exec java ${JAVA_OPTS:-} --enable-native-access=ALL-UNNAMED -Dzeroj.allowInsecureTrustedSetup=true -jar /app/app.jar \"$@\"", \
  "--"]
