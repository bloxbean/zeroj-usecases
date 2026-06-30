FROM eclipse-temurin:25-jdk AS build

ARG USECASE_DIR
ARG APP_NAME
ARG ZEROJ_VERSION=0.1.0-pre4
ARG PUBLISH_LOCAL_ZEROJ=true
ARG ZEROJ_PUBLISH_TASKS=":zeroj-api:publishToMavenLocal :zeroj-backend-spi:publishToMavenLocal :zeroj-codec:publishToMavenLocal :zeroj-bls12381:publishToMavenLocal :zeroj-blst:publishToMavenLocal :zeroj-crypto:publishToMavenLocal :zeroj-circuit-dsl:publishToMavenLocal :zeroj-circuit-annotation-api:publishToMavenLocal :zeroj-circuit-lib:publishToMavenLocal :zeroj-circuit-annotation-processor:publishToMavenLocal :zeroj-verifier-groth16:publishToMavenLocal :zeroj-verifier-plonk:publishToMavenLocal :zeroj-onchain-julc:publishToMavenLocal"

WORKDIR /workspace/zeroj
COPY --from=zeroj-src . ./

RUN if [ "${PUBLISH_LOCAL_ZEROJ}" = "true" ]; then \
      chmod +x ./gradlew \
      && ./gradlew --no-daemon ${ZEROJ_PUBLISH_TASKS} -x test -PskipSigning; \
    fi

WORKDIR /workspace/usecase
COPY ${USECASE_DIR}/ ./

RUN chmod +x ./gradlew \
    && ./gradlew --no-daemon installDist -x test -PzerojVersion=${ZEROJ_VERSION}

FROM eclipse-temurin:25-jre

ARG APP_NAME
ENV APP_NAME=${APP_NAME}
ENV RUN_YACI=true
ENV YACI_BASE_URL=http://host.docker.internal:8080/api/v1/
ENV YACI_ADMIN_URL=http://host.docker.internal:10000
ENV YACI_HEALTH_URL=http://host.docker.internal:8080/api/v1/epochs/latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /workspace/usecase/build/install/${APP_NAME}/ ./
COPY docker/run-cli-usecase.sh /usr/local/bin/run-cli-usecase
RUN chmod +x /usr/local/bin/run-cli-usecase

ENTRYPOINT ["/usr/local/bin/run-cli-usecase"]
