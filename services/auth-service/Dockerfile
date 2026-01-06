FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /app

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

RUN ./mvnw -B -q -DskipTests dependency:go-offline

COPY src src

RUN ./mvnw -B -q -DskipTests package


FROM eclipse-temurin:21-jre-alpine

RUN addgroup -g 1001 -S appgroup \
    && adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

RUN chown -R appuser:appgroup /app

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget -q0- -f http://localhost:8081/actuator/health || exit 1

EXPOSE 8081

ENV JAVA_OPTS="-XX:+UseContainerSupport \
               -XX:MaxRAMPercentage=75.0 \
               -XX:InitialRAMPercentage=50.0 \
               -XX:+UseG1GC \
               -XX:+ExitOnOutOfMemoryError \
               -Djava.security.egd=file:/dev/./urandom"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
