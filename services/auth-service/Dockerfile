FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /app

COPY mvnw pom.xml ./
COPY .mvn .mvn

RUN ./mvnw -B -q -DskipTests dependency:go-offline

COPY src src

RUN ./mvnw -B -q -DskipTests package


FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache curl \
    && addgroup -S appgroup \
    && adduser -S appuser -G appgroup -u 1001

WORKDIR /app

COPY --from=build /app/target/auth-service-*.jar app.jar

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 \
               -XX:InitialRAMPercentage=50.0 \
               -XX:+UseG1GC \
               -XX:+ExitOnOutOfMemoryError"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

USER appuser

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
