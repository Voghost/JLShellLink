FROM eclipse-temurin:21-jre

COPY target/link-stun-server-*.jar /app.jar
USER 65532:65532
ENTRYPOINT ["java", "-jar", "/app.jar"]
