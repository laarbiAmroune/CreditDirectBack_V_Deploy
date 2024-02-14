# Build Stage
FROM maven:3.8.4-openjdk-17 AS build
COPY . .
RUN mvn clean package -DskipTests

# Final Stage
FROM adoptopenjdk:11-jre-hotspot

COPY --from=build target/ClientMicrocervice-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
