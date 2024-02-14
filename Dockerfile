
FROM maven:3.9.6-openjdk-17 AS build
COPY . .
RUN mvn clean package -DskipTests


FROM openjdk:17-jre-slim

COPY --from=build target/ClientMicrocervice-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
