# Step 1: Build the app using a Maven image with OpenJDK 17
FROM maven:3.8-openjdk-17 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the pom.xml and the source code
COPY pom.xml .
COPY src ./src

# Run Maven to build the app and skip tests (optional)
RUN mvn clean package -DskipTests

# Step 2: Create the runtime container with OpenJDK 17
FROM openjdk:17

# Set the working directory inside the container
WORKDIR /app

# Copy the built JAR file from the build container
COPY --from=build /app/target/security-0.0.1-SNAPSHOT.jar /app/security.jar

# Expose the port that the Spring Boot app will run on (default: 8080)
EXPOSE 8080

# Run the Spring Boot application
ENTRYPOINT ["java", "-jar", "/app/security.jar"]
