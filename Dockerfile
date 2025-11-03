# Importing JDK and copying required files
FROM openjdk:21-jdk-slim AS build
WORKDIR /app
COPY pom.xml .
COPY src src

# Copy Maven wrapper
COPY mvnw .
COPY .mvn .mvn

# Set execution permission for the Maven wrapper
RUN chmod +x ./mvnw
RUN ./mvnw clean package -DskipTests


FROM openjdk:21-jdk-slim
VOLUME /tmp


COPY --from=build /app/target/*.jar /api-gateway.jar
ENTRYPOINT ["java","-jar","api-gateway.jar"]
EXPOSE 8080