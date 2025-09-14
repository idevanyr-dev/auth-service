FROM eclipse-temurin:21-jdk-jammy

# Set working directory
WORKDIR /app

# Copy gradle wrapper and build files
COPY gradle/ gradle/
COPY gradlew build.gradle settings.gradle ./

# Make gradlew executable
RUN chmod +x ./gradlew

# Copy source code
COPY src/ src/

# Build the application
RUN ./gradlew build -x test --no-daemon

# Copy the built JAR file
COPY build/libs/auth-service-0.0.1-SNAPSHOT.jar app.jar

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/auth/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]