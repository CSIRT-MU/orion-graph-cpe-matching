FROM maven:3.6-openjdk-11-slim

RUN mkdir /app
COPY ./src/ /app/src/
COPY ./pom.xml /app/

WORKDIR /app

RUN mvn test -DskipTests