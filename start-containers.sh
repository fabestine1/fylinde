#!/bin/bash

# Check if the container exists
if [ "$(docker ps -aq -f name=postgres_keycloak_demo)" ]; then
    echo "Removing existing PostgreSQL container..."
    docker rm -f postgres_keycloak_demo
fi

# Create a persistent volume for PostgreSQL if it doesn't already exist
docker volume create keycloak_postgres_data

# Run the PostgreSQL container with the persistent volume
docker run -v keycloak_postgres_data:/var/lib/postgresql/data -p 5433:5433 --name postgres_keycloak_demo -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=password -d postgres:14.2

# Run docker-compose to start all other services
docker-compose up --build
