#!/bin/bash

# Check if the container already exists and is running
if [ "$(docker ps -aq -f name=postgres_keycloak_demo)" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=postgres_keycloak_demo)" ]; then
        # Cleanup if the container is not running
        docker rm postgres_keycloak_demo
    fi
fi

# Run the postgres container
docker run --name postgres_keycloak_demo -v pgdata_keycloak_demo:/var/lib/postgresql/data -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=password -e POSTGRES_DB=keycloak -p 5432:5432 -d postgres:14

# Wait for PostgreSQL to be ready
./wait-for-it.sh localhost:5433 --timeout=60 --strict -- echo "PostgreSQL is up and running"

# Start Keycloak
docker-compose up -d keycloak
