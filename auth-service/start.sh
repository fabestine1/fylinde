#!/bin/bash

# Step 1: Ensure the wait-for-it script is executable
chmod +x ./wait-for-it.sh

# Step 2: Wait for MySQL to be ready
echo "Waiting for MySQL to initialize..."
./wait-for-it.sh db:3307 --timeout=180 --strict -- echo "Database is ready."

# Step 3: Start the Flask application
echo "Starting auth-service..."
exec python3 ./app/main.py
