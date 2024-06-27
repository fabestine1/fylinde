#!/bin/bash

# Log start of the script
echo "Starting start.sh script..."

# Ensure the wait-for-it script is executable
chmod +x ./wait-for-it.sh
echo "wait-for-it.sh script is now executable."

# Wait for MySQL to be ready
echo "Waiting for MySQL to initialize..."
./wait-for-it.sh db:3307 --timeout=180 --strict -- echo "Database is ready."

# Check if the database is ready
if [ $? -ne 0 ]; then
  echo "Database is not ready. Exiting..."
  exit 1
fi

# Log database readiness
echo "Database is ready."

# Set the FLASK_APP environment variable
export FLASK_APP=/app/app/main.py
echo "FLASK_APP is set to $FLASK_APP"

# Set the PYTHONPATH environment variable
export PYTHONPATH=/app
echo "PYTHONPATH is set to $PYTHONPATH"

# Navigate to the app directory
cd /app
echo "Current directory is $(pwd)"

# Log the files in the current directory
echo "Files in the current directory:"
ls -l

# Check if main.py exists
if [ ! -f app/main.py ]; then
  echo "main.py does not exist in the /app directory. Exiting..."
  exit 1
fi

# Check if migrations folder exists
if [ ! -d "migrations" ]; then
  echo "Migrations folder does not exist. Initializing migrations..."
  flask db init
fi

# Run database migrations
echo "Running database migrations..."
flask db migrate -m "Initial migration."
flask db upgrade
if [ $? -ne 0 ]; then
  echo "Database migrations failed. Exiting..."
  exit 1
fi

# Log successful migration
echo "Database migrations completed successfully."

# Start the Flask application
echo "Starting auth-service..."
python -m flask run --host=0.0.0.0
