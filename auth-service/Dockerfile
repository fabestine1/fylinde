# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install Flask-Migrate
RUN pip install Flask-Migrate

# Make wait-for-it.sh and start.sh executable
RUN chmod +x /app/wait-for-it.sh /app/start.sh

# Set the FLASK_APP environment variable
ENV FLASK_APP=/app/main.py

# Run start.sh as the entrypoint
ENTRYPOINT ["./start.sh"]