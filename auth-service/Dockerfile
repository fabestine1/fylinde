# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Dockerfile snippet
COPY ./start.sh /app/start.sh
RUN cat /app/start.sh  # Add this line to print the script content

# Add this line to print the directory contents during the build process
RUN ls -l /app


# Install curl for connectivity checks
RUN apt-get update && apt-get install -y curl

# Install required packages
#RUN apt-get update && apt-get install -y iputils-ping

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install Flask-Migrate
RUN pip install Flask-Migrate

# Make wait-for-it.sh and start.sh executable
RUN chmod +x /app/wait-for-it.sh /app/start.sh

# Copy entrypoint.sh and make it executable
RUN chmod +x /app/entrypoint.sh

# Ensure entrypoint.sh is executable and check if it exists
RUN chmod +x /app/entrypoint.sh && ls -l /app/entrypoint.sh


# Set the FLASK_APP environment variable
ENV FLASK_APP=/app/main.py

# Run start.sh as the CMD
CMD ["./start.sh"]
