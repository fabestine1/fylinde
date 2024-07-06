# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install curl for connectivity checks
RUN apt-get update && apt-get install -y curl

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

# Make port 5004 available to the world outside this container
EXPOSE 5004

# Set the FLASK_APP environment variable
ENV FLASK_APP=/app/app/main.py
ENV FLASK_ENV=development

# Run start.sh as the CMD
CMD ["./start.sh"]
