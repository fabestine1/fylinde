# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make wait-for-it.sh and start.sh executable
RUN chmod +x wait-for-it.sh start.sh

# Run start.sh as the entrypoint
ENTRYPOINT ["./start.sh"]
CMD ["sh", "-c", "ls -R /app && python3 .app/main.py"]