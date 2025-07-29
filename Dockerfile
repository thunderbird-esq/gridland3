# Use an official Python image as a parent image
FROM python:3.9-slim

# --- Set Build-Time Argument for the API Key ---
# This declares a build argument that we will pass in from the command line.
ARG SHODAN_API_KEY_ARG

# --- Set Environment Variable from the Argument ---
# This creates a permanent environment variable inside the image from the build argument.
# The server.py script will read this variable.
ENV SHODAN_API_KEY=$SHODAN_API_KEY_ARG

# Set the working directory in the container
WORKDIR /app

# --- Install System Dependencies ---
# Install GStreamer and other necessary tools.
RUN apt-get update && apt-get install -y \
    gstreamer1.0-tools \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    && rm -rf /var/lib/apt/lists/*

# --- Install Python Dependencies ---
# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Copy Application Code ---
# Copy all application files
COPY . .

# --- Expose Port and Run Application ---
EXPOSE 8080
CMD ["python3", "server.py"]

