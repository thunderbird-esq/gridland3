# Use an official Python image as a parent image
FROM python:3.9-slim

# --- HuggingFace Spaces Configuration ---
# HuggingFace Spaces requires port 7860
ENV PORT=7860

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

# --- Create non-root user for HuggingFace Spaces ---
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app
COPY --chown=user . $HOME/app

# --- Expose Port and Run Application ---
EXPOSE 7860
CMD ["python3", "server.py"]
