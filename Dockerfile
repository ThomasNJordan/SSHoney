# Use the official Ubuntu 20.04 LTS as the base image
FROM ubuntu:20.04

# Set environment variables to avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update the package repository and install necessary packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libssh-dev \
    libcurl4-openssl-dev \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy your project files into the container
COPY . /app

# Set the working directory
WORKDIR /app

# Expose the SSH port
EXPOSE 2222

# Replace the CMD with ENTRYPOINT to run a shell
ENTRYPOINT ["/bin/bash"]


