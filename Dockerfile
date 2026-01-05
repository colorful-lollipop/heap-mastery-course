FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Create non-root user early
RUN useradd -m -s /bin/bash student && \
    echo "student:student" | chpasswd && \
    usermod -aG sudo student

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    gdb \
    python3 \
    python3-pip \
    python3-dev \
    git \
    vim \
    nano \
    file \
    strace \
    ltrace \
    checksec \
    libc6-dbg \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --upgrade pip && \
    pip3 install \
    pwntools \
    ROPgadget \
    one_gadget \
    capstone \
    keystone-engine

# Install Pwndbg
WORKDIR /opt
RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh --update

# Install GEF (alternative to pwndbg)
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Set up security limits
RUN echo "student hard nproc 64" >> /etc/security/limits.conf && \
    echo "student hard memlock 65536" >> /etc/security/limits.conf && \
    echo "student hard fsize 1048576" >> /etc/security/limits.conf

# Create project directory
WORKDIR /home/student/heap-course

# Copy project files
COPY --chown=student:student . /home/student/heap-course

# Build the project
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make

# Set environment variables for debugging
ENV LD_PRELOAD=
ENV DEBUG=1

# Switch to non-root user
USER student

# Set up GDB to use pwndbg by default
RUN echo "source /opt/pwndbg/gdbinit.py" >> /home/student/.gdbinit

# Expose common ports (if needed for remote debugging)
# EXPOSE 1234

# Default command
CMD ["/bin/bash"]
