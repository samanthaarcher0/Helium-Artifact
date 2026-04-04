# Base image
FROM python:3.11

# Set working directory
WORKDIR /helium

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    vim \
    less \
    python3-dev \
    ninja-build \
    pkg-config \
    libgmp-dev \
    libmpfr-dev \
    libboost-all-dev \
    time \
    && rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir meson cython

# Install Bitwuzla
RUN git clone https://github.com/bitwuzla/bitwuzla.git && \
    cd bitwuzla && \
    pip install .

# Copy code into docker
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Unzip Intel Pin and build pin tool
WORKDIR /helium/Leakage-Quantification
RUN wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-4.1-99687-gd9b8f822c-gcc-linux.tar.gz
RUN tar -xvf pin-external-4.1-99687-gd9b8f822c-gcc-linux.tar.gz
ENV PIN_ROOT=/helium/Leakage-Quantification/pin-external-4.1-99687-gd9b8f822c-gcc-linux
RUN cd pin-leakage_function_simulation && \
    mkdir obj-intel64 && \
    make obj-intel64/TracerSim.so

# Default: open a shell
CMD ["/bin/bash"]
