FROM golang:1.24.4-bullseye

# Install required tools
RUN apt update && apt install -y \
    cmake \
    ninja-build \
    gcc \
    make \
    git \
    pkg-config \
    libssl-dev

# Build liboqs
RUN git clone --recursive https://github.com/open-quantum-safe/liboqs.git /liboqs && \
    mkdir /liboqs/build && \
    cd /liboqs/build && \
    cmake -GNinja .. -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON && \
    ninja && \
    ninja install

RUN git clone --recursive https://github.com/open-quantum-safe/liboqs-go /liboqs-go

# 🔧 Set PKG_CONFIG_PATH so liboqs-go can find liboqs.pc
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$HOME/liboqs-go/.config
ENV LD_LIBRARY_PATH=/usr/local/lib

# Set up app workspace
WORKDIR /app
COPY . .

# Download Go dependencies
RUN go mod tidy

# Run app
CMD ["go", "run", "main.go"]
