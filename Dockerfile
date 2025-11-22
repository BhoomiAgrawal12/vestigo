FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    gcc-arm-linux-gnueabihf \
    gcc-mips-linux-gnu \
    gcc-riscv64-linux-gnu \
    gcc-avr \
    avr-libc \
    clang \
    llvm \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
