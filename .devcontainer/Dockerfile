FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-lc"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sudo curl git build-essential cmake pkg-config \
    libcurl4-openssl-dev libssl-dev libjsoncpp-dev \
    libnghttp2-dev libidn2-dev librtmp-dev libssh2-1-dev libpsl-dev \
    libkrb5-dev libldap2-dev libzstd-dev libbrotli-dev zlib1g-dev \
  && rm -rf /var/lib/apt/lists/*

RUN set -eux; triplet="$(gcc -dumpmachine)"; \
  [ -d /usr/include/curl ] || ln -s "/usr/include/${triplet}/curl" /usr/include/curl; \
  [ -d /usr/include/json ] || ln -s /usr/include/jsoncpp/json /usr/include/json

# Build environment is now ready for dynamic linking with gcc/g++

# Keep the container alive for Dev Containers
CMD ["bash", "-lc", "sleep infinity"]
