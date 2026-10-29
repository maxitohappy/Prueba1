# Herramientas gratuitas de pentesting, aisladas en un contenedor.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends hydra sqlmap curl ca-certificates john \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
CMD ["bash"]
