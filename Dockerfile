# syntax=docker/dockerfile:1
# Imagem do Sentinels: binário estático + Trivy sobre distroless, sem shell,
# rodando como usuário sem privilégio (65532).
ARG GO_VERSION=1.26
ARG TRIVY_VERSION=0.76.1

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/SantanaCharles/sentinels/internal/version.Version=${VERSION} -X github.com/SantanaCharles/sentinels/internal/version.Commit=${COMMIT}" \
      -o /out/sentinels ./cmd/sentinels \
 && mkdir -p /out/data/reports /out/data/cache /out/data/trivy

FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/sentinels /usr/local/bin/sentinels
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build --chown=65532:65532 /out/data /var/lib/sentinels
COPY sentinels.example.yaml /etc/sentinels/sentinels.example.yaml
ENV TRIVY_CACHE_DIR=/var/lib/sentinels/trivy
# O agente reconhece o próprio container por este label e não se audita.
LABEL io.sentinels.self="true" \
      org.opencontainers.image.title="Sentinels" \
      org.opencontainers.image.description="Agente de segurança para servidores e containers" \
      org.opencontainers.image.source="https://github.com/SantanaCharles/sentinels" \
      org.opencontainers.image.licenses="Apache-2.0"
USER 65532:65532
VOLUME ["/var/lib/sentinels"]
ENTRYPOINT ["/usr/local/bin/sentinels"]
CMD ["watch", "-config", "/etc/sentinels/sentinels.yaml"]
