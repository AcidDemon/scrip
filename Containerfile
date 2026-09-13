FROM docker.io/library/rust:1.98.1-alpine3.24@sha256:1716b3aa042d735f4566d14dc54e8037de9d69556e2d5dd58131d93a613d173d AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets

# musl targets link statically by default. Check with readelf before packaging.
RUN target="$(rustc -vV | sed -n 's/^host: //p')" && \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    cargo build --locked --release --target "$target" && \
    install -d -m 0700 -o 65532 -g 65532 /rootfs/var/lib/scrip && \
    install -m 0755 "target/$target/release/scrip" /rootfs/scrip && \
    readelf -l /rootfs/scrip > /tmp/program-headers && \
    readelf -d /rootfs/scrip > /tmp/dynamic && \
    ! grep -E 'INTERP|NEEDED' /tmp/program-headers /tmp/dynamic

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/AcidDemon/scrip" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /rootfs/ /
USER 65532:65532
WORKDIR /var/lib/scrip
EXPOSE 8080/tcp 9999/tcp
ENTRYPOINT ["/scrip"]
CMD ["run"]
