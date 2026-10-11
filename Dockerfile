FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY agent ./agent
COPY shared ./shared
COPY tests ./tests
COPY rules ./rules
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel 2 && ctest --test-dir build --output-on-failure
FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/rudy-sentinel"           org.opencontainers.image.description="Rudy Sentinel portable offline replay engine; Windows driver and desktop console are separate"           org.opencontainers.image.licenses="MIT"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home rudy && mkdir /data && chown rudy:rudy /data
COPY --from=build /src/build/rudy-sentinel /usr/local/bin/rudy-sentinel
COPY rules /opt/sentinel/rules
COPY examples /opt/sentinel/examples
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["rudy-sentinel"]
CMD ["--help"]
