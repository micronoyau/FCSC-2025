FROM ubuntu:24.04 AS builder
WORKDIR /app
RUN apt-get update                              && \
    apt-get install -qy --no-install-recommends    \
        socat=1.8.*                             && \
    apt-get clean                               && \
    rm -rf /var/lib/apt/lists/                  && \
    useradd ctf
COPY --chown=ctf:ctf   --chmod=500 ./compiled/http3         /app
COPY --chown=ctf:ctf   --chmod=400 ./src/flag.txt           /app
COPY --chown=root:root --chmod=755 ./compiled/libc-2.39.so  /lib/x86_64-linux-gnu/libc.so.6
COPY --chown=root:root --chmod=755 ./compiled/ld-2.39.so    /lib64/ld-linux-x86-64.so.2
USER ctf
EXPOSE 4000
CMD ["/usr/bin/socat", "tcp-listen:4000,reuseaddr,fork", "exec:'/usr/bin/timeout -k 121 120 /app/http3'"]
