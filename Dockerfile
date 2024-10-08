FROM rust:slim as builder

RUN mkdir /src
COPY . /src
WORKDIR /src
RUN cargo build


FROM quay.io/centos/centos:stream9

Run yum install -y strace && yum clean all

COPY --from=builder /src/target/debug/vfsd-mock /usr/local/bin/vfsd-mock
RUN useradd -ms /bin/bash test
USER test
