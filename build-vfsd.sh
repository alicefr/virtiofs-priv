#!/bin/bash -x

. vfsd.env

mkdir -p  ${VFSDWD}
cd ${VFSDWD}

mkdir -p socket
mkdir -p shared-dir

git clone https://gitlab.com/virtio-fs/virtiofsd

cd virtiofsd
cp ../../../Dockerfile.vfsd .
cp ../../../run-vfsd.sh .

podman build -t vfsd -f Dockerfile.vfsd
