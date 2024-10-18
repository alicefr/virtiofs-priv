#!/bin/bash -x

. vfsd.env

podman run --rm -ti --name demo \
	--user test \
	--security-opt label=disable  \
	--volume $(pwd)/${VFSDWD}/shared-dir:/shared-dir:U \
	--security-opt=seccomp=demo.json \
	--annotation run.oci.seccomp.receiver=/tmp/demo.sock \
        --volume $(pwd)/${VFSDWD}/socket:/socket:U \
        vfsd:latest \
        /bin/bash
        #/usr/local/bin/virtiofsd --socket-path=/socket/vsfd.sock --shared-dir=/shared-dir --sandbox=none --log-level=debug --inode-file-handles=mandatory



