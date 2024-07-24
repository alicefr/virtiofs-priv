#!/bin/bash -xe

podman run --rm -ti --name demo \
	--user 1000 \
	--security-opt=seccomp=demo.json \
	--annotation run.oci.seccomp.receiver=/tmp/demo.sock \
	busybox \
	sh -c "touch /tmp/blabla && chown 1000:1000 /tmp/blabla"
