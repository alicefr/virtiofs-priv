#!/bin/bash -xe

podman run --rm -ti --name demo \
	--user test \
	 -w /home/test \
	--security-opt=seccomp=demo.json \
	--annotation run.oci.seccomp.receiver=/tmp/demo.sock \
	vfsd-mock:latest \
	/usr/local/bin/vfsd-mock --shared-dir /home/test/share-dir  --file /home/test/share-dir/demo
#	busybox \
#	sh -c "touch /tmp/blabla && chown 1000:1000 /tmp/blabla"
