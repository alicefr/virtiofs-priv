#!/bin/bash -x

# let's use target as temporal directory since it's ignored by git
mkdir -p target/shared-dir
touch target/shared-dir/demo-file

podman run --rm -ti --name demo \
	--user test \
	--security-opt label=disable  \
	--volume $(pwd)/target/shared-dir:/shared-dir:U \
	--security-opt=seccomp=demo.json \
	--annotation run.oci.seccomp.receiver=/tmp/demo.sock \
	vfsd-mock:latest \
	/usr/local/bin/vfsd-mock --shared-dir /shared-dir  --file /shared-dir/demo-file
