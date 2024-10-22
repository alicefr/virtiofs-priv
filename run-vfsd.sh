#!/bin/bash -x

/usr/local/bin/virtiofsd --socket-path=/socket/vsfd.sock --shared-dir=/shared-dir --sandbox=none --log-level=debug --inode-file-handles=mandatory
