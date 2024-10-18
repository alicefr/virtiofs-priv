# Virtiofs root daemon

Using seccomp notifier to run virtiofs rootless.

## Testing with the mock
### Build
```bash
cargo build
```
### Demo
Build the mock virtiofs image:
```bash
 podman build -t vfsd-mock -f Dockerfile.mock
```
Run the virtiofs-priv program:
```bash
./target/debug/vfsd-priv -s /tmp/demo.sock
```
Launch the rootless container with the `demo.sh` script
```bash
./demo-mock.sh
+ podman run --rm -ti --name demo --user test -w /home/test --security-opt=seccomp=demo.json --annotation run.oci.seccomp.receiver=/tmp/demo.sock vfsd-mock:latest /usr/local/bin/vfsd-mock --shared-dir /home/test/share-dir --file /home/test/share-dir/demo
it works!
```

The `demo.json` is the standard profile, which can be found under `/usr/share/containers/seccomp.json` plus the seccomp notification:
```json
{
       "action" : "SCMP_ACT_NOTIFY",
       "names" : [
                "open_by_handle_at",
                "name_to_handle_at"
       ]
}
```
