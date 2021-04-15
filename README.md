# resync: send a file to remote host, repeatedly

`resync` is a super-simple utility that opens an SSH connection to a remote
host, watches a remote file for changes, and copies the file to the remote
host when it notices a change. You could certainly implement this yourself
with some sort of shell loop; I wrote this because I had to copy a binary to
a remote system over and over again, where the SSH handshake would take more
than a few seconds each time, and I got tired of waiting. This utility keeps
the session open while watching the local file, so that handshaking only
happens once.

## tl;dr

```
$ resync local_file remote_host:/remote/path/to/file
INFO - connected to remote_host.
INFO - resyncing local_file => /remote/path/to/file
INFO - local_file => /remote/path/to/file in 1.21s (3.5 MB/s)
INFO - watching local file for changes
[...time passes, file changes...]
INFO - resyncing local_file => /remote/path/to/file
INFO - local_file => /remote/path/to/file in 0.73s (5.9 MB/s)
```

## Installation

For now you have to use `cargo` to build and install it. When I have a few
more pain points corrected, I will upload it to crates.io. Until then...

```
git clone https://github.com/Crosse/resync.git
cd resync
cargo install --path .
```

## Issues

Just like Genie in Aladdin, this comes with some caveats and addendums. While
it uses `libssh` under the hood, it doesn't parse your SSH config, so it
won't know about any custom proxies or any other SSH configuration you might
have. (This is sad and I'd love to fix it.) It also doesn't do any DNS
resolution on the remote host, and for some reason `libssh` can't find
non-FQDN names in your `known_hosts` file.

## License

MIT. Feel free to fork, modify, and not give back, as long as the license
stays intact. (I mean, I'd love it if you _did_ upstream any changes, but you
do you.) I made this for me, and any benefit others might derive from it is
really tangential to its original purpose.
