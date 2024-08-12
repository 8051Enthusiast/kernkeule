kernkeule
=========

Takes a process, calls `clone(2)` on it using ptrace, and then loads a new binary into the child process, replacing the original one but still keeping the old memory mappings.

Call it like this:
```
$ kernkeule <pid> <new-binary> [args...]
```

Right now it only works on x86_64 Linux with kernel version >= 5.9.
It can be installed using `cargo install --path .` in case you actually need this cursed thing.