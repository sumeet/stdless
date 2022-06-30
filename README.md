# stdless

A webserver implemented in Rust without using standard library, calling into Linux system calls using inline Assembly.

## Build Instructions

```console
$ cargo run
$ chrome localhost:8080
```

## Safety Warning

This is totally unsafe webserver. For example, the user can navigate to any file on the host filesystem. So don't really
run this anywhere.