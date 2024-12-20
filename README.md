# Tracer

Ptrace-based cdylib injector for Linux x86_64

## Usage

```
> ./run.sh <process_name/pid:pid> <library_path>
Options:
        -m: Mask the library with a random library in /usr/lib
        -c: Divide masking library into chunks and mprotect each chunk
```
