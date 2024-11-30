cargo build || exit 1

sudo ./target/debug/tracer "$@"