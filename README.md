# Shirk

A Crystal library for building SSH servers using libssh. Provides both low-level FFI bindings and a high-level callback-based API.

## ⚠️ Important Limitations

**This library is designed for non-interactive SSH command execution**, such as:

- Remote API endpoints
- Automated deployment commands
- CI/CD integrations
- Git-over-SSH servers

**It is NOT suitable for:**

- Interactive shells (bash, zsh, etc.)
- Full terminal emulation (PTY)
- Real-time streaming input/output
- Commands that require user interaction (vim, nano, less, etc.)

### Stdin Handling

The high-level API (`Shirk::Server`) collects **all stdin before calling your handler**. This means:

- ✅ `echo "data" | ssh host command` works - all piped data is available in `ctx.stdin`
- ✅ `ssh host command` without stdin works - handler is called after a short timeout with empty `ctx.stdin`
- ❌ Interactive input doesn't work - there's no way to read/write incrementally

If you need more control over stdin handling, use the low-level API (see `examples/ssh_server.cr`) which provides raw callbacks for data as it arrives.

## Requirements

- Crystal 1.0+
- libssh (install via your package manager)

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  shirk:
    github: ralsina/shirk
```

## High-Level API

The `Shirk::Server` class provides a clean callback-based interface:

```crystal
require "shirk"

server = Shirk::Server.new(
  host: "0.0.0.0",
  port: 2222,
  host_key: "ssh_host_rsa_key"
  # KEX algorithms default to include post-quantum support:
  # ml-kem-768-sha256-x25519-sha256@libssh.org:sntrup761x25519-sha512@openssh.com:...
)

# Public key authentication - receives SHA256 fingerprint
server.on_auth_pubkey do |user, fingerprint|
  puts "Key auth: #{user} with #{fingerprint}"
  true  # accept all keys
end

# Password authentication
server.on_auth_password do |user, password|
  user == "admin" && password == "secret"
end

# Handle exec requests
server.on_exec do |ctx|
  puts "Command: #{ctx.command}"
  ctx.write("Hello, #{ctx.user}!\n")
  ctx.write_stderr("No errors\n")
  0  # exit code
end

server.run
```

### ExecContext

The `on_exec` callback receives an `ExecContext` with:

- `ctx.command` - the command string
- `ctx.user` - authenticated username
- `ctx.stdin` - all stdin data from client (collected before handler runs)
- `ctx.write(data)` - write to stdout
- `ctx.write_stderr(data)` - write to stderr
- Return value is the exit code

### Features

- **Post-quantum cryptography** - supports ML-KEM-768x25519 and SNTRUP761x25519 key exchange algorithms by default
- **Fork model** - each connection runs in a child process for isolation
- **Password auth** via `on_auth_password` callback
- **Public key auth** via `on_auth_pubkey` callback (receives SHA256 fingerprint)
- **Exec handling** with proper stdout/stderr/exit status
- **Shell support** via `on_shell` callback (optional)

## Low-Level API

For more control, use the FFI bindings directly. See `examples/ssh_server.cr` for a complete example that closely follows the libssh C API.

## Examples

### Simple Server

```shell
crystal build examples/simple_server.cr -o simple_server
./simple_server
```

Test with:
```shell
ssh -p 2222 admin@localhost  # password: secret
# or with Python
python3 -c "import paramiko; c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy()); c.connect('localhost',2222,username='admin',password='secret'); print(c.exec_command('whoami')[1].read())"
```

### Generate Host Key

```shell
ssh-keygen -t rsa -b 2048 -f ssh_host_rsa_key -N ""
```

## Development

```shell
shards install
crystal spec
crystal build examples/simple_server.cr
```

## Contributing

1. Fork it (<https://github.com/ralsina/shirk/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Roberto Alsina](https://github.com/ralsina) - creator and maintainer
