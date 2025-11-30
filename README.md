# Shirk

Shirk is an experiment in wrapping **libssh** with Crystal. It contains both
direct translations of the C sample servers and a higher-level API that makes
writing echo-style SSH services straightforward.

## High-level server API

`Shirk::SshServer` (defined in `src/shirk/server_simple.cr`) is a thin wrapper
around libssh that keeps all callback structs, session state, and channel
handlers on the Crystal side. You only need to inherit from `Shirk::SshServer`
and override the hooks you care about:

```crystal
class TestServer < Shirk::SshServer
  def initialize
    super(host_key: "/etc/ssh/ssh_host_rsa_key", port: 8888)
  end

  def auth_publickey(session_id, username, fingerprint, signature_state)
    puts "[#{session_id}] #{username} => #{fingerprint} (state #{signature_state})"
    signature_state == 1
  end

  def on_channel_data(session_id, channel_id, data)
    puts "[#{session_id}] #{data.size} bytes"
    super # default implementation echoes the data
  end
end

TestServer.new.start
sleep
```

The class takes care of:

- Owning and initializing `ssh_server_callbacks_struct` /
  `ssh_channel_callbacks_struct` so libssh never dereferences freed memory.
- Boxing the Crystal receiver once and reusing the pointer across callbacks.
- Extracting and printing the client public-key fingerprint during auth.
- Driving the libssh event loop until both authentication and channel
  creation succeed, then echoing data back to the client by default.

See `examples/simple_high_level.cr` for a complete runnable server using this
API. Run it with:

```shell
crystal run examples/simple_high_level.cr
```

Then connect via SSH (e.g. `ssh -p 8888 myuser@localhost`) and watch the
server log the fingerprint and echo your keystrokes.

## Low-level sample

`examples/samplesshd-cb.cr` is a nearly line-for-line translation of the
upstream libssh callback sample. It is useful for checking behavior against the
original C implementation.

## Development

Clone the repository and install dependencies:

```shell
shards install
```

Useful commands:

- `crystal build examples/simple_high_level.cr`
- `crystal run examples/simple_high_level.cr`
- `crystal spec`

## Contributing

1. Fork it (<https://github.com/ralsina/shirk/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Roberto Alsina](https://github.com/ralsina) - creator and maintainer
