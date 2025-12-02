require "../src/shirk"

# =============================================================================
# High-Level SSH Server Example
# =============================================================================
#
# This example shows how to use Shirk::Server, the high-level API for building
# SSH servers. It provides a callback-based interface that handles all the
# low-level libssh details for you.
#
# KEY BEHAVIORS:
#
# 1. COMMAND EXECUTION:
#    - If you set `on_exec`, YOUR handler processes all commands manually
#      using ctx.write() for output and returning an exit code
#    - If you DON'T set `on_exec`, commands are executed via /bin/sh automatically
#      (like the low-level ssh_server.cr example)
#
# 2. STDIN HANDLING:
#    - When using on_exec: use ctx.read() to read client input
#    - When NOT using on_exec: stdin is piped to the spawned process automatically
#      and EOF is properly propagated (so `cat`, `gets_to_end`, etc. work)
#
# 3. AUTHENTICATION:
#    - on_auth_password: receives (user, password), return true to accept
#    - on_auth_pubkey: receives (user, fingerprint), return true to accept
#    - If no handlers set, falls back to Server's username/password properties
#
# For a server that just runs shell commands (like a real SSH server), simply
# don't set on_exec and it will execute commands automatically. See the bottom
# of this file for that simpler example.
#
# =============================================================================

# This example uses on_exec to handle commands manually (no shell execution)
server = Shirk::Server.new(
  host: "0.0.0.0",
  port: 2222,
  host_key: "ssh_host_rsa_key"
)

# Accept all public keys and print the fingerprint
server.on_auth_pubkey do |user, fingerprint|
  puts "Pubkey auth: user=#{user} fingerprint=#{fingerprint}"
  true # Accept
end

# Also accept password "secret" for user "admin"
server.on_auth_password do |user, password|
  puts "Password auth: user=#{user}"
  user == "admin" && password == "secret"
end

# Handle exec requests MANUALLY - commands are NOT executed via shell
# Remove this block to have commands executed automatically via /bin/sh
server.on_exec do |ctx|
  puts "Exec: #{ctx.command}"

  case ctx.command
  when "whoami"
    ctx.write("admin\n")
    0
  when "echo hello"
    ctx.write("hello\n")
    0
  when "fail"
    ctx.write_stderr("Command failed!\n")
    42
  when "cat"
    # Example: reading stdin from the client
    # Use ctx.read() to read data sent by the client.
    # Test with: echo "hello" | ssh -p 2222 admin@localhost cat
    #
    # NOTE: ctx.read() returns whatever data is available (up to max_bytes).
    # It may return partial data or empty string. For complete input,
    # you may need to loop until you have all the data you need.
    input = ctx.read(4096)
    ctx.write(input)
    0
  when "uppercase"
    # Another stdin example: transform input to uppercase
    # Test with: echo "hello world" | ssh -p 2222 admin@localhost uppercase
    input = ctx.read(4096)
    ctx.write(input.upcase)
    0
  else
    ctx.write("You said: #{ctx.command}\n")
    0
  end
end

puts "Starting SSH server on port 2222..."
puts "Test with: ssh -p 2222 admin@localhost whoami"
server.run

# =============================================================================
# SIMPLER EXAMPLE: Auto-execute commands via shell
# =============================================================================
#
# If you want a server that just runs commands (like a real SSH server),
# don't set on_exec:
#
#   server = Shirk::Server.new(
#     host: "0.0.0.0",
#     port: 2222,
#     host_key: "ssh_host_rsa_key"
#   )
#
#   server.on_auth_password do |user, password|
#     user == "admin" && password == "secret"
#   end
#
#   server.run
#
# This will execute any command the client sends via /bin/sh, with proper
# stdin/stdout/stderr handling. Example:
#
#   echo "hello" | ssh -p 2222 admin@localhost cat
#   # Output: hello
#
# =============================================================================
