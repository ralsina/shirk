require "../src/shirk"

# =============================================================================
# High-Level SSH Server Example
# =============================================================================
#
# This example demonstrates the Shirk::Server high-level API with both
# on_exec and on_shell handlers. It reads all stdin from the client and
# echoes it back.
#
# TEST COMMANDS:
#
#   # Test exec with stdin:
#   echo "hello world" | ssh -p 2222 admin@localhost mycommand
#
#   # Test shell with stdin:
#   echo "hello from shell" | ssh -p 2222 admin@localhost
#
# KEY BEHAVIORS:
#
# 1. on_exec: Called when client runs a command (ssh host command)
#    - ctx.command contains the command string
#    - ctx.read() reads stdin from client (returns "" when no more data)
#    - ctx.write() sends to client stdout
#    - ctx.write_stderr() sends to client stderr
#    - Return value is the exit code
#
# 2. on_shell: Called when client requests interactive shell (ssh host)
#    - Same as on_exec but ctx.command is empty
#
# 3. Authentication:
#    - on_auth_password: receives (user, password), return true to accept
#    - on_auth_pubkey: receives (user, fingerprint), return true to accept
#
# =============================================================================

server = Shirk::Server.new(
  host: "0.0.0.0",
  port: 2222,
  host_key: "ssh_host_rsa_key"
)

# Accept all public keys
server.on_auth_pubkey do |user, fingerprint|
  puts "Pubkey auth: user=#{user} fingerprint=#{fingerprint}"
  true
end

# Accept password "secret" for user "admin"
server.on_auth_password do |user, password|
  puts "Password auth: user=#{user}"
  user == "admin" && password == "secret"
end

# Handle exec requests (ssh host command)
server.on_exec do |ctx|
  # Print the command received from the client
  ctx.write("Command: #{ctx.command}\n")

  # Read all stdin until EOF
  # ctx.read() returns "" when there's no more data
  all_input = String::Builder.new
  loop do
    chunk = ctx.read(4096)
    break if chunk.empty?
    all_input << chunk
  end

  # Print all the input received
  input = all_input.to_s
  if input.empty?
    ctx.write("No input received.\n")
  else
    ctx.write("Input received (#{input.bytesize} bytes):\n")
    ctx.write(input)
  end

  0 # Exit code
end

# Handle shell requests (ssh host)
server.on_shell do |ctx|
  ctx.write("Shell session started. Send input and close stdin (Ctrl+D).\n")

  # Read all stdin until EOF
  all_input = String::Builder.new
  loop do
    chunk = ctx.read(4096)
    break if chunk.empty?
    all_input << chunk
  end

  # Print all the input received
  input = all_input.to_s
  if input.empty?
    ctx.write("No input received.\n")
  else
    ctx.write("Input received (#{input.bytesize} bytes):\n")
    ctx.write(input)
  end

  0 # Exit code
end

puts "Starting SSH server on port 2222..."
puts "Test exec: echo 'hello' | ssh -p 2222 admin@localhost mycommand"
puts "Test shell: echo 'hello' | ssh -p 2222 admin@localhost"
server.run
