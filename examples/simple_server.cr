require "../src/shirk"

# Simple SSH server example using high-level API
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

# Handle exec requests
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
  else
    ctx.write("You said: #{ctx.command}\n")
    0
  end
end

puts "Starting SSH server on port 2222..."
puts "Test with: ssh -p 2222 admin@localhost"
puts "Or: python3 -c \"import paramiko; c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy()); c.connect('localhost',2222,username='admin',password='secret'); print(c.exec_command('whoami')[1].read())\""

server.run
