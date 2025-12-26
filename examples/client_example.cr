require "../src/shirk"

# =============================================================================
# High-Level SSH Client Example
# =============================================================================
#
# This example demonstrates the Shirk::Client high-level API for connecting
# to SSH servers and executing commands.
#
# USAGE EXAMPLES:
#
#   # Password authentication:
#   crystal run examples/client_example.cr -- password localhost 2222 admin secret
#
#   # Public key authentication:
#   crystal run examples/client_example.cr -- pubkey localhost 2222 admin ~/.ssh/id_rsa
#
#   # SSH agent authentication:
#   crystal run examples/client_example.cr -- agent localhost 2222 admin
#
# =============================================================================

if ARGV.size < 2
  puts "Usage: #{PROGRAM_NAME} <method> <host> <port> <user> [auth_data]"
  puts ""
  puts "Methods:"
  puts "  password <host> <port> <user> <password>"
  puts "  pubkey   <host> <port> <user> <key_file>"
  puts "  agent    <host> <port> <user>"
  exit 1
end

method = ARGV[0]
host = ARGV[1]
port = ARGV[2].to_i
user = ARGV[3]

puts "=== Shirk SSH Client Example ==="
puts "Method: #{method}"
puts "Host: #{host}:#{port}"
puts "User: #{user}"
puts ""

# libssh is now initialized automatically when Shirk module loads

begin
  # Create client with higher verbosity for debugging
  client = Shirk::Client.new(host, port, user: user, strict_host_key_checking: false, verbosity: 3)
  
  # Connect
  puts "Connecting..."
  client.connect
  puts "Connected successfully!"
  
  # Show available auth methods
  puts "Available auth methods: #{client.auth_methods.join(", ")}"
  
  # Authenticate
  case method
  when "password"
    if ARGV.size < 5
      puts "Password method requires password argument"
      exit 1
    end
    password = ARGV[4]
    puts "Authenticating with password..."
    client.auth_password(password)
    
  when "pubkey"
    if ARGV.size < 5
      puts "Public key method requires key file argument"
      exit 1
    end
    key_file = ARGV[4]
    puts "Authenticating with public key: #{key_file}"
    client.auth_publickey(key_file)
    
  when "agent"
    puts "Authenticating with SSH agent..."
    client.auth_agent
    
  else
    puts "Unknown authentication method: #{method}"
    exit 1
  end
  
  puts "Authentication successful!"
  puts ""
  
  # Execute some commands
  commands = [
    "whoami",
    "pwd",
    "echo 'Hello from SSH client!'",
    "date",
    "ls -la /tmp"
  ]
  
  commands.each do |cmd|
    puts ">>> #{cmd}"
    result = client.exec(cmd)
    
    if result.success?
      if !result.stdout.empty?
        puts result.stdout
      end
    else
      puts "Command failed (exit code: #{result.exit_code})"
      if !result.stderr.empty?
        puts "STDERR: #{result.stderr}"
      end
    end
    puts ""
  end
  
  # Test error handling
  puts ">>> false_command_that_should_not_exist"
  result = client.exec("false_command_that_should_not_exist")
  puts "Exit code: #{result.exit_code}"
  puts "STDERR: #{result.stderr}" unless result.stderr.empty?
  puts ""
  
  puts "Disconnecting..."
  client.disconnect
  puts "Done!"
  
rescue ex
  puts "Error: #{ex.message}"
  puts ex.backtrace.join("\n") if ARGV.includes?("--debug")
  exit 1
ensure
  # Finalize libssh
  Shirk.finalize_libssh
end