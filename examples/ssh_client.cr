#!/usr/bin/env crystal

# SSH Client Example - following libssh sample.c closely
# Based on https://api.libssh.org/master/libssh_tutor_guided_tour.html

require "../src/shirk"

# Check arguments
if ARGV.size < 2
  puts "Usage: #{PROGRAM_NAME} <host> <port> [user] [key_file]"
  exit 1
end

host = ARGV[0]
port = ARGV[1].to_i
user = ARGV[2]? || ENV["USER"] || "root"
key_file = ARGV[3]? || "#{ENV["HOME"]}/.ssh/id_rsa"

puts "Connecting to #{host}:#{port} as #{user} using key #{key_file}"

# Initialize libssh
if LibSSH.ssh_init < 0
  STDERR.puts "ssh_init failed"
  exit 1
end

# Create session
session = LibSSH.ssh_new
if session.null?
  STDERR.puts "ssh_new failed"
  LibSSH.ssh_finalize
  exit 1
end

# Set options
LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_HOST, host.to_unsafe.as(Void*))
LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_USER, user.to_unsafe.as(Void*))

port_str = port.to_s
LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_PORT_STR, port_str.to_unsafe.as(Void*))

# Disable strict host key checking (for convenience - don't do this in production!)
strict = 0
LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_STRICT_HOSTKEY_CHECKING, pointerof(strict).as(Void*))

# Set verbosity for debugging
verbosity = 0  # SSH_LOG_NONE - disable verbose logging
LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_LOG_VERBOSITY, pointerof(verbosity).as(Void*))

# Disable config file processing (might be causing issues)
ssh_dir = Pointer(LibC::Char).null
LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_SSH_DIR, ssh_dir.as(Void*))

puts "Options set, session pointer: #{session}"
puts "About to set blocking mode..."

# Set blocking mode BEFORE connect
LibSSH.ssh_set_blocking(session, 1)

puts "Blocking mode set, about to connect..."

# Connect
puts "Connecting..."
rc = LibSSH.ssh_connect(session)
if rc != LibSSH::SSH_OK
  error = String.new(LibSSH.ssh_get_error(session.as(Void*)))
  STDERR.puts "Error connecting to #{host}:#{port}: #{error}"
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

puts "Connected successfully!"

# Authenticate
puts "Authenticating with SSH key..."

# Load private key
privkey = Pointer(LibSSH::Key).malloc(1)
rc = LibSSH.ssh_pki_import_privkey_file(key_file, nil, Pointer(Void).null, Pointer(Void).null, privkey)

if rc != LibSSH::SSH_OK
  error = String.new(LibSSH.ssh_get_error(session.as(Void*)))
  STDERR.puts "Error loading private key #{key_file}: #{error}"
  LibSSH.ssh_disconnect(session)
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

puts "Private key loaded successfully"

# Try public key authentication
auth_result = LibSSH.ssh_userauth_publickey(session, user.to_unsafe, privkey[0])

if auth_result != LibSSH::SSH_AUTH_SUCCESS
  error = String.new(LibSSH.ssh_get_error(session.as(Void*)))
  STDERR.puts "Error authenticating: #{error}"
  LibSSH.ssh_key_free(privkey[0])
  LibSSH.ssh_disconnect(session)
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

puts "Authenticated successfully!"

# Free the private key
LibSSH.ssh_key_free(privkey[0])

# Execute command
command = "whoami"
puts "\nExecuting command: #{command}"

channel = LibSSH.ssh_channel_new(session)
if channel.null?
  STDERR.puts "Failed to create channel"
  LibSSH.ssh_disconnect(session)
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

rc = LibSSH.ssh_channel_open_session(channel)
if rc != LibSSH::SSH_OK
  error = String.new(LibSSH.ssh_get_error(session.as(Void*)))
  STDERR.puts "Failed to open channel: #{error}"
  LibSSH.ssh_channel_free(channel)
  LibSSH.ssh_disconnect(session)
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

if LibSSH.ssh_channel_request_exec(channel, command) != LibSSH::SSH_OK
  error = String.new(LibSSH.ssh_get_error(session.as(Void*)))
  STDERR.puts "Failed to execute command: #{error}"
  LibSSH.ssh_channel_close(channel)
  LibSSH.ssh_channel_free(channel)
  LibSSH.ssh_disconnect(session)
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

puts "Command output:"

# Read stdout
buffer = Bytes.new(4096)
loop do
  nbytes = LibSSH.ssh_channel_read(channel, buffer, 4096, 0)
  break if nbytes <= 0
  print String.new(buffer[0, nbytes])
end

# Send EOF
LibSSH.ssh_channel_send_eof(channel)
LibSSH.ssh_channel_close(channel)
LibSSH.ssh_channel_free(channel)

# Disconnect
LibSSH.ssh_disconnect(session)
LibSSH.ssh_free(session)
LibSSH.ssh_finalize

puts "\n\nDone!"
