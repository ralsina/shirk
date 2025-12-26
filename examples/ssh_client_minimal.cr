#!/usr/bin/env crystal

require "../src/shirk"

if ARGV.size < 1
  puts "Usage: #{PROGRAM_NAME} <host>"
  exit 1
end

host = ARGV[0]

# Initialize
LibSSH.ssh_init

# Create session
session = LibSSH.ssh_new
if session.null?
  STDERR.puts "ssh_new failed"
  exit 1
end

puts "Session created: #{session}"

# Don't parse SSH config - it returns -1 and may be causing issues
# rc = LibSSH.ssh_options_parse_config(session, nil)
# puts "Parse config: rc=#{rc}"

# Set host
rc = LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_HOST, host.to_unsafe.as(Void*))
puts "Set host #{host}: rc=#{rc}"

# Set user - try with a literal string to see if it's a GC issue
rc = LibSSH.ssh_options_set(session, LibSSH::SSH_OPTIONS_USER, "ralsina".to_unsafe.as(Void*))
puts "Set user ralsina: rc=#{rc}"

# Check blocking mode (should be 1 by default)
blocking = LibSSH.ssh_is_blocking(session)
puts "Is blocking: #{blocking}"

# Keep it in blocking mode
# LibSSH.ssh_set_blocking(session, 0)
# blocking_after = LibSSH.ssh_is_blocking(session)
# puts "After set_blocking(0): #{blocking_after}"

# Check FD before connect
fd_before = LibSSH.ssh_get_fd(session)
puts "FD before connect: #{fd_before}"

# Try to connect
puts "\nConnecting..."
rc = LibSSH.ssh_connect(session)
puts "Connect result: #{rc} (SSH_OK=#{LibSSH::SSH_OK})"

if rc != LibSSH::SSH_OK
  error = String.new(LibSSH.ssh_get_error(session.as(Void*)))
  error_code = LibSSH.ssh_get_error_code(session.as(Void*))
  fd = LibSSH.ssh_get_fd(session)
  STDERR.puts "Error: #{error}"
  STDERR.puts "Error code: #{error_code}"
  STDERR.puts "FD after fail: #{fd}"
  LibSSH.ssh_free(session)
  LibSSH.ssh_finalize
  exit 1
end

puts "Connected!"

LibSSH.ssh_disconnect(session)
LibSSH.ssh_free(session)
LibSSH.ssh_finalize
