require "./src/shirk"

puts "Testing minimal SSH connection..."

# Test with very basic settings - longer timeout
client = Shirk::Client.new("localhost", 22, user: "ralsina", verbosity: 4, timeout: 30)

begin
  client.connect
  puts "Connected successfully!"
rescue ex
  puts "Failed to connect: #{ex.message}"
  # Get libssh error details
  session_ptr = client.@session
  error_msg = String.new(LibSSH.ssh_get_error(session_ptr.as(Void*)))
  puts "LibSSH error: #{error_msg}"
end

puts "Done."