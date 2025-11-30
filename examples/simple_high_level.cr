#!/usr/bin/env crystal

require "../src/shirk/server_simple"

# Simple test of high-level SSH server
class TestServer < Shirk::SshServer
  def initialize
    super(
      host_key: "/home/ralsina/.ssh/id_rsa",
      port: 8888,
      bind_address: "0.0.0.0"
    )
  end

  def auth_publickey(session_id : String, username : String, fingerprint : String, signature_state : Int32) : Bool
    puts "[#{session_id}] Auth attempt: #{username} with key #{fingerprint}"
    if signature_state == 1
      puts "[#{session_id}] Valid signature, accepting authentication"
      return true
    else
      puts "[#{session_id}] Key offered, waiting for signature"
      return true  # Accept the key to see signature
    end
  end

  def on_authenticated(session_id : String)
    puts "[#{session_id}] Authentication successful!"
  end

  def on_disconnect(session_id : String)
    puts "[#{session_id}] Disconnected"
  end
end

# Create and start the server
server = TestServer.new
puts "Starting simple high-level SSH server on port 8888..."
server.start

puts "Server started. Press Ctrl+C to stop."

# Keep the main thread alive
while server.running?
  sleep(Time::Span.new(seconds: 1))
end

puts "Server stopped."
