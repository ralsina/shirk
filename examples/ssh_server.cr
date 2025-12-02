# Crystal port of ssh_server.c using fork model
#
# Usage: crystal run examples/ssh_server.cr -- 127.0.0.1 -p 2222 -k ssh_host_rsa_key -u myuser -P mypassword

require "../src/shirk"
require "option_parser"

BUF_SIZE    = 1048576
SESSION_END = LibSSH::SSH_CLOSED | LibSSH::SSH_CLOSED_ERROR

# Config module to hold settings
module Config
  class_property port : String = "2222"
  class_property host_key : String = "ssh_host_rsa_key"
  class_property bind_addr : String = "127.0.0.1"
  class_property username : String = "myuser"
  class_property password : String = "mypassword"
  class_property authorized_keys : String = ""
end

# === Data structures matching C structs ===

class ChannelData
  property pid : Int32 = 0
  property pty_master : Int32 = -1
  property pty_slave : Int32 = -1
  property child_stdin : Int32 = -1
  property child_stdout : Int32 = -1
  property child_stderr : Int32 = -1
  property event : LibSSH::Event = Pointer(Void).null.as(LibSSH::Event)
  property event_registered : Bool = false
  # Buffer for data that arrives before child is spawned
  property stdin_buffer : IO::Memory = IO::Memory.new
  property eof_received : Bool = false
end

class SessionData
  property channel : LibSSH::Channel = Pointer(Void).null.as(LibSSH::Channel)
  property auth_attempts : Int32 = 0
  property authenticated : Bool = false
end

# === Callbacks ===

# Password authentication callback
def auth_password(session : LibSSH::Session, user : UInt8*, pass : UInt8*, userdata : Void*) : Int32
  sdata = Box(SessionData).unbox(userdata)
  
  user_str = String.new(user)
  pass_str = String.new(pass)
  
  puts "Auth attempt: user=#{user_str}"
  
  if user_str == Config.username && pass_str == Config.password
    puts "Authentication successful"
    sdata.authenticated = true
    return LibSSH::SSH_AUTH_SUCCESS
  end
  
  sdata.auth_attempts += 1
  puts "Authentication failed (attempt #{sdata.auth_attempts})"
  LibSSH::SSH_AUTH_DENIED
end

# Public key authentication callback - accepts all keys and prints fingerprint
def auth_publickey(session : LibSSH::Session, user : UInt8*, pubkey : LibSSH::Key, signature_state : UInt8, userdata : Void*) : Int32
  sdata = Box(SessionData).unbox(userdata)
  user_str = String.new(user)
  
  # Get key fingerprint
  hash = Pointer(UInt8).null
  hlen = 0_u64
  if LibSSH.ssh_get_publickey_hash(pubkey, LibSSH::SSH_PUBLICKEY_HASH_SHA256, pointerof(hash), pointerof(hlen)) == LibSSH::SSH_OK
    fingerprint_ptr = LibSSH.ssh_get_fingerprint_hash(LibSSH::SSH_PUBLICKEY_HASH_SHA256, hash, hlen)
    if fingerprint_ptr
      fingerprint = String.new(fingerprint_ptr)
      puts "Pubkey auth: user=#{user_str}, fingerprint=#{fingerprint}"
      LibC.free(fingerprint_ptr.as(Void*))
    end
    LibSSH.ssh_clean_pubkey_hash(pointerof(hash))
  else
    puts "Pubkey auth: user=#{user_str}, state=#{signature_state} (could not get fingerprint)"
  end
  
  # If no signature yet, just say we accept this type of key
  if signature_state == LibSSH::SSH_PUBLICKEY_STATE_NONE
    return LibSSH::SSH_AUTH_SUCCESS
  end
  
  # Signature must be valid
  if signature_state != LibSSH::SSH_PUBLICKEY_STATE_VALID
    return LibSSH::SSH_AUTH_DENIED
  end
  
  # Accept all valid signatures
  puts "Public key authentication successful"
  sdata.authenticated = true
  LibSSH::SSH_AUTH_SUCCESS
end

# Channel open callback
def channel_open(session : LibSSH::Session, userdata : Void*) : LibSSH::Channel
  sdata = Box(SessionData).unbox(userdata)
  puts "Channel open request"
  sdata.channel = LibSSH.ssh_channel_new(session)
  sdata.channel
end

# Channel data callback (client -> server)
def data_function(session : LibSSH::Session, channel : LibSSH::Channel, data : Void*, len : UInt32, is_stderr : Int32, userdata : Void*) : Int32
  cdata = Box(ChannelData).unbox(userdata)
  
  puts "DATA CALLBACK: len=#{len}, pid=#{cdata.pid}, stdin_fd=#{cdata.child_stdin}"
  
  return 0 if len == 0
  
  bytes = Slice.new(data.as(UInt8*), len.to_i)
  
  # If child not spawned yet, buffer the data
  if cdata.pid < 1
    cdata.stdin_buffer.write(bytes)
    puts "Buffered #{len} bytes (total: #{cdata.stdin_buffer.size})"
    return len.to_i
  end
  
  # Check if child is alive
  result = LibC.kill(cdata.pid, 0)
  if result < 0
    puts "Child is dead, dropping data"
    return 0
  end
  
  # Check if stdin is still open
  if cdata.child_stdin == -1
    puts "Child stdin already closed, dropping data"
    return 0
  end
  
  # Write to child's stdin
  written = LibC.write(cdata.child_stdin, bytes, len)
  puts "Wrote #{written} bytes to child stdin"
  written.to_i
end

# Channel EOF callback - client signals end of input
def eof_function(session : LibSSH::Session, channel : LibSSH::Channel, userdata : Void*) : Void
  cdata = Box(ChannelData).unbox(userdata)
  
  puts "EOF received from client"
  cdata.eof_received = true
  
  # If child is already running, close stdin now
  if cdata.pid > 0 && cdata.child_stdin != -1
    fd = cdata.child_stdin
    puts "Closing child stdin (fd #{fd})"
    result = LibC.close(fd)
    puts "Close result: #{result}"
    cdata.child_stdin = -1
    puts "child_stdin is now: #{cdata.child_stdin}"
  end
  # Otherwise, exec_nopty will handle flushing buffer and closing stdin
end

# Exec request callback
def exec_request(session : LibSSH::Session, channel : LibSSH::Channel, command : UInt8*, userdata : Void*) : Int32
  cdata = Box(ChannelData).unbox(userdata)
  cmd = String.new(command)
  
  puts "Exec request: #{cmd}"
  
  return LibSSH::SSH_ERROR if cdata.pid > 0
  
  # Use exec_nopty since we don't have PTY allocated
  exec_nopty(cmd, cdata)
end

# Shell request callback
def shell_request(session : LibSSH::Session, channel : LibSSH::Channel, userdata : Void*) : Int32
  cdata = Box(ChannelData).unbox(userdata)
  
  puts "Shell request"
  
  return LibSSH::SSH_ERROR if cdata.pid > 0
  
  # Shell without PTY - just pretend we allow it
  LibSSH::SSH_OK
end

# === exec_nopty: fork a child to run command ===
def exec_nopty(command : String, cdata : ChannelData) : Int32
  # Create pipes for stdin, stdout, stderr
  stdin_pipe = uninitialized StaticArray(LibC::Int, 2)
  stdout_pipe = uninitialized StaticArray(LibC::Int, 2)
  stderr_pipe = uninitialized StaticArray(LibC::Int, 2)
  
  if LibC.pipe(stdin_pipe) != 0
    STDERR.puts "Failed to create stdin pipe"
    return LibSSH::SSH_ERROR
  end
  
  if LibC.pipe(stdout_pipe) != 0
    LibC.close(stdin_pipe[0])
    LibC.close(stdin_pipe[1])
    STDERR.puts "Failed to create stdout pipe"
    return LibSSH::SSH_ERROR
  end
  
  if LibC.pipe(stderr_pipe) != 0
    LibC.close(stdin_pipe[0])
    LibC.close(stdin_pipe[1])
    LibC.close(stdout_pipe[0])
    LibC.close(stdout_pipe[1])
    STDERR.puts "Failed to create stderr pipe"
    return LibSSH::SSH_ERROR
  end
  
  pid = LibC.fork
  
  case pid
  when -1
    # Fork failed
    STDERR.puts "Fork failed"
    return LibSSH::SSH_ERROR
  when 0
    # Child process
    # Close unused pipe ends first
    LibC.close(stdin_pipe[1])   # Close write end of stdin
    LibC.close(stdout_pipe[0])  # Close read end of stdout
    LibC.close(stderr_pipe[0])  # Close read end of stderr
    
    LibC.dup2(stdin_pipe[0], 0)  # stdin
    LibC.dup2(stdout_pipe[1], 1) # stdout
    LibC.dup2(stderr_pipe[1], 2) # stderr
    
    # Close the originals after dup2
    LibC.close(stdin_pipe[0])
    LibC.close(stdout_pipe[1])
    LibC.close(stderr_pipe[1])
    
    # Exec the command
    LibC.execl("/bin/sh", "sh", "-c", command, Pointer(UInt8).null)
    LibC._exit(127)
  else
    # Parent process
    # Close unused ends
    LibC.close(stdin_pipe[0])
    LibC.close(stdout_pipe[1])
    LibC.close(stderr_pipe[1])
    
    cdata.pid = pid
    cdata.child_stdin = stdin_pipe[1]
    cdata.child_stdout = stdout_pipe[0]
    cdata.child_stderr = stderr_pipe[0]
    
    puts "Child process started: pid=#{pid}"
    
    # Flush any buffered stdin data to the child
    if cdata.stdin_buffer.size > 0
      cdata.stdin_buffer.rewind
      buffered_data = cdata.stdin_buffer.to_slice
      puts "Flushing #{buffered_data.size} buffered bytes to child stdin"
      LibC.write(cdata.child_stdin, buffered_data, buffered_data.size)
      cdata.stdin_buffer.clear
    end
    
    # If EOF was already received, close stdin now
    if cdata.eof_received && cdata.child_stdin != -1
      puts "EOF was pending, closing child stdin now"
      LibC.close(cdata.child_stdin)
      cdata.child_stdin = -1
    end
  end
  
  LibSSH::SSH_OK
end

# === process_stdout / process_stderr: fd callbacks for event poll ===

def process_stdout(fd : Int32, revents : Int16, userdata : Void*) : Int32
  channel = userdata.as(LibSSH::Channel)
  
  if (revents & POLLIN) != 0
    buf = Bytes.new(BUF_SIZE)
    n = LibC.read(fd, buf, BUF_SIZE)
    if n > 0
      LibSSH.ssh_channel_write(channel, buf, n.to_u32)
    end
    return n.to_i
  end
  -1
end

def process_stderr(fd : Int32, revents : Int16, userdata : Void*) : Int32
  channel = userdata.as(LibSSH::Channel)
  
  if (revents & POLLIN) != 0
    buf = Bytes.new(BUF_SIZE)
    n = LibC.read(fd, buf, BUF_SIZE)
    if n > 0
      LibSSH.ssh_channel_write_stderr(channel, buf, n.to_u32)
    end
    return n.to_i
  end
  -1
end

# === handle_session: main session handler (runs in child process) ===

def handle_session(event : LibSSH::Event, session : LibSSH::Session)
  cdata = ChannelData.new
  sdata = SessionData.new
  
  cdata_ptr = Box.box(cdata)
  sdata_ptr = Box.box(sdata)
  
  # Set up channel callbacks
  channel_cb = LibSSH::ChannelCallbacksStruct.new
  channel_cb.size = sizeof(LibSSH::ChannelCallbacksStruct)
  channel_cb.userdata = cdata_ptr
  channel_cb.channel_data_function = ->data_function(LibSSH::Session, LibSSH::Channel, Void*, UInt32, Int32, Void*).pointer
  channel_cb.channel_eof_function = ->eof_function(LibSSH::Session, LibSSH::Channel, Void*).pointer
  channel_cb.channel_exec_request_function = ->exec_request(LibSSH::Session, LibSSH::Channel, UInt8*, Void*).pointer
  channel_cb.channel_shell_request_function = ->shell_request(LibSSH::Session, LibSSH::Channel, Void*).pointer
  
  # Set up server callbacks
  server_cb = LibSSH::ServerCallbacksStruct.new
  server_cb.size = sizeof(LibSSH::ServerCallbacksStruct)
  server_cb.userdata = sdata_ptr
  server_cb.auth_password_function = ->auth_password(LibSSH::Session, UInt8*, UInt8*, Void*).pointer
  server_cb.channel_open_request_session_function = ->channel_open(LibSSH::Session, Void*).pointer
  
  # Set auth methods - always enable both password and pubkey
  server_cb.auth_pubkey_function = ->auth_publickey(LibSSH::Session, UInt8*, LibSSH::Key, UInt8, Void*).pointer
  LibSSH.ssh_set_auth_methods(session, LibSSH::SSH_AUTH_METHOD_PASSWORD | LibSSH::SSH_AUTH_METHOD_PUBLICKEY)
  
  # Register server callbacks
  LibSSH.ssh_set_server_callbacks(session, pointerof(server_cb))
  
  # Handle key exchange
  if LibSSH.ssh_handle_key_exchange(session) != LibSSH::SSH_OK
    STDERR.puts "Key exchange failed: #{String.new(LibSSH.ssh_get_error(session.as(Void*)))}"
    return
  end
  
  puts "Key exchange completed"
  
  # Add session to event
  LibSSH.ssh_event_add_session(event, session)
  
  # Wait for authentication and channel
  n = 0
  while !sdata.authenticated || sdata.channel.null?
    if sdata.auth_attempts >= 3 || n >= 100
      puts "Auth timeout or too many attempts"
      return
    end
    
    if LibSSH.ssh_event_dopoll(event, 100) == LibSSH::SSH_ERROR
      STDERR.puts "Event poll error: #{String.new(LibSSH.ssh_get_error(session.as(Void*)))}"
      return
    end
    n += 1
  end
  
  puts "Session authenticated, channel open"
  
  # Register channel callbacks
  LibSSH.ssh_set_channel_callbacks(sdata.channel, pointerof(channel_cb))
  
  # Track if we got child exit status
  child_exit_status : Int32 = -1
  child_exited = false
  
  # Main event loop
  loop do
    # Use short timeout to check child status regularly
    poll_result = LibSSH.ssh_event_dopoll(event, 100)
    
    # Check if child has exited first (highest priority)
    if cdata.pid > 0
      status = uninitialized Int32
      wait_result = LibC.waitpid(cdata.pid, pointerof(status), LibC::WNOHANG)
      if wait_result != 0
        child_exit_status = status
        child_exited = true
        puts "Child exited with status #{status}"
        break
      end
    end
    
    # Handle poll errors - only fatal if no child running
    if poll_result == LibSSH::SSH_ERROR
      if cdata.pid > 0
        # Child running, keep waiting for it
        next
      else
        # No child, this is a real error
        LibSSH.ssh_channel_close(sdata.channel)
        break
      end
    end
    
    # Check if we need to register child fds
    if !cdata.event_registered && cdata.pid > 0
      cdata.event_registered = true
      
      # Pass channel pointer as userdata
      channel_as_ptr = sdata.channel.as(Void*)
      
      if cdata.child_stdout != -1
        if LibSSH.ssh_event_add_fd(event, cdata.child_stdout, POLLIN, 
            ->process_stdout(Int32, Int16, Void*).pointer, channel_as_ptr) != LibSSH::SSH_OK
          STDERR.puts "Failed to add stdout to event"
          LibSSH.ssh_channel_close(sdata.channel)
        end
      end
      
      if cdata.child_stderr != -1
        if LibSSH.ssh_event_add_fd(event, cdata.child_stderr, POLLIN,
            ->process_stderr(Int32, Int16, Void*).pointer, channel_as_ptr) != LibSSH::SSH_OK
          STDERR.puts "Failed to add stderr to event"
          LibSSH.ssh_channel_close(sdata.channel)
        end
      end
    end
    
    # If no child, break when channel closes
    if cdata.pid == 0
      break unless LibSSH.ssh_channel_is_open(sdata.channel) != 0
    end
  end
  
  puts "Session ending"
  
  # Cleanup file descriptors
  LibC.close(cdata.pty_master) if cdata.pty_master != -1
  LibC.close(cdata.child_stdin) if cdata.child_stdin != -1
  LibC.close(cdata.child_stdout) if cdata.child_stdout != -1
  LibC.close(cdata.child_stderr) if cdata.child_stderr != -1
  
  # Remove fds from event
  LibSSH.ssh_event_remove_fd(event, cdata.child_stdout) if cdata.child_stdout != -1
  LibSSH.ssh_event_remove_fd(event, cdata.child_stderr) if cdata.child_stderr != -1
  
  # Send exit status
  if child_exited && wifexited(child_exit_status)
    exit_code = wexitstatus(child_exit_status)
    puts "Child exited with status: #{exit_code}"
    LibSSH.ssh_channel_request_send_exit_status(sdata.channel, exit_code)
  elsif cdata.pid > 0
    # Child didn't exit cleanly, kill it
    if LibC.kill(cdata.pid, 0) == 0
      LibC.kill(cdata.pid, Signal::KILL.value)
    end
  end
  
  LibSSH.ssh_channel_send_eof(sdata.channel)
  LibSSH.ssh_channel_close(sdata.channel)
  
  # Wait for client to terminate
  50.times do
    break if (LibSSH.ssh_get_status(session) & SESSION_END) != 0
    LibSSH.ssh_event_dopoll(event, 100)
  end
end

# === LibC extensions ===

lib LibC
  fun fork : Int32
  fun dup2(oldfd : Int32, newfd : Int32) : Int32
  fun execl(path : UInt8*, arg0 : UInt8*, ...) : Int32
  fun _exit(status : Int32) : NoReturn
  fun kill(pid : Int32, sig : Int32) : Int32
end

# Macros for wait status
def wifexited(status : Int32) : Bool
  (status & 0x7f) == 0
end

def wexitstatus(status : Int32) : Int32
  (status >> 8) & 0xff
end

# === Main ===

# Parse arguments
OptionParser.parse do |parser|
  parser.banner = "Usage: ssh_server [options] BINDADDR"
  
  parser.on("-p PORT", "--port=PORT", "Port to bind (default: 2222)") do |p|
    Config.port = p
  end
  
  parser.on("-k FILE", "--hostkey=FILE", "Host key file") do |f|
    Config.host_key = f
  end
  
  parser.on("-u USER", "--user=USER", "Expected username") do |u|
    Config.username = u
  end
  
  parser.on("-P PASS", "--pass=PASS", "Expected password") do |p|
    Config.password = p
  end
  
  parser.on("-a FILE", "--authorizedkeys=FILE", "Authorized keys file for pubkey auth") do |f|
    Config.authorized_keys = f
  end
  
  parser.on("-h", "--help", "Show help") do
    puts parser
    exit
  end
  
  parser.unknown_args do |args|
    if args.size >= 1
      Config.bind_addr = args[0]
    end
  end
end

# Set up SIGCHLD handler
Signal::CHLD.trap do
  # Reap zombies
  loop do
    status = uninitialized Int32
    break if LibC.waitpid(-1, pointerof(status), LibC::WNOHANG) <= 0
  end
end

# Initialize libssh
if LibSSH.ssh_init < 0
  STDERR.puts "ssh_init failed"
  exit 1
end

# Create bind
sshbind = LibSSH.ssh_bind_new
if sshbind.null?
  STDERR.puts "ssh_bind_new failed"
  LibSSH.ssh_finalize
  exit 1
end

# Configure bind
LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDADDR, Config.bind_addr.to_unsafe.as(Void*))
LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDPORT_STR, Config.port.to_unsafe.as(Void*))
LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_HOSTKEY, Config.host_key.to_unsafe.as(Void*))

# Listen
if LibSSH.ssh_bind_listen(sshbind) < 0
  STDERR.puts "Listen failed: #{String.new(LibSSH.ssh_get_error(sshbind.as(Void*)))}"
  LibSSH.ssh_bind_free(sshbind)
  LibSSH.ssh_finalize
  exit 1
end

puts "SSH server listening on #{Config.bind_addr}:#{Config.port}"
puts "  Username: #{Config.username}"
puts "  Host key: #{Config.host_key}"

# Main accept loop
loop do
  session = LibSSH.ssh_new
  if session.null?
    STDERR.puts "Failed to allocate session"
    next
  end
  
  # Accept connection
  rc = LibSSH.ssh_bind_accept(sshbind, session)
  
  if rc != LibSSH::SSH_ERROR
    puts "New connection accepted"
    
    # Fork to handle session
    pid = LibC.fork
    
    case pid
    when 0
      # Child process - handle the session
      # Clear SIGCHLD handler
      Signal::CHLD.reset
      
      # Free bind in child (allows parent restart)
      LibSSH.ssh_bind_free(sshbind)
      
      # Create event and handle session
      event = LibSSH.ssh_event_new
      if !event.null?
        handle_session(event, session)
        LibSSH.ssh_event_free(event)
      else
        STDERR.puts "Failed to create event"
      end
      
      LibSSH.ssh_disconnect(session)
      LibSSH.ssh_free(session)
      exit 0
      
    when -1
      STDERR.puts "Fork failed"
    end
  else
    STDERR.puts "Accept failed: #{String.new(LibSSH.ssh_get_error(sshbind.as(Void*)))}"
  end
  
  # Parent cleanup
  LibSSH.ssh_disconnect(session)
  LibSSH.ssh_free(session)
end
