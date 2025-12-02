# High-level SSH Server API
#
# Example usage:
#   server = Shirk::Server.new("0.0.0.0", 2222, host_key: "ssh_host_rsa_key")
#
#   server.on_auth_password do |user, password|
#     user == "admin" && password == "secret"
#   end
#
#   server.on_auth_pubkey do |user, fingerprint|
#     puts "Key: #{fingerprint}"
#     true  # accept all
#   end
#
#   server.on_exec do |ctx|
#     ctx.write("Hello from SSH!\n")
#     0  # exit code
#   end
#
#   server.run

require "./ffi"

# LibC extensions
lib LibC
  fun fork : Int32
  fun dup2(oldfd : Int32, newfd : Int32) : Int32
  fun execl(path : UInt8*, arg0 : UInt8*, ...) : Int32
  fun _exit(status : Int32) : NoReturn
  fun kill(pid : Int32, sig : Int32) : Int32
  fun free(ptr : Void*) : Void
end

module Shirk
  # Channel data class - similar to low-level example
  class ChannelData
    property pid : Int32 = 0
    property child_stdin : Int32 = -1
    property child_stdout : Int32 = -1
    property child_stderr : Int32 = -1
    property registered : Bool = false
    property event : LibSSH::Event
    property session : LibSSH::Session
    property channel : LibSSH::Channel = Pointer(Void).null.as(LibSSH::Channel)
    property server : Server
    property user : String = ""
    property handler_done : Bool = false
    property handler_exit : Int32 = 0
    property stdin_buffer : IO::Memory = IO::Memory.new
    property eof_received : Bool = false

    def initialize(@event, @session, @server)
    end
  end

  # Session data class
  class SessionData
    property authenticated : Bool = false
    property auth_attempts : Int32 = 0
    property channel : LibSSH::Channel = Pointer(Void).null.as(LibSSH::Channel)
    property current_user : String = ""
    property server : Server

    def initialize(@server)
    end
  end

  # Context passed to exec/shell callbacks
  class ExecContext
    getter command : String
    getter user : String
    @channel : LibSSH::Channel
    @event : LibSSH::Event

    def initialize(@channel, @event, @command, @user)
    end

    # Write to stdout
    def write(data : String)
      LibSSH.ssh_channel_write(@channel, data.to_unsafe, data.bytesize.to_u32)
    end

    # Write to stderr
    def write_stderr(data : String)
      LibSSH.ssh_channel_write_stderr(@channel, data.to_unsafe, data.bytesize.to_u32)
    end

    # Read from client (stdin)
    def read(max_bytes : Int32 = 4096) : String
      buf = Bytes.new(max_bytes)
      n = LibSSH.ssh_channel_read(@channel, buf, max_bytes.to_u32, 0)
      return "" if n <= 0
      String.new(buf[0, n])
    end
  end

  class Server
    property host : String
    property port : Int32
    property host_key : String
    property username : String
    property password : String

    @auth_password_handler : Proc(String, String, Bool)?
    @auth_pubkey_handler : Proc(String, String, Bool)?
    @exec_handler : Proc(ExecContext, Int32)?
    @shell_handler : Proc(ExecContext, Int32)?

    def initialize(@host : String, @port : Int32, @host_key : String,
                   @username : String = "", @password : String = "")
    end

    # Set password authentication handler
    # Block receives (user, password) and should return true to accept
    def on_auth_password(&block : String, String -> Bool)
      @auth_password_handler = block
    end

    # Set public key authentication handler
    # Block receives (user, fingerprint) and should return true to accept
    def on_auth_pubkey(&block : String, String -> Bool)
      @auth_pubkey_handler = block
    end

    # Set exec request handler
    # Block receives ExecContext and should return exit code
    def on_exec(&block : ExecContext -> Int32)
      @exec_handler = block
    end

    # Set shell request handler
    # Block receives ExecContext (with empty command) and should return exit code
    def on_shell(&block : ExecContext -> Int32)
      @shell_handler = block
    end

    # Accessor for auth handler (used by callbacks)
    def auth_password_handler
      @auth_password_handler
    end

    def auth_pubkey_handler
      @auth_pubkey_handler
    end

    def exec_handler
      @exec_handler
    end

    def shell_handler
      @shell_handler
    end

    # Run the server (blocks forever, forks for each connection)
    def run
      setup_sigchld_handler

      if LibSSH.ssh_init < 0
        raise "ssh_init failed"
      end

      sshbind = LibSSH.ssh_bind_new
      raise "ssh_bind_new failed" if sshbind.null?

      # Configure bind
      LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDADDR, @host.to_unsafe.as(Void*))
      port_str = @port.to_s
      LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDPORT_STR, port_str.to_unsafe.as(Void*))
      LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_HOSTKEY, @host_key.to_unsafe.as(Void*))

      if LibSSH.ssh_bind_listen(sshbind) < 0
        error = String.new(LibSSH.ssh_get_error(sshbind.as(Void*)))
        LibSSH.ssh_bind_free(sshbind)
        LibSSH.ssh_finalize
        raise "Listen failed: #{error}"
      end

      puts "SSH server listening on #{@host}:#{@port}"

      loop do
        session = LibSSH.ssh_new
        next if session.null?

        rc = LibSSH.ssh_bind_accept(sshbind, session)
        if rc != LibSSH::SSH_ERROR
          pid = LibC.fork
          case pid
          when 0
            # Child process
            Signal::CHLD.reset
            LibSSH.ssh_bind_free(sshbind)

            event = LibSSH.ssh_event_new
            if !event.null?
              handle_session(event, session)
              LibSSH.ssh_event_free(event)
            end

            LibSSH.ssh_disconnect(session)
            LibSSH.ssh_free(session)
            exit 0
          when -1
            STDERR.puts "Fork failed"
          end
        end

        LibSSH.ssh_disconnect(session)
        LibSSH.ssh_free(session)
      end
    end

    private def setup_sigchld_handler
      Signal::CHLD.trap do
        loop do
          status = uninitialized Int32
          break if LibC.waitpid(-1, pointerof(status), LibC::WNOHANG) <= 0
        end
      end
    end

    private def handle_session(event : LibSSH::Event, session : LibSSH::Session)
      # Create session and channel data objects
      sdata = SessionData.new(self)
      cdata = ChannelData.new(event, session, self)

      sdata_ptr = Box.box(sdata)
      cdata_ptr = Box.box(cdata)

      # Set up channel callbacks FIRST (before key exchange)
      channel_cb = LibSSH::ChannelCallbacksStruct.new
      channel_cb.size = sizeof(LibSSH::ChannelCallbacksStruct)
      channel_cb.userdata = cdata_ptr
      channel_cb.channel_data_function = ->Shirk.channel_data_cb(LibSSH::Session, LibSSH::Channel, Void*, UInt32, Int32, Void*).pointer
      channel_cb.channel_eof_function = ->Shirk.channel_eof_cb(LibSSH::Session, LibSSH::Channel, Void*).pointer
      channel_cb.channel_exec_request_function = ->Shirk.channel_exec_cb(LibSSH::Session, LibSSH::Channel, UInt8*, Void*).pointer
      channel_cb.channel_shell_request_function = ->Shirk.channel_shell_cb(LibSSH::Session, LibSSH::Channel, Void*).pointer

      # Server callbacks
      server_cb = LibSSH::ServerCallbacksStruct.new
      server_cb.size = sizeof(LibSSH::ServerCallbacksStruct)
      server_cb.userdata = sdata_ptr
      server_cb.auth_password_function = ->Shirk.auth_password_cb(LibSSH::Session, UInt8*, UInt8*, Void*).pointer
      server_cb.auth_pubkey_function = ->Shirk.auth_pubkey_cb(LibSSH::Session, UInt8*, LibSSH::Key, UInt8, Void*).pointer
      server_cb.channel_open_request_session_function = ->Shirk.channel_open_cb(LibSSH::Session, Void*).pointer

      # Set auth methods
      auth_methods = 0
      auth_methods |= LibSSH::SSH_AUTH_METHOD_PASSWORD if @auth_password_handler || !@username.empty?
      auth_methods |= LibSSH::SSH_AUTH_METHOD_PUBLICKEY
      auth_methods = LibSSH::SSH_AUTH_METHOD_PASSWORD | LibSSH::SSH_AUTH_METHOD_PUBLICKEY if auth_methods == 0

      LibSSH.ssh_set_auth_methods(session, auth_methods)
      LibSSH.ssh_set_server_callbacks(session, pointerof(server_cb))

      # Key exchange
      if LibSSH.ssh_handle_key_exchange(session) != LibSSH::SSH_OK
        return
      end

      LibSSH.ssh_event_add_session(event, session)

      # Wait for auth and channel
      n = 0
      while !sdata.authenticated || sdata.channel.null?
        return if sdata.auth_attempts >= 3 || n >= 100
        return if LibSSH.ssh_event_dopoll(event, 100) == LibSSH::SSH_ERROR
        n += 1
      end

      channel = sdata.channel
      cdata.channel = channel
      cdata.user = sdata.current_user

      # Register channel callbacks
      LibSSH.ssh_set_channel_callbacks(channel, pointerof(channel_cb))

      # Event loop
      child_exit_status = -1
      child_exited = false
      handler_completed = false
      status = uninitialized Int32

      loop do
        # Use short timeout when handler is done or we have a child process
        timeout = (cdata.handler_done || cdata.pid > 0) ? 100 : -1

        poll_result = LibSSH.ssh_event_dopoll(event, timeout)

        if poll_result == LibSSH::SSH_ERROR
          # Don't exit event loop if we have a running child
          if cdata.pid > 0
            wait_result = LibC.waitpid(cdata.pid, pointerof(status), LibC::WNOHANG)
            if wait_result == 0
              next
            end
          end
          LibSSH.ssh_channel_close(channel)
          break
        end

        # Check if handler completed and we should close
        if cdata.handler_done && !handler_completed
          handler_completed = true
          LibSSH.ssh_channel_request_send_exit_status(channel, cdata.handler_exit)
          LibSSH.ssh_channel_send_eof(channel)
          LibSSH.ssh_channel_close(channel)
          break
        end

        # Register child fds if needed
        if !cdata.registered && cdata.pid > 0
          cdata.registered = true
          channel_as_ptr = channel.as(Void*)

          if cdata.child_stdout != -1
            result = LibSSH.ssh_event_add_fd(event, cdata.child_stdout, POLLIN,
              ->Shirk.process_stdout(Int32, Int16, Void*).pointer, channel_as_ptr)
          end

          if cdata.child_stderr != -1
            LibSSH.ssh_event_add_fd(event, cdata.child_stderr, POLLIN,
              ->Shirk.process_stderr(Int32, Int16, Void*).pointer, channel_as_ptr)
          end
        end

        # Check if child is still running
        if cdata.pid > 0
          wait_result = LibC.waitpid(cdata.pid, pointerof(status), LibC::WNOHANG)
          if wait_result != 0
            child_exit_status = status
            child_exited = true
            break
          end
          next
        end

        break unless LibSSH.ssh_channel_is_open(channel) != 0
      end

      # Cleanup
      LibC.close(cdata.child_stdin) if cdata.child_stdin != -1
      LibC.close(cdata.child_stdout) if cdata.child_stdout != -1
      LibC.close(cdata.child_stderr) if cdata.child_stderr != -1

      LibSSH.ssh_event_remove_fd(event, cdata.child_stdout) if cdata.child_stdout != -1
      LibSSH.ssh_event_remove_fd(event, cdata.child_stderr) if cdata.child_stderr != -1

      if child_exited && wifexited(child_exit_status)
        exit_code = wexitstatus(child_exit_status)
        LibSSH.ssh_channel_request_send_exit_status(channel, exit_code)
      elsif cdata.pid > 0
        LibC.kill(cdata.pid, Signal::KILL.value) if LibC.kill(cdata.pid, 0) == 0
      end

      LibSSH.ssh_channel_send_eof(channel)
      LibSSH.ssh_channel_close(channel)

      50.times do
        break if (LibSSH.ssh_get_status(session) & (LibSSH::SSH_CLOSED | LibSSH::SSH_CLOSED_ERROR)) != 0
        LibSSH.ssh_event_dopoll(event, 100)
      end
    end

    private def wifexited(status : Int32) : Bool
      (status & 0x7f) == 0
    end

    private def wexitstatus(status : Int32) : Int32
      (status >> 8) & 0xff
    end
  end

  # =====================================================
  # Named callback functions (like low-level example)
  # =====================================================

  # Channel data callback
  def self.channel_data_cb(session : LibSSH::Session, channel : LibSSH::Channel, data : Void*, len : UInt32, is_stderr : Int32, userdata : Void*) : Int32
    cdata = Box(ChannelData).unbox(userdata)

    return 0 if len == 0

    bytes = Slice.new(data.as(UInt8*), len.to_i)

    # If child not spawned yet, buffer the data
    if cdata.pid < 1
      cdata.stdin_buffer.write(bytes)
      return len.to_i
    end

    return 0 if cdata.child_stdin < 0       # Already closed
    return 0 if LibC.kill(cdata.pid, 0) < 0 # Child dead

    n = LibC.write(cdata.child_stdin, bytes, len).to_i
    n
  end

  # Channel EOF callback
  def self.channel_eof_cb(session : LibSSH::Session, channel : LibSSH::Channel, userdata : Void*) : Int32
    cdata = Box(ChannelData).unbox(userdata)

    cdata.eof_received = true

    # Close child stdin when client sends EOF
    if cdata.child_stdin != -1
      result = LibC.close(cdata.child_stdin)
      cdata.child_stdin = -1
    else
    end

    LibSSH::SSH_OK
  end

  # Channel exec request callback
  def self.channel_exec_cb(session : LibSSH::Session, channel : LibSSH::Channel, cmd : UInt8*, userdata : Void*) : Int32
    cdata = Box(ChannelData).unbox(userdata)
    server = cdata.server
    command = String.new(cmd)

    return LibSSH::SSH_ERROR if cdata.pid > 0 || cdata.handler_done

    # If we have a handler, use it directly
    if handler = server.exec_handler
      ctx = ExecContext.new(channel, cdata.event, command, cdata.user)
      exit_code = handler.call(ctx)
      cdata.handler_exit = exit_code
      cdata.handler_done = true
      return LibSSH::SSH_OK
    end

    # Default: run command via shell
    result = run_command_for_channel(command, cdata)
    result
  end

  # Channel shell request callback
  def self.channel_shell_cb(session : LibSSH::Session, channel : LibSSH::Channel, userdata : Void*) : Int32
    cdata = Box(ChannelData).unbox(userdata)
    server = cdata.server

    return LibSSH::SSH_ERROR if cdata.pid > 0 || cdata.handler_done

    if handler = server.shell_handler
      ctx = ExecContext.new(channel, cdata.event, "", cdata.user)
      exit_code = handler.call(ctx)
      cdata.handler_exit = exit_code
      cdata.handler_done = true
      return LibSSH::SSH_OK
    end

    LibSSH::SSH_OK
  end

  # Auth password callback
  def self.auth_password_cb(session : LibSSH::Session, user : UInt8*, pass : UInt8*, userdata : Void*) : Int32
    sdata = Box(SessionData).unbox(userdata)
    server = sdata.server
    user_str = String.new(user)
    pass_str = String.new(pass)

    accepted = if handler = server.auth_password_handler
                 handler.call(user_str, pass_str)
               else
                 !server.username.empty? && user_str == server.username && pass_str == server.password
               end

    if accepted
      sdata.authenticated = true
      sdata.current_user = user_str
      LibSSH::SSH_AUTH_SUCCESS
    else
      sdata.auth_attempts += 1
      LibSSH::SSH_AUTH_DENIED
    end
  end

  # Auth pubkey callback
  def self.auth_pubkey_cb(session : LibSSH::Session, user : UInt8*, pubkey : LibSSH::Key, sig_state : UInt8, userdata : Void*) : Int32
    sdata = Box(SessionData).unbox(userdata)
    server = sdata.server
    user_str = String.new(user)

    # Get fingerprint
    fingerprint = ""
    hash = Pointer(UInt8).null
    hlen = 0_u64
    if LibSSH.ssh_get_publickey_hash(pubkey, LibSSH::SSH_PUBLICKEY_HASH_SHA256, pointerof(hash), pointerof(hlen)) == LibSSH::SSH_OK
      fp_ptr = LibSSH.ssh_get_fingerprint_hash(LibSSH::SSH_PUBLICKEY_HASH_SHA256, hash, hlen)
      if fp_ptr
        fingerprint = String.new(fp_ptr)
        LibC.free(fp_ptr.as(Void*))
      end
      LibSSH.ssh_clean_pubkey_hash(pointerof(hash))
    end

    if sig_state == LibSSH::SSH_PUBLICKEY_STATE_NONE
      LibSSH::SSH_AUTH_SUCCESS
    elsif sig_state == LibSSH::SSH_PUBLICKEY_STATE_VALID
      accepted = if handler = server.auth_pubkey_handler
                   handler.call(user_str, fingerprint)
                 else
                   true
                 end

      if accepted
        sdata.authenticated = true
        sdata.current_user = user_str
        LibSSH::SSH_AUTH_SUCCESS
      else
        LibSSH::SSH_AUTH_DENIED
      end
    else
      LibSSH::SSH_AUTH_DENIED
    end
  end

  # Channel open callback
  def self.channel_open_cb(session : LibSSH::Session, userdata : Void*) : LibSSH::Channel
    sdata = Box(SessionData).unbox(userdata)
    ch = LibSSH.ssh_channel_new(session)
    sdata.channel = ch
    ch
  end

  # Stdout fd callback
  def self.process_stdout(fd : Int32, revents : Int16, userdata : Void*) : Int32
    channel = userdata.as(LibSSH::Channel)

    if (revents & POLLIN) != 0
      buf = Bytes.new(65536)
      n = LibC.read(fd, buf, 65536)
      if n > 0
        LibSSH.ssh_channel_write(channel, buf, n.to_u32)
      end
      return n.to_i
    end
    -1
  end

  # Stderr fd callback
  def self.process_stderr(fd : Int32, revents : Int16, userdata : Void*) : Int32
    channel = userdata.as(LibSSH::Channel)

    if (revents & POLLIN) != 0
      buf = Bytes.new(65536)
      n = LibC.read(fd, buf, 65536)
      if n > 0
        LibSSH.ssh_channel_write_stderr(channel, buf, n.to_u32)
      end
      return n.to_i
    end
    -1
  end

  # Helper to run command via fork/exec
  def self.run_command_for_channel(command : String, cdata : ChannelData) : Int32
    stdin_pipe = uninitialized StaticArray(LibC::Int, 2)
    stdout_pipe = uninitialized StaticArray(LibC::Int, 2)
    stderr_pipe = uninitialized StaticArray(LibC::Int, 2)

    return LibSSH::SSH_ERROR if LibC.pipe(stdin_pipe) != 0
    return LibSSH::SSH_ERROR if LibC.pipe(stdout_pipe) != 0
    return LibSSH::SSH_ERROR if LibC.pipe(stderr_pipe) != 0

    pid = LibC.fork
    case pid
    when -1
      return LibSSH::SSH_ERROR
    when 0
      # Child process
      LibC.dup2(stdin_pipe[0], 0)
      LibC.dup2(stdout_pipe[1], 1)
      LibC.dup2(stderr_pipe[1], 2)
      # Close all original pipe fds
      LibC.close(stdin_pipe[0])
      LibC.close(stdin_pipe[1])
      LibC.close(stdout_pipe[0])
      LibC.close(stdout_pipe[1])
      LibC.close(stderr_pipe[0])
      LibC.close(stderr_pipe[1])
      LibC.execl("/bin/sh", "sh", "-c", command, Pointer(UInt8).null)
      LibC._exit(127)
    else
      # Parent process
      LibC.close(stdin_pipe[0])
      LibC.close(stdout_pipe[1])
      LibC.close(stderr_pipe[1])

      cdata.pid = pid
      cdata.child_stdin = stdin_pipe[1]
      cdata.child_stdout = stdout_pipe[0]
      cdata.child_stderr = stderr_pipe[0]

      # Flush any buffered stdin data
      buffer = cdata.stdin_buffer
      if buffer.size > 0
        buffer.rewind
        data = buffer.to_slice
        LibC.write(cdata.child_stdin, data, data.size)
      end

      # If EOF was already received, close stdin now
      if cdata.eof_received
        LibC.close(cdata.child_stdin)
        cdata.child_stdin = -1
      end
    end

    LibSSH::SSH_OK
  end
end
