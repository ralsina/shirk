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

module Shirk
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
      # Session state
      authenticated = false
      auth_attempts = 0
      channel = Pointer(Void).null.as(LibSSH::Channel)
      current_user = ""
      
      # Channel state for exec
      child_pid = 0
      child_stdin = -1
      child_stdout = -1
      child_stderr = -1
      fds_registered = false
      
      # Box self for callbacks
      server_ptr = Box.box(self)
      
      # Session data for callbacks
      session_data = {
        authenticated: Pointer(Bool).malloc(1),
        auth_attempts: Pointer(Int32).malloc(1),
        channel: Pointer(LibSSH::Channel).malloc(1),
        current_user: Pointer(String).malloc(1),
        server: self,
      }
      session_data[:authenticated].value = false
      session_data[:auth_attempts].value = 0
      session_data[:channel].value = Pointer(Void).null.as(LibSSH::Channel)
      session_data[:current_user].value = ""
      
      sdata_ptr = Box.box(session_data)
      
      # Channel data
      channel_data = {
        pid: Pointer(Int32).malloc(1),
        stdin: Pointer(Int32).malloc(1),
        stdout: Pointer(Int32).malloc(1),
        stderr: Pointer(Int32).malloc(1),
        registered: Pointer(Bool).malloc(1),
        event: event,
        session: session,
        server: self,
        user: Pointer(String).malloc(1),
        handler_done: Pointer(Bool).malloc(1),
        handler_exit: Pointer(Int32).malloc(1),
      }
      channel_data[:pid].value = 0
      channel_data[:stdin].value = -1
      channel_data[:stdout].value = -1
      channel_data[:stderr].value = -1
      channel_data[:registered].value = false
      channel_data[:user].value = ""
      channel_data[:handler_done].value = false
      channel_data[:handler_exit].value = 0
      
      cdata_ptr = Box.box(channel_data)
      
      # Server callbacks
      server_cb = LibSSH::ServerCallbacksStruct.new
      server_cb.size = sizeof(LibSSH::ServerCallbacksStruct)
      server_cb.userdata = sdata_ptr
      server_cb.auth_password_function = ->(_sess : LibSSH::Session, user : UInt8*, pass : UInt8*, ud : Void*) {
        data = Box(typeof(session_data)).unbox(ud)
        server = data[:server]
        user_str = String.new(user)
        pass_str = String.new(pass)
        
        accepted = if handler = server.@auth_password_handler
          handler.call(user_str, pass_str)
        else
          # Fallback to configured user/pass
          !server.username.empty? && user_str == server.username && pass_str == server.password
        end
        
        if accepted
          data[:authenticated].value = true
          data[:current_user].value = user_str
          LibSSH::SSH_AUTH_SUCCESS
        else
          data[:auth_attempts].value += 1
          LibSSH::SSH_AUTH_DENIED
        end
      }.pointer
      
      server_cb.auth_pubkey_function = ->(_sess : LibSSH::Session, user : UInt8*, pubkey : LibSSH::Key, sig_state : UInt8, ud : Void*) {
        data = Box(typeof(session_data)).unbox(ud)
        server = data[:server]
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
        
        # STATE_NONE = probe, STATE_VALID = real auth
        if sig_state == LibSSH::SSH_PUBLICKEY_STATE_NONE
          LibSSH::SSH_AUTH_SUCCESS
        elsif sig_state == LibSSH::SSH_PUBLICKEY_STATE_VALID
          accepted = if handler = server.@auth_pubkey_handler
            handler.call(user_str, fingerprint)
          else
            true  # Accept all by default
          end
          
          if accepted
            data[:authenticated].value = true
            data[:current_user].value = user_str
            LibSSH::SSH_AUTH_SUCCESS
          else
            LibSSH::SSH_AUTH_DENIED
          end
        else
          LibSSH::SSH_AUTH_DENIED
        end
      }.pointer
      
      server_cb.channel_open_request_session_function = ->(sess : LibSSH::Session, ud : Void*) {
        data = Box(typeof(session_data)).unbox(ud)
        ch = LibSSH.ssh_channel_new(sess)
        data[:channel].value = ch
        ch
      }.pointer
      
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
      
      # Wait for auth
      n = 0
      while !session_data[:authenticated].value || session_data[:channel].value.null?
        return if session_data[:auth_attempts].value >= 3 || n >= 100
        return if LibSSH.ssh_event_dopoll(event, 100) == LibSSH::SSH_ERROR
        n += 1
      end
      
      channel = session_data[:channel].value
      current_user = session_data[:current_user].value
      channel_data[:user].value = current_user
      
      # Channel callbacks
      channel_cb = LibSSH::ChannelCallbacksStruct.new
      channel_cb.size = sizeof(LibSSH::ChannelCallbacksStruct)
      channel_cb.userdata = cdata_ptr
      
      channel_cb.channel_data_function = ->(_sess : LibSSH::Session, _ch : LibSSH::Channel, data_ptr : Void*, len : UInt32, _is_stderr : Int32, ud : Void*) {
        cdata = Box(typeof(channel_data)).unbox(ud)
        return 0 if len == 0 || cdata[:pid].value < 1
        return 0 if LibC.kill(cdata[:pid].value, 0) < 0
        bytes = Slice.new(data_ptr.as(UInt8*), len.to_i)
        LibC.write(cdata[:stdin].value, bytes, len).to_i
      }.pointer
      
      channel_cb.channel_exec_request_function = ->(_sess : LibSSH::Session, ch : LibSSH::Channel, cmd : UInt8*, ud : Void*) {
        cdata = Box(typeof(channel_data)).unbox(ud)
        server = cdata[:server]
        command = String.new(cmd)
        
        return LibSSH::SSH_ERROR if cdata[:pid].value > 0 || cdata[:handler_done].value
        
        # If we have a handler, use it directly
        if handler = server.@exec_handler
          ctx = ExecContext.new(ch, cdata[:event], command, cdata[:user].value)
          exit_code = handler.call(ctx)
          # Mark as done - event loop will handle cleanup
          cdata[:handler_exit].value = exit_code
          cdata[:handler_done].value = true
          return LibSSH::SSH_OK
        end
        
        # Default: run command via shell
        run_command(command, cdata)
      }.pointer
      
      channel_cb.channel_shell_request_function = ->(_sess : LibSSH::Session, ch : LibSSH::Channel, ud : Void*) {
        cdata = Box(typeof(channel_data)).unbox(ud)
        server = cdata[:server]
        
        return LibSSH::SSH_ERROR if cdata[:pid].value > 0 || cdata[:handler_done].value
        
        if handler = server.@shell_handler
          ctx = ExecContext.new(ch, cdata[:event], "", cdata[:user].value)
          exit_code = handler.call(ctx)
          cdata[:handler_exit].value = exit_code
          cdata[:handler_done].value = true
          return LibSSH::SSH_OK
        end
        
        LibSSH::SSH_OK
      }.pointer
      
      LibSSH.ssh_set_channel_callbacks(channel, pointerof(channel_cb))
      
      # Event loop
      child_exit_status = -1
      child_exited = false
      handler_completed = false
      
      loop do
        # Use short timeout when handler is done to finish sending data
        timeout = channel_data[:handler_done].value ? 100 : -1
        
        if LibSSH.ssh_event_dopoll(event, timeout) == LibSSH::SSH_ERROR
          LibSSH.ssh_channel_close(channel)
          break
        end
        
        # Check if handler completed and we should close
        if channel_data[:handler_done].value && !handler_completed
          handler_completed = true
          # Send exit status and close channel
          LibSSH.ssh_channel_request_send_exit_status(channel, channel_data[:handler_exit].value)
          LibSSH.ssh_channel_send_eof(channel)
          LibSSH.ssh_channel_close(channel)
          break
        end
        
        # Register child fds if needed
        if !channel_data[:registered].value && channel_data[:pid].value > 0
          channel_data[:registered].value = true
          channel_as_ptr = channel.as(Void*)
          
          if channel_data[:stdout].value != -1
            LibSSH.ssh_event_add_fd(event, channel_data[:stdout].value, POLLIN,
              ->(fd : Int32, revents : Int16, ud : Void*) {
                ch = ud.as(LibSSH::Channel)
                if (revents & POLLIN) != 0
                  buf = Bytes.new(65536)
                  n = LibC.read(fd, buf, 65536)
                  LibSSH.ssh_channel_write(ch, buf, n.to_u32) if n > 0
                  return n.to_i
                end
                -1
              }.pointer, channel_as_ptr)
          end
          
          if channel_data[:stderr].value != -1
            LibSSH.ssh_event_add_fd(event, channel_data[:stderr].value, POLLIN,
              ->(fd : Int32, revents : Int16, ud : Void*) {
                ch = ud.as(LibSSH::Channel)
                if (revents & POLLIN) != 0
                  buf = Bytes.new(65536)
                  n = LibC.read(fd, buf, 65536)
                  LibSSH.ssh_channel_write_stderr(ch, buf, n.to_u32) if n > 0
                  return n.to_i
                end
                -1
              }.pointer, channel_as_ptr)
          end
        end
        
        break unless LibSSH.ssh_channel_is_open(channel) != 0
        
        if channel_data[:pid].value > 0
          status = uninitialized Int32
          wait_result = LibC.waitpid(channel_data[:pid].value, pointerof(status), LibC::WNOHANG)
          if wait_result != 0
            child_exit_status = status
            child_exited = true
            break
          end
        end
      end
      
      # Cleanup
      LibC.close(channel_data[:stdin].value) if channel_data[:stdin].value != -1
      LibC.close(channel_data[:stdout].value) if channel_data[:stdout].value != -1
      LibC.close(channel_data[:stderr].value) if channel_data[:stderr].value != -1
      
      LibSSH.ssh_event_remove_fd(event, channel_data[:stdout].value) if channel_data[:stdout].value != -1
      LibSSH.ssh_event_remove_fd(event, channel_data[:stderr].value) if channel_data[:stderr].value != -1
      
      if child_exited && wifexited(child_exit_status)
        exit_code = wexitstatus(child_exit_status)
        LibSSH.ssh_channel_request_send_exit_status(channel, exit_code)
      elsif channel_data[:pid].value > 0
        LibC.kill(channel_data[:pid].value, Signal::KILL.value) if LibC.kill(channel_data[:pid].value, 0) == 0
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
end

# Helper to run command via fork/exec
private def run_command(command : String, cdata) : Int32
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
    LibC.dup2(stdin_pipe[0], 0)
    LibC.dup2(stdout_pipe[1], 1)
    LibC.dup2(stderr_pipe[1], 2)
    LibC.execl("/bin/sh", "sh", "-c", command, Pointer(UInt8).null)
    LibC._exit(127)
  else
    LibC.close(stdin_pipe[0])
    LibC.close(stdout_pipe[1])
    LibC.close(stderr_pipe[1])
    
    cdata[:pid].value = pid
    cdata[:stdin].value = stdin_pipe[1]
    cdata[:stdout].value = stdout_pipe[0]
    cdata[:stderr].value = stderr_pipe[0]
  end
  
  LibSSH::SSH_OK
end

# LibC extensions
lib LibC
  fun fork : Int32
  fun dup2(oldfd : Int32, newfd : Int32) : Int32
  fun execl(path : UInt8*, arg0 : UInt8*, ...) : Int32
  fun _exit(status : Int32) : NoReturn
  fun kill(pid : Int32, sig : Int32) : Int32
  fun free(ptr : Void*) : Void
end
