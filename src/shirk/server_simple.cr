require "./ffi"

module Shirk
  # Simple high-level SSH Server API
  class SshServer
    # Instance variables with type declarations
    @host_key : String
    @port : Int32
    @bind_address : String
    @running : Bool = false

    # Per-connection state (since handle_single_connection handles one at a time)
    @authenticated : Bool = false
    @channel : LibSSH::SshChannel? = nil
    @current_session_id : String = ""

    # Callback structs and userdata pointers must outlive the C callbacks
    @server_cb : LibSSH::SshServerCallbacksStruct = LibSSH::SshServerCallbacksStruct.new
    @channel_cb : LibSSH::SshChannelCallbacksStruct = LibSSH::SshChannelCallbacksStruct.new
    @userdata_ptr : Void* = Pointer(Void).null

    # Error tracking - critical for proper event loop handling
    @error : Int32 = 0

    def initialize(host_key : String, port : Int32 = 2222, bind_address : String = "0.0.0.0")
      @host_key = host_key
      @port = port
      @bind_address = bind_address
    end

    def start
      @running = true
      spawn { run_server }
      true
    end

    def stop
      @running = false
    end

    def running?
      @running
    end

    # Helper methods for callbacks to access instance state
    def current_session_id : String
      @current_session_id
    end

    def set_authenticated(value : Bool)
      @authenticated = value
    end

    def authenticated?
      @authenticated
    end

    def set_channel(channel : LibSSH::SshChannel)
      @channel = channel
    end

    def channel_ready?
      !@channel.nil?
    end

    def error?
      @error != 0
    end

    def set_error(code : Int32)
      @error = code
    end

    def reset_error
      @error = 0
    end

    # Override these methods in your subclass
    def on_connect(session_id : String, username : String?, remote_address : String?) : Bool
      puts "Connected: #{session_id}"
      true
    end

    def auth_none(session_id : String, username : String?) : Int32
      LibSSH::SSH_AUTH_DENIED
    end

    def auth_password(session_id : String, username : String, password : String) : Bool
      false
    end

    def auth_publickey(session_id : String, username : String, fingerprint : String, signature_state : Int32) : Bool
      puts "Auth attempt: #{username} with #{fingerprint} (state #{signature_state})"

      if signature_state == 0
        puts "Key offered, requesting signature"
        true
      elsif signature_state == 1
        puts "Valid signature, accepting"
        true
      else
        false
      end
    end

    def on_authenticated(session_id : String)
      puts "Authenticated: #{session_id}"
    end

    def on_disconnect(session_id : String)
      puts "Disconnected: #{session_id}"
    end

    # Called when a new channel is requested
    # Return true to allow, false to reject
    def on_channel_open(session_id : String, channel_type : String) : Bool
      puts "Channel opened: #{channel_type} for #{session_id}"
      true
    end

    # Called when a PTY is requested
    # Return true to allow, false to reject
    def on_pty_request(session_id : String, channel_id : String, term : String, width : Int32, height : Int32) : Bool
      puts "PTY requested for #{session_id}: #{term} (#{width}x#{height})"
      true
    end

    # Called when a shell is requested
    # Return true to allow, false to reject
    def on_shell_request(session_id : String, channel_id : String) : Bool
      puts "Shell requested for #{session_id} on #{channel_id}"
      true
    end

    # Called when a command execution is requested
    # Return true to allow, false to reject
    def on_exec_request(session_id : String, channel_id : String, command : String) : Bool
      puts "Command requested for #{session_id}: #{command}"
      true
    end

    # Called when data is received on a channel
    def on_channel_data(session_id : String, channel_id : String, data : Bytes)
      # Default echo behavior - send data back
      puts "[#{session_id}] Data received on #{channel_id}: #{data.size} bytes"
      if channel = @channel
        LibSSH.ssh_channel_write(channel, data, data.size)
      end
    end

    # Called when a channel is closed
    def on_channel_close(session_id : String, channel_id : String)
      puts "[#{session_id}] Channel #{channel_id} closed"
      @channel = nil
    end

    # Static callback functions
    def self.auth_none_callback(ssh_session : LibSSH::SshSession, user : LibC::Char*, userdata : Void*)
      puts "DEBUG: auth_none_callback CALLED!"
      return LibSSH::SSH_AUTH_DENIED unless userdata

      # Extract server instance from userdata
      server = Box(SshServer).unbox(userdata)
      username = user ? String.new(user) : ""

      # Use the current session ID that was set in handle_single_connection
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id

      puts "DEBUG: auth_none_callback calling user method for #{session_id}"

      # Call user method
      result = normalize_auth_result(server.auth_none(session_id, username))

      puts "DEBUG: auth_none_callback END, result=#{result}"
      result
    end

    def self.auth_pubkey_callback(ssh_session : LibSSH::SshSession, user : LibC::Char*, pubkey : LibSSH::SshKey, signature_state : Int32, userdata : Void*)
      puts "DEBUG: auth_pubkey_callback CALLED!"
      return LibSSH::SSH_AUTH_DENIED unless userdata

      server = Box(SshServer).unbox(userdata)
      username = user ? String.new(user) : ""
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id

      fingerprint = extract_fingerprint(pubkey)
      puts "[#{session_id}] Public key authentication attempt for user '#{username}' (state: #{signature_state})"
      puts "[#{session_id}] Client public key SHA256 fingerprint: #{fingerprint}"

      accepted = server.auth_publickey(session_id, username, fingerprint, signature_state)

      unless accepted
        puts "[#{session_id}] Public key authentication denied by user callback"
        return LibSSH::SSH_AUTH_DENIED
      end

      if signature_state == 1
        server.set_authenticated(true)
        server.on_authenticated(session_id)
      end

      puts "DEBUG: auth_pubkey_callback END (accept)"
      LibSSH::SSH_AUTH_SUCCESS
    end

    # REQUIRED: Channel open callback - critical for preventing segfaults
    def self.channel_open_callback(ssh_session : LibSSH::SshSession, userdata : Void*) : LibSSH::SshChannel
      puts "DEBUG: channel_open_callback START"
      unless userdata
        puts "No userdata in channel_open_callback"
        return Pointer(Void).null.as(LibSSH::SshChannel)
      end

      # Extract server instance from userdata
      server = Box(SshServer).unbox(userdata)
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id

      # Create and return a new channel
      channel = LibSSH.ssh_channel_new(ssh_session)
      if channel
        server.set_channel(channel)
        puts "[#{session_id}] Channel created and ready"

        # REQUIRED: Set up channel callbacks for this channel
        server.setup_channel_callbacks(channel, session_id)
      else
        puts "[#{session_id}] Failed to create channel"
      end

      puts "DEBUG: channel_open_callback END"
      channel || Pointer(Void).null.as(LibSSH::SshChannel)
    end

    # REQUIRED: Channel PTY request callback
    def self.channel_pty_request_callback(ssh_session : LibSSH::SshSession, channel : LibSSH::SshChannel, term : UInt8*, x : Int32, y : Int32, px : Int32, py : Int32, userdata : Void*) : LibC::Int
      return 0 unless userdata

      # Extract server instance from userdata
      server = Box(SshServer).unbox(userdata)
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id
      channel_id = "channel_#{Time.utc.to_unix_ms}"

      term_str = term ? String.new(term) : ""

      puts "[#{session_id}] PTY requested: #{term_str} (#{x}x#{y})"

      # Call user method and convert Bool to Int32
      result = server.on_pty_request(session_id, channel_id, term_str, x, y)
      result ? 0 : 1
    end

    # REQUIRED: Channel shell request callback
    def self.channel_shell_request_callback(ssh_session : LibSSH::SshSession, channel : LibSSH::SshChannel, userdata : Void*) : LibC::Int
      return 0 unless userdata

      # Extract server instance from userdata
      server = Box(SshServer).unbox(userdata)
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id
      channel_id = "channel_#{Time.utc.to_unix_ms}"

      puts "[#{session_id}] Shell requested on channel #{channel_id}"

      # Call user method and convert Bool to Int32
      result = server.on_shell_request(session_id, channel_id)
      result ? 0 : 1
    end

    # REQUIRED: Channel data callback
    def self.channel_data_callback(ssh_session : LibSSH::SshSession, channel : LibSSH::SshChannel, data : Void*, len : UInt32, is_stderr : Int32, userdata : Void*) : LibC::Int
      return 0 unless userdata

      # Extract server instance from userdata
      server = Box(SshServer).unbox(userdata)
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id
      channel_id = "channel_#{Time.utc.to_unix_ms}"

      # Convert data to Bytes
      if data && len > 0
        bytes = Bytes.new(data.as(UInt8*), len)

        # Call user method
        server.on_channel_data(session_id, channel_id, bytes)
      end

      len.to_i32
    end

    # REQUIRED: Channel close callback
    def self.channel_close_callback(ssh_session : LibSSH::SshSession, channel : LibSSH::SshChannel, userdata : Void*) : LibC::Int
      return 0 unless userdata

      # Extract server instance from userdata
      server = Box(SshServer).unbox(userdata)
      session_id = server.current_session_id.empty? ? "session_#{Time.utc.to_unix_ms}" : server.current_session_id
      channel_id = "channel_#{Time.utc.to_unix_ms}"

      # Call user method
      server.on_channel_close(session_id, channel_id)

      0
    end

    private def self.normalize_auth_result(result : Int32) : Int32
      case result
      when LibSSH::SSH_AUTH_SUCCESS,
           LibSSH::SSH_AUTH_DENIED,
           LibSSH::SSH_AUTH_PARTIAL,
           LibSSH::SSH_AUTH_INFO,
           LibSSH::SSH_AUTH_AGAIN,
           LibSSH::SSH_AUTH_ERROR
        result
      else
        LibSSH::SSH_AUTH_DENIED
      end
    end

    private def self.extract_fingerprint(pubkey : LibSSH::SshKey) : String
      return "unknown" unless pubkey

      hash_ptr = LibC.malloc(sizeof(Void*)).as(Pointer(UInt8*))
      len_ptr = LibC.malloc(sizeof(LibC::SizeT)).as(Pointer(LibC::SizeT))
      hash_ptr.value = Pointer(UInt8).null
      len_ptr.value = LibC::SizeT.new(0)
      fingerprint = "unknown"

      begin
        if LibSSH.ssh_get_publickey_hash(pubkey, LibSSH::SSH_PUBLICKEY_HASH_SHA256, hash_ptr, len_ptr) == LibSSH::SSH_OK
          hash = hash_ptr.value
          len = len_ptr.value

          if hash
            fp_ptr = LibSSH.ssh_get_fingerprint_hash(LibSSH::SSH_PUBLICKEY_HASH_SHA256, hash, len)
            if fp_ptr
              fingerprint = String.new(fp_ptr)
              LibSSH.ssh_string_free_char(fp_ptr)
            end
            LibSSH.ssh_string_free_char(hash)
          end
        end
      ensure
        LibC.free(hash_ptr.as(Void*)) if hash_ptr
        LibC.free(len_ptr.as(Void*)) if len_ptr
      end

      fingerprint
    end


    def run_server
      sshbind = LibSSH.ssh_bind_new()
      return unless sshbind

      begin
        LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_HOSTKEY, @host_key)
        LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDPORT_STR, @port.to_s)
        LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDADDR, @bind_address)

        if LibSSH.ssh_bind_listen(sshbind) < 0
          puts "Error listening"
          return
        end

        puts "Server listening on #{@bind_address}:#{@port}"

        while @running
          session = LibSSH.ssh_new()
          if session
            handle_single_connection(sshbind, session)
          end
        end

      ensure
        LibSSH.ssh_bind_free(sshbind)
      end
    end

    def handle_single_connection(sshbind, session)
      if LibSSH.ssh_bind_accept(sshbind, session) == LibSSH::SSH_OK
        session_id = "session_#{Time.utc.to_unix_ms}"
        @current_session_id = session_id

        # Reset per-connection state
        @authenticated = false
        @channel = nil
        reset_error

        if LibSSH.ssh_handle_key_exchange(session) == LibSSH::SSH_OK
          LibSSH.ssh_set_auth_methods(session, LibSSH::SSH_AUTH_METHOD_PUBLICKEY)

          setup_callbacks(session, session_id)

          # Handle authentication with finite timeout to prevent segfault
          mainloop = LibSSH.ssh_event_new()
          if mainloop
            LibSSH.ssh_event_add_session(mainloop, session)
            run_event_loop(session, session_id, mainloop)
            LibSSH.ssh_event_free(mainloop)
          end
        end

        on_disconnect(session_id)

        # Reset per-connection state for next connection
        @current_session_id = ""
        @authenticated = false
        @channel = nil

        LibSSH.ssh_disconnect(session)
      end

      LibSSH.ssh_free(session)
    end

    def setup_callbacks(session, session_id)
      puts "DEBUG: setup_callbacks START for #{session_id}"

      # Use instance variable for callback struct to keep it in scope
      @server_cb.size = LibC::SizeT.new(sizeof(LibSSH::SshServerCallbacksStruct))

      # Box the server instance to pass as userdata and keep pointer alive
      if @userdata_ptr.null?
        @userdata_ptr = Box(SshServer).box(self)
      end
      userdata = @userdata_ptr

      # REQUIRED: Authentication callbacks
      @server_cb.auth_none_function = ->SshServer.auth_none_callback(LibSSH::SshSession, LibC::Char*, Void*)
      @server_cb.auth_pubkey_function = ->SshServer.auth_pubkey_callback(LibSSH::SshSession, LibC::Char*, LibSSH::SshKey, Int32, Void*)

      # REQUIRED: Channel callbacks - critical for preventing segfaults
      @server_cb.channel_open_request_session_function = ->SshServer.channel_open_callback(LibSSH::SshSession, Void*)

      @server_cb.userdata = userdata

      result = LibSSH.ssh_set_server_callbacks(session, pointerof(@server_cb))
      puts "DEBUG: ssh_set_server_callbacks returned: #{result}"

      puts "DEBUG: setup_callbacks END for #{session_id}"

      # REQUIRED: Set up channel callbacks after channel is created
      # This needs to be called in the channel_open_callback
    end

    def setup_channel_callbacks(channel, session_id)
      # Use instance variable for callback struct to keep it in scope
      @channel_cb.size = LibC::SizeT.new(sizeof(LibSSH::SshChannelCallbacksStruct))

      # Reuse the boxed server pointer for channel callbacks
      if @userdata_ptr.null?
        @userdata_ptr = Box(SshServer).box(self)
      end
      userdata = @userdata_ptr

      # REQUIRED: Channel request callbacks
      @channel_cb.channel_pty_request_function = ->SshServer.channel_pty_request_callback(LibSSH::SshSession, LibSSH::SshChannel, UInt8*, Int32, Int32, Int32, Int32, Void*)
      @channel_cb.channel_shell_request_function = ->SshServer.channel_shell_request_callback(LibSSH::SshSession, LibSSH::SshChannel, Void*)
      @channel_cb.channel_data_function = ->SshServer.channel_data_callback(LibSSH::SshSession, LibSSH::SshChannel, Void*, UInt32, Int32, Void*)
      @channel_cb.channel_close_function = ->SshServer.channel_close_callback(LibSSH::SshSession, LibSSH::SshChannel, Void*)

      @channel_cb.userdata = userdata

      LibSSH.ssh_set_channel_callbacks(channel, pointerof(@channel_cb))
    end

    def run_event_loop(session, session_id, mainloop)
      # Wait for BOTH authentication AND channel establishment with infinite timeout
      iteration = 0
      while @running && (!authenticated? || !channel_ready?)
        iteration += 1
        puts "DEBUG: Event loop iteration #{iteration}, authenticated=#{authenticated?}, channel_ready=#{channel_ready?}, error=#{error?}"

        if error?
          puts "DEBUG: Breaking loop due to error"
          break
        end

        result = LibSSH.ssh_event_dopoll(mainloop, -1)
        puts "DEBUG: ssh_event_dopoll returned #{result}"

        if result == LibSSH::SSH_ERROR
          error_msg = LibSSH.ssh_get_error(session)
          puts "Error : #{String.new(error_msg)}"
          set_error(1)
          LibSSH.ssh_disconnect(session)
          break
        elsif result == LibSSH::SSH_AGAIN
          puts "DEBUG: SSH_AGAIN, continuing loop"
        else
          puts "DEBUG: dopoll result: #{result} (not SSH_ERROR or SSH_AGAIN)"
        end
      end

      if error?
        puts "Error, exiting loop"
      else
        puts "Authenticated and got a channel"
        puts "Session #{session_id} authenticated and channel ready"
        handle_communication_loop(session_id, session)
      end
    end

    # Handle the main communication loop after authentication and channel establishment
    def handle_communication_loop(session_id : String, session : LibSSH::SshSession)
      puts "[#{session_id}] Starting communication loop"

      buffer = Bytes.new(4096)  # Buffer for reading data

      while @running && authenticated? && channel_ready?
        channel = @channel
        break unless channel

        # Read data from channel
        bytes_read = LibSSH.ssh_channel_read(channel, buffer, buffer.size, 0)

        if bytes_read > 0
          # Echo the data back (default behavior)
          if LibSSH.ssh_channel_write(channel, buffer, bytes_read) == LibSSH::SSH_ERROR
            puts "[#{session_id}] Error writing to channel"
            break
          end

          # Call user callback for data handling
          data_received = buffer[0, bytes_read]
          on_channel_data(session_id, "main_channel", data_received)

        elsif bytes_read == LibSSH::SSH_ERROR
          puts "[#{session_id}] Error reading from channel"
          break

        elsif bytes_read < 0
          # Handle SSH_AGAIN or other non-fatal conditions
          next
        end

        # Small delay to prevent tight loop
        sleep(Time::Span.new(nanoseconds: 10_000_000))  # 0.01 seconds
      end

      puts "[#{session_id}] Communication loop ended"
    end
  end
end