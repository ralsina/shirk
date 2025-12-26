# High-level SSH Client API
#
# Example usage:
#   client = Shirk::Client.new("localhost", 2222, user: "admin")
#   client.auth_password("secret")
#   result = client.exec("whoami")
#   puts result.stdout
#   client.disconnect

require "./ffi"

module Shirk
  # Initialize libssh globally when module loads
  LibSSH.ssh_init

  # Class method to finalize libssh when program exits
  def self.finalize_libssh
    LibSSH.ssh_finalize
  end

  # Result of command execution
  class ExecResult
    getter stdout : String
    getter stderr : String
    getter exit_code : Int32

    def initialize(@stdout : String, @stderr : String, @exit_code : Int32)
    end

    def success?
      @exit_code == 0
    end
  end

  # High-level SSH client
  class Client
    property host : String
    property port : Int32
    property user : String
    property timeout : Int32
    property strict_host_key_checking : Bool
    property verbosity : Int32

    @session : LibSSH::Session
    @connected : Bool = false
    @authenticated : Bool = false

    def initialize(@host : String, @port : Int32 = 22, @user : String = ENV["USER"]? || "root",
                   @timeout : Int32 = 30, @strict_host_key_checking : Bool = false,
                   @verbosity : Int32 = 0)
      @session = LibSSH.ssh_new
      raise "Failed to create SSH session" if @session.null?

      configure_session
    end

    def finalize
      disconnect if @connected
      LibSSH.ssh_free(@session) unless @session.null?
    end

    # Connect to the SSH server
    def connect
      raise "Already connected" if @connected

      LibSSH.ssh_set_blocking(@session, 1)

      puts "Attempting to connect to #{@host}:#{@port}..." if @verbosity > 0
      rc = LibSSH.ssh_connect(@session)
      puts "ssh_connect returned: #{rc}" if @verbosity > 0
      
      if rc != LibSSH::SSH_OK
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Failed to connect to #{@host}:#{@port}: #{error}"
      end

      puts "Connected successfully!" if @verbosity > 0
      @connected = true
    end

    # Disconnect from the SSH server
    def disconnect
      if @connected
        LibSSH.ssh_disconnect(@session)
        @connected = false
        @authenticated = false
      end
    end

    # Authenticate with password
    def auth_password(password : String) : Bool
      ensure_connected
      raise "Already authenticated" if @authenticated

      rc = LibSSH.ssh_userauth_password(@session, @user.to_unsafe, password.to_unsafe)
      @authenticated = rc == LibSSH::SSH_AUTH_SUCCESS
      
      unless @authenticated
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Password authentication failed: #{error}"
      end

      @authenticated
    end

    # Authenticate with public key (file path)
    def auth_publickey(key_file : String, passphrase : String? = nil) : Bool
      ensure_connected
      raise "Already authenticated" if @authenticated

      privkey = Pointer(LibSSH::Key).malloc(1)
      rc = LibSSH.ssh_pki_import_privkey_file(
        key_file.to_unsafe, 
        passphrase ? passphrase.to_unsafe : Pointer(LibC::Char).null, 
        Pointer(Void).null,  # auth_fn
        Pointer(Void).null,  # auth_data
        privkey
      )

      puts "DEBUG: ssh_pki_import_privkey_file returned: #{rc}" if @verbosity > 1

      if rc != LibSSH::SSH_OK
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Failed to load private key #{key_file}: #{error}"
      end

      puts "DEBUG: Attempting public key authentication" if @verbosity > 1
      key = privkey.value
      auth_result = LibSSH.ssh_userauth_publickey(@session, @user.to_unsafe, key)
      
      puts "DEBUG: ssh_userauth_publickey returned: #{auth_result}" if @verbosity > 1
      
      LibSSH.ssh_key_free(key) if key

      @authenticated = auth_result == LibSSH::SSH_AUTH_SUCCESS
      
      unless @authenticated
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Public key authentication failed: #{error}"
      end

      @authenticated
    end

    # Authenticate with public key (base64 key data)
    def auth_publickey_base64(key_data : String, passphrase : String? = nil) : Bool
      ensure_connected
      raise "Already authenticated" if @authenticated

      privkey = Pointer(LibSSH::Key).malloc(1)
      rc = LibSSH.ssh_pki_import_privkey_base64(
        key_data.to_unsafe, 
        passphrase ? passphrase.to_unsafe : Pointer(LibC::Char).null,
        Pointer(Void).null,  # auth_fn
        Pointer(Void).null,  # auth_data
        privkey
      )
      
      key = privkey.value

      if rc != LibSSH::SSH_OK
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Failed to load private key from base64 data: #{error}"
      end

      auth_result = LibSSH.ssh_userauth_publickey(@session, @user.to_unsafe, key)
      LibSSH.ssh_key_free(key) if key

      @authenticated = auth_result == LibSSH::SSH_AUTH_SUCCESS
      
      unless @authenticated
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Public key authentication failed: #{error}"
      end

      @authenticated
    end

    # Try to authenticate with SSH agent
    def auth_agent : Bool
      ensure_connected
      raise "Already authenticated" if @authenticated

      rc = LibSSH.ssh_userauth_agent(@session, @user.to_unsafe)
      @authenticated = rc == LibSSH::SSH_AUTH_SUCCESS
      
      unless @authenticated
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "SSH agent authentication failed: #{error}"
      end

      @authenticated
    end

    # Execute a command and return the result
    def exec(command : String) : ExecResult
      ensure_authenticated

      channel = LibSSH.ssh_channel_new(@session)
      if channel.null?
        error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
        raise "Failed to create channel: #{error}"
      end

      begin
        rc = LibSSH.ssh_channel_open_session(channel)
        if rc != LibSSH::SSH_OK
          error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
          raise "Failed to open channel: #{error}"
        end

        if LibSSH.ssh_channel_request_exec(channel, command.to_unsafe) != LibSSH::SSH_OK
          error = String.new(LibSSH.ssh_get_error(@session.as(Void*)))
          raise "Failed to execute command: #{error}"
        end

        stdout = IO::Memory.new
        stderr = IO::Memory.new
        buffer = Bytes.new(4096)

        # Read stdout until EOF
        loop do
          nbytes = LibSSH.ssh_channel_read(channel, buffer, 4096, 0)
          break if nbytes <= 0
          stdout.write(buffer[0, nbytes])
        end

        # Read stderr until EOF
        loop do
          nbytes = LibSSH.ssh_channel_read(channel, buffer, 4096, 1)
          break if nbytes <= 0
          stderr.write(buffer[0, nbytes])
        end

        # Get exit status
        exit_code = 0
        exit_status = LibSSH.ssh_channel_get_exit_status(channel)
        exit_code = exit_status if exit_status >= 0

        ExecResult.new(stdout.to_s, stderr.to_s, exit_code)
      ensure
        LibSSH.ssh_channel_send_eof(channel)
        LibSSH.ssh_channel_close(channel)
        LibSSH.ssh_channel_free(channel)
      end
    end

    # Get list of supported authentication methods
    def auth_methods : Array(String)
      ensure_connected

      methods = LibSSH.ssh_userauth_list(@session, @user.to_unsafe)
      result = [] of String

      result << "none" if (methods & LibSSH::SSH_AUTH_METHOD_NONE) != 0
      result << "password" if (methods & LibSSH::SSH_AUTH_METHOD_PASSWORD) != 0
      result << "publickey" if (methods & LibSSH::SSH_AUTH_METHOD_PUBLICKEY) != 0
      result << "hostbased" if (methods & LibSSH::SSH_AUTH_METHOD_HOSTBASED) != 0
      result << "interactive" if (methods & LibSSH::SSH_AUTH_METHOD_INTERACTIVE) != 0
      result << "gssapi-mic" if (methods & LibSSH::SSH_AUTH_METHOD_GSSAPI_MIC) != 0

      result
    end

    private def configure_session
      # Use exact same options as working C version
      LibSSH.ssh_options_set(@session, LibSSH::SSH_OPTIONS_HOST, @host.to_unsafe.as(Void*))
      LibSSH.ssh_options_set(@session, LibSSH::SSH_OPTIONS_PORT_STR, @port.to_s.to_unsafe.as(Void*))
      LibSSH.ssh_options_set(@session, LibSSH::SSH_OPTIONS_LOG_VERBOSITY, pointerof(@verbosity).as(Void*))
      
      # Try without SSH_DIR option to see if that causes file access
      # LibSSH.ssh_options_set(@session, LibSSH::SSH_OPTIONS_SSH_DIR, Pointer(Void).null)
      
      puts "Session configured for #{@host}:#{@port}" if @verbosity > 1
    end

    private def ensure_connected
      connect unless @connected
      raise "Not connected" unless @connected
    end

    private def ensure_authenticated
      ensure_connected
      raise "Not authenticated" unless @authenticated
    end
  end
end