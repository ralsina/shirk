#!/usr/bin/env crystal

require "../src/shirk"

# Exact Crystal translation of samplesshd-cb.c following the same order
module Shirk
  # Constants exactly from C (lines 35-48)
  BUF_SIZE = 2049
  KEYS_FOLDER = "/etc/ssh/"
  USER = "myuser"
  PASSWORD = "mypassword"

  # Static variables exactly like C (lines 50-53)
  @@authenticated = 0
  @@tries = 0
  @@error = 0
  @@chan : LibSSH::SshChannel? = nil

  # Static channel callback struct exactly like C (lines 131-134)
  @@channel_cb = LibSSH::SshChannelCallbacksStruct.new

  # Function definitions exactly matching C (lines 55-146)

  # auth_none function (lines 55-74)
  def self.auth_none(session : LibSSH::SshSession, user : LibC::Char*, userdata : Void*) : Int32
    banner = LibSSH.ssh_string_from_char("Banner Example\n")

    # Line 61-62: (void)user; (void)userdata; - unused parameters in C

    # Line 64-65: Set auth methods - only public key
    LibSSH.ssh_set_auth_methods(session, LibSSH::SSH_AUTH_METHOD_PUBLICKEY)

    # Line 67-71: Send banner
    if banner != nil
      LibSSH.ssh_send_issue_banner(session, banner)
    end
    LibSSH.ssh_string_free(banner)

    # Line 73: Return denied
    LibSSH::SSH_AUTH_DENIED
  end

  
  # auth_pubkey function - handles public key authentication
  def self.auth_pubkey(session : LibSSH::SshSession, user : LibC::Char*, pubkey : LibSSH::SshKey, signature_state : Int32, userdata : Void*) : Int32
    user_str = user ? String.new(user) : ""

    printf("Public key authentication attempt for user '%s' (signature_state: %d)\n", user_str, signature_state)

    # signature_state: 0 = just the public key, 1 = valid signature
    if signature_state == 0
      printf("Public key offered, checking if we want to accept this key\n")

      # Extract and print the fingerprint of the client's public key
      if pubkey != nil
        hash_ptr = Pointer(Pointer(UInt8)).malloc(1)
        hash_len = Pointer(LibC::SizeT).malloc(1)

        # Get SHA256 hash of the public key
        if LibSSH.ssh_get_publickey_hash(pubkey, LibSSH::SSH_PUBLICKEY_HASH_SHA256, hash_ptr, hash_len) == LibSSH::SSH_OK
          hash = hash_ptr.value
          len = hash_len.value

          # Convert to printable fingerprint
          fingerprint = LibSSH.ssh_get_fingerprint_hash(LibSSH::SSH_PUBLICKEY_HASH_SHA256, hash, len)
          if fingerprint != nil
            fingerprint_str = String.new(fingerprint)
            printf("Client public key SHA256 fingerprint: %s\n", fingerprint_str)
            LibSSH.ssh_string_free_char(fingerprint)
          end

          # Clean up the hash memory
          LibSSH.ssh_string_free_char(hash)
        end
      end

      # For now, accept any public key to see the fingerprint
      return LibSSH::SSH_AUTH_SUCCESS
    elsif signature_state == 1
      printf("Public key signature is valid\n")
      # Check if user is allowed to authenticate with this key
      if user_str == USER
        @@authenticated = 1
        printf("Public key authentication successful\n")
        return LibSSH::SSH_AUTH_SUCCESS
      end
    end

    printf("Public key authentication denied\n")
    LibSSH::SSH_AUTH_DENIED
  end

  # pty_request function (lines 110-122)
  def self.pty_request(session : LibSSH::SshSession, channel : LibSSH::SshChannel,
                        term : UInt8*, x : Int32, y : Int32, px : Int32, py : Int32,
                        userdata : Void*) : Int32
    # Lines 112-119: (void) parameter casts - unused in C
    printf("Allocated terminal\n")
    0
  end

  # shell_request function (lines 124-129)
  def self.shell_request(session : LibSSH::SshSession, channel : LibSSH::SshChannel, userdata : Void*) : Int32
    # Lines 125-127: (void) parameter casts - unused in C
    printf("Allocated shell\n")
    0
  end

  # new_session_channel function (lines 136-146)
  def self.new_session_channel(session : LibSSH::SshSession, userdata : Void*) : LibSSH::SshChannel
    # Line 137-138: (void) session; (void) userdata;

    # Line 139-140: Check if channel already exists
    if @@chan != nil
      return Pointer(Void).null.as(LibSSH::SshChannel)
    end

    printf("Allocated session channel\n")
    @@chan = LibSSH.ssh_channel_new(session)

    # Line 143: ssh_callbacks_init(&channel_cb);
    @@channel_cb.size = sizeof(typeof(@@channel_cb)).to_u64

    # Line 144: ssh_set_channel_callbacks(chan, &channel_cb);
    if @@chan
      LibSSH.ssh_set_channel_callbacks(@@chan.not_nil!, pointerof(@@channel_cb))
    end

    @@chan.not_nil!
  end

  
  # Main function exactly matching C (lines 250-345)
  def self.main
    # Line 252-254: Variable declarations
    session : LibSSH::SshSession? = nil
    sshbind : LibSSH::SshBind? = nil
    mainloop : LibSSH::SshEvent? = nil

    # Line 255-263: Server callbacks struct initialization
    cb = LibSSH::SshServerCallbacksStruct.new
    cb.userdata = Pointer(Void).null
    cb.auth_none_function = ->(session : LibSSH::SshSession, user : LibC::Char*, userdata : Void*) { auth_none(session, user, userdata) }
    cb.auth_pubkey_function = ->(session : LibSSH::SshSession, user : LibC::Char*, pubkey : LibSSH::SshKey, signature_state : Int32, userdata : Void*) { auth_pubkey(session, user, pubkey, signature_state, userdata) }
    cb.channel_open_request_session_function = ->(session : LibSSH::SshSession, userdata : Void*) { new_session_channel(session, userdata) }

    # Line 265-267: Local variables
    buf = Slice(UInt8).new(BUF_SIZE)
    i : Int32
    r : Int32

    # Line 269-270: Create bind and session
    sshbind = LibSSH.ssh_bind_new()
    session = LibSSH.ssh_new()

    # Line 272: Set host key
    if LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_HOSTKEY, "/home/ralsina/.ssh/id_rsa") < 0
      puts "Failed to set host key"
      return 1
    end

    # Set port 6666
    if LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDPORT_STR, "6666") < 0
      puts "Failed to set port"
      return 1
    end

    # Set bind address 0.0.0.0
    if LibSSH.ssh_bind_options_set(sshbind, LibSSH::SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0") < 0
      puts "Failed to set bind address"
      return 1
    end

    # Line 285-288: Listen
    if LibSSH.ssh_bind_listen(sshbind) < 0
      printf("Error listening to socket: Unknown error\n")
      return 1
    end

    # Line 289-293: Accept connection
    r = LibSSH.ssh_bind_accept(sshbind, session)
    if r == LibSSH::SSH_ERROR
      printf("error accepting a connection : Unknown error\n")
      return 1
    end

    # Line 294: ssh_callbacks_init(&cb);
    cb.size = sizeof(typeof(cb)).to_u64

    # Line 295: ssh_set_server_callbacks(session, &cb);
    LibSSH.ssh_set_server_callbacks(session, pointerof(cb))

    # Line 297-299: Handle key exchange
    if LibSSH.ssh_handle_key_exchange(session) != LibSSH::SSH_OK
      error_msg = LibSSH.ssh_get_error(session)
      printf("ssh_handle_key_exchange: %s\n", String.new(error_msg))
      return 1
    end

    # Line 301: Set auth methods - only public key
    LibSSH.ssh_set_auth_methods(session, LibSSH::SSH_AUTH_METHOD_PUBLICKEY)

    # Line 302-303: Create and add to event loop
    mainloop = LibSSH.ssh_event_new()
    LibSSH.ssh_event_add_session(mainloop, session)

    # Initialize channel callbacks struct (line 131-134)
    @@channel_cb.userdata = Pointer(Void).null
    @@channel_cb.channel_pty_request_function = ->(session : LibSSH::SshSession, channel : LibSSH::SshChannel, term : UInt8*, x : Int32, y : Int32, px : Int32, py : Int32, userdata : Void*) { pty_request(session, channel, term, x, y, px, py, userdata) }
    @@channel_cb.channel_shell_request_function = ->(session : LibSSH::SshSession, channel : LibSSH::SshChannel, userdata : Void*) { shell_request(session, channel, userdata) }

    # Line 305-314: Main authentication loop
    while !(@@authenticated == 1 && @@chan != nil)
      if @@error != 0
        break
      end

      r = LibSSH.ssh_event_dopoll(mainloop, -1)
      if r == LibSSH::SSH_ERROR
        error_msg = LibSSH.ssh_get_error(session)
        printf("Error : %s\n", String.new(error_msg))
        LibSSH.ssh_disconnect(session)
        return 1
      end
    end

    # Line 315-318: Check results
    if @@error != 0
      printf("Error, exiting loop\n")
    else
      printf("Authenticated and got a channel\n")
    end

    # Line 319-340: Main communication loop
    loop do
      i = LibSSH.ssh_channel_read(@@chan.not_nil!, buf.to_unsafe, BUF_SIZE - 1, 0)
      if i > 0
        if LibSSH.ssh_channel_write(@@chan.not_nil!, buf.to_unsafe, i) == LibSSH::SSH_ERROR
          printf("error writing to channel\n")
          return 1
        end

        buf[i] = 0_u8  # Null terminate (line 327)
        printf("%s", String.new(buf[0, i]))
        STDOUT.flush

        if buf[0] == 0x0d_u8
          if LibSSH.ssh_channel_write(@@chan.not_nil!, "\n", 1) == LibSSH::SSH_ERROR
            printf("error writing to channel\n")
            return 1
          end
          printf("\n")
        end
      elsif i <= 0
        break
      end
    end

    # Line 341-343: Cleanup
    LibSSH.ssh_disconnect(session)
    LibSSH.ssh_bind_free(sshbind)
    LibSSH.ssh_finalize()

    0
  end
end

# Run the server
exit(Shirk.main)