# Minimal libssh FFI bindings - following ssh_server.c closely
#
# This is a fresh start, binding only what's needed for a working SSH server
# using the fork model from ssh_server.c (WITH_FORK).

@[Link("ssh")]
lib LibSSH
  # === Types ===
  type Session = Void*
  type Bind = Void*
  type Channel = Void*
  type Event = Void*
  type Key = Void*

  alias SocketT = Int32

  # === Return codes ===
  SSH_OK    =  0
  SSH_ERROR = -1
  SSH_AGAIN = -2
  SSH_EOF   = -127

  # === Auth return codes ===
  SSH_AUTH_SUCCESS = 0
  SSH_AUTH_DENIED  = 1
  SSH_AUTH_PARTIAL = 2
  SSH_AUTH_INFO    = 3
  SSH_AUTH_AGAIN   = 4
  SSH_AUTH_ERROR   = -1

  # === Auth methods ===
  SSH_AUTH_METHOD_UNKNOWN     = 0x0000
  SSH_AUTH_METHOD_NONE        = 0x0001
  SSH_AUTH_METHOD_PASSWORD    = 0x0002
  SSH_AUTH_METHOD_PUBLICKEY   = 0x0004
  SSH_AUTH_METHOD_HOSTBASED   = 0x0008
  SSH_AUTH_METHOD_INTERACTIVE = 0x0010
  SSH_AUTH_METHOD_GSSAPI_MIC  = 0x0020

  # === Session status flags ===
  SSH_CLOSED        = 0x01
  SSH_READ_PENDING  = 0x02
  SSH_CLOSED_ERROR  = 0x04
  SSH_WRITE_PENDING = 0x08

  # === Bind options ===
  SSH_BIND_OPTIONS_BINDADDR          = 0
  SSH_BIND_OPTIONS_BINDPORT          = 1
  SSH_BIND_OPTIONS_BINDPORT_STR      = 2
  SSH_BIND_OPTIONS_HOSTKEY           = 3
  SSH_BIND_OPTIONS_DSAKEY            = 4
  SSH_BIND_OPTIONS_RSAKEY            = 5
  SSH_BIND_OPTIONS_BANNER            = 6
  SSH_BIND_OPTIONS_LOG_VERBOSITY     = 7
  SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = 8
  SSH_BIND_OPTIONS_ECDSAKEY          = 9
  SSH_BIND_OPTIONS_IMPORT_KEY        = 10

  # === Public key hash types ===
  SSH_PUBLICKEY_HASH_SHA1   = 0
  SSH_PUBLICKEY_HASH_MD5    = 1
  SSH_PUBLICKEY_HASH_SHA256 = 2

  # === Public key state (for auth callback) ===
  SSH_PUBLICKEY_STATE_NONE  = 0
  SSH_PUBLICKEY_STATE_VALID = 1

  # === Key comparison flags ===
  SSH_KEY_CMP_PUBLIC = 0

  # === Server callbacks struct (matches libssh server.h lines 72-128) ===
  # Fields must match exact order in C struct
  struct ServerCallbacksStruct
    size : LibC::SizeT
    userdata : Void*
    auth_password_function : Void*
    auth_none_function : Void*
    auth_gssapi_mic_function : Void*
    auth_pubkey_function : Void*
    service_request_function : Void*
    channel_open_request_session_function : Void*
    gssapi_select_oid_function : Void*
    gssapi_accept_sec_ctx_function : Void*
    gssapi_verify_mic_function : Void*
  end

  # === Channel callbacks struct (matches libssh callbacks.h lines 850-925) ===
  struct ChannelCallbacksStruct
    size : LibC::SizeT
    userdata : Void*
    channel_data_function : Void*
    channel_eof_function : Void*
    channel_close_function : Void*
    channel_signal_function : Void*
    channel_exit_status_function : Void*
    channel_exit_signal_function : Void*
    channel_pty_request_function : Void*
    channel_shell_request_function : Void*
    channel_auth_agent_req_function : Void*
    channel_x11_req_function : Void*
    channel_pty_window_change_function : Void*
    channel_exec_request_function : Void*
    channel_env_request_function : Void*
    channel_subsystem_request_function : Void*
    channel_write_wontblock_function : Void*
  end

  # === Core functions ===
  fun ssh_init : Int32
  fun ssh_finalize : Int32

  # === Bind functions ===
  fun ssh_bind_new : Bind
  fun ssh_bind_free(bind : Bind) : Void
  fun ssh_bind_options_set(bind : Bind, type : Int32, value : Void*) : Int32
  fun ssh_bind_listen(bind : Bind) : Int32
  fun ssh_bind_accept(bind : Bind, session : Session) : Int32

  # === Session functions ===
  fun ssh_new : Session
  fun ssh_free(session : Session) : Void
  fun ssh_disconnect(session : Session) : Void
  fun ssh_handle_key_exchange(session : Session) : Int32
  fun ssh_get_error(session : Void*) : LibC::Char*
  fun ssh_get_status(session : Session) : Int32
  fun ssh_set_auth_methods(session : Session, methods : Int32) : Int32
  fun ssh_set_server_callbacks(session : Session, cb : ServerCallbacksStruct*) : Int32
  fun ssh_blocking_flush(session : Session, timeout : Int32) : Int32

  # === Channel functions ===
  fun ssh_channel_new(session : Session) : Channel
  fun ssh_channel_free(channel : Channel) : Void
  fun ssh_channel_close(channel : Channel) : Int32
  fun ssh_channel_send_eof(channel : Channel) : Int32
  fun ssh_channel_is_open(channel : Channel) : Int32
  fun ssh_channel_is_eof(channel : Channel) : Int32
  fun ssh_channel_read(channel : Channel, dest : Void*, count : UInt32, is_stderr : Int32) : Int32
  fun ssh_channel_write(channel : Channel, data : Void*, len : UInt32) : Int32
  fun ssh_channel_write_stderr(channel : Channel, data : Void*, len : UInt32) : Int32
  fun ssh_channel_request_send_exit_status(channel : Channel, status : Int32) : Int32
  fun ssh_set_channel_callbacks(channel : Channel, cb : ChannelCallbacksStruct*) : Int32

  # === Event functions ===
  fun ssh_event_new : Event
  fun ssh_event_free(event : Event) : Void
  fun ssh_event_add_session(event : Event, session : Session) : Int32
  fun ssh_event_add_fd(event : Event, fd : SocketT, events : LibC::Short, cb : Void*, userdata : Void*) : Int32
  fun ssh_event_remove_fd(event : Event, fd : SocketT) : Int32
  fun ssh_event_dopoll(event : Event, timeout : Int32) : Int32

  # === Key functions (for pubkey auth) ===
  fun ssh_key_free(key : Key) : Void
  fun ssh_key_cmp(k1 : Key, k2 : Key, what : Int32) : Int32
  fun ssh_pki_import_pubkey_base64(b64 : LibC::Char*, type : Int32, key : Key*) : Int32
  fun ssh_key_type_from_name(name : LibC::Char*) : Int32
  
  # === Key fingerprint functions ===
  fun ssh_get_publickey_hash(key : Key, type : Int32, hash : UInt8**, hlen : LibC::SizeT*) : Int32
  fun ssh_get_fingerprint_hash(type : Int32, hash : UInt8*, len : LibC::SizeT) : LibC::Char*
  fun ssh_clean_pubkey_hash(hash : UInt8**) : Void
end

# Poll event flags (from poll.h)
POLLIN  = 0x0001_i16
POLLOUT = 0x0004_i16
POLLERR = 0x0008_i16
POLLHUP = 0x0010_i16
