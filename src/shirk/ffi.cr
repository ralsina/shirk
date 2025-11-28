@[Link("ssh")]
lib LibSSH
  # Basic types
  type SshSession = Void*
  type SshBind = Void*
  type SshChannel = Void*
  type SshMessage = Void*
  type SshEvent = Void*
  type SshKey = Void*

  # Error codes
  SSH_OK = 0
  SSH_ERROR = -1
  SSH_AGAIN = -2
  SSH_EOF = -127

  # Authentication methods
  SSH_AUTH_METHOD_UNKNOWN = 0
  SSH_AUTH_METHOD_NONE = 1
  SSH_AUTH_METHOD_PASSWORD = 2
  SSH_AUTH_METHOD_PUBLICKEY = 4
  SSH_AUTH_METHOD_HOSTBASED = 8
  SSH_AUTH_METHOD_INTERACTIVE = 16
  SSH_AUTH_METHOD_GSSAPI_MIC = 32
  SSH_AUTH_METHOD_GSSAPI_AUTH = 64

  # Authentication results
  SSH_AUTH_SUCCESS = 0
  SSH_AUTH_DENIED = -1
  SSH_AUTH_PARTIAL = -2
  SSH_AUTH_INFO = -3
  SSH_AUTH_AGAIN = -4
  SSH_AUTH_ERROR = -5

  # Message types
  SSH_REQUEST_AUTH = 1
  SSH_REQUEST_CHANNEL_OPEN = 2
  SSH_REQUEST_CHANNEL = 3
  SSH_REQUEST_SERVICE = 4
  SSH_REQUEST_GLOBAL = 5

  # SSH bind options (from enum ssh_bind_options_e)
  SSH_BIND_OPTIONS_BINDADDR = 0
  SSH_BIND_OPTIONS_BINDPORT = 1
  SSH_BIND_OPTIONS_BINDPORT_STR = 2
  SSH_BIND_OPTIONS_HOSTKEY = 3
  SSH_BIND_OPTIONS_DSAKEY = 4  # deprecated
  SSH_BIND_OPTIONS_RSAKEY = 5  # deprecated
  SSH_BIND_OPTIONS_BANNER = 6
  SSH_BIND_OPTIONS_LOG_VERBOSITY = 7
  SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = 8
  SSH_BIND_OPTIONS_ECDSAKEY = 9  # deprecated
  SSH_BIND_OPTIONS_IMPORT_KEY = 10

  # Channel request types
  SSH_CHANNEL_REQUEST_PTY = 0
  SSH_CHANNEL_REQUEST_EXEC = 1
  SSH_CHANNEL_REQUEST_SHELL = 2
  SSH_CHANNEL_REQUEST_SUBSYSTEM = 3
  SSH_CHANNEL_REQUEST_WINDOW_CHANGE = 4
  SSH_CHANNEL_REQUEST_X11 = 5
  SSH_CHANNEL_REQUEST_SIGNAL = 6

  # Initialize libssh
  fun ssh_init = ssh_init() : Int32
  fun ssh_finalize = ssh_finalize() : Int32

  # SSH bind functions
  fun ssh_bind_new = ssh_bind_new() : SshBind
  fun ssh_bind_free = ssh_bind_free(ssh_bind : SshBind) : Void
  fun ssh_bind_options_set = ssh_bind_options_set(ssh_bind : SshBind, type : Int32, value : Void*) : Int32
  fun ssh_bind_listen = ssh_bind_listen(ssh_bind : SshBind) : Int32
  fun ssh_bind_accept = ssh_bind_accept(ssh_bind : SshBind, session : SshSession) : Int32

  # SSH session functions
  fun ssh_new = ssh_new() : SshSession
  fun ssh_free = ssh_free(session : SshSession) : Void
  fun ssh_disconnect = ssh_disconnect(session : SshSession) : Void
  fun ssh_handle_key_exchange = ssh_handle_key_exchange(session : SshSession) : Int32
  fun ssh_set_auth_methods = ssh_set_auth_methods(session : SshSession, auth_methods : Int32) : Int32

  # Message functions
  fun ssh_message_get = ssh_message_get(session : SshSession) : SshMessage
  fun ssh_message_type = ssh_message_type(msg : SshMessage) : Int32
  fun ssh_message_subtype = ssh_message_subtype(msg : SshMessage) : Int32
  fun ssh_message_free = ssh_message_free(msg : SshMessage) : Void

  # Authentication message functions
  fun ssh_message_auth_user = ssh_message_auth_user(msg : SshMessage) : UInt8*
  fun ssh_message_auth_password = ssh_message_auth_password(msg : SshMessage) : UInt8*
  fun ssh_message_auth_reply_success = ssh_message_auth_reply_success(msg : SshMessage) : Int32
  fun ssh_message_auth_reply_failure = ssh_message_auth_reply_failure(msg : SshMessage, partial_methods : Int32) : Int32

  # Channel functions
  fun ssh_channel_new = ssh_channel_new(session : SshSession) : SshChannel
  fun ssh_channel_free = ssh_channel_free(channel : SshChannel) : Void
  fun ssh_channel_open_session = ssh_channel_open_session(channel : SshChannel) : Int32
  fun ssh_channel_request_pty = ssh_channel_request_pty(channel : SshChannel) : Int32
  fun ssh_channel_request_pty_size = ssh_channel_request_pty_size(channel : SshChannel, term : UInt8*, col : Int32, row : Int32) : Int32
  fun ssh_channel_request_shell = ssh_channel_request_shell(channel : SshChannel) : Int32
  fun ssh_channel_read = ssh_channel_read(channel : SshChannel, buffer : UInt8*, count : UInt32, is_stderr : Int32) : Int32
  fun ssh_channel_write = ssh_channel_write(channel : SshChannel, buffer : UInt8*, count : UInt32) : Int32
  fun ssh_channel_send_eof = ssh_channel_send_eof(channel : SshChannel) : Int32
  fun ssh_channel_close = ssh_channel_close(channel : SshChannel) : Int32
  fun ssh_channel_is_eof = ssh_channel_is_eof(channel : SshChannel) : Int32

  # Event functions
  fun ssh_event_new = ssh_event_new() : SshEvent
  fun ssh_event_free = ssh_event_free(event : SshEvent) : Void
  fun ssh_event_add_session = ssh_event_add_session(event : SshEvent, session : SshSession) : Int32
  fun ssh_event_dopoll = ssh_event_dopoll(event : SshEvent, timeout : Int32) : Int32

  # Error handling
  fun ssh_get_error = ssh_get_error(session : SshSession) : UInt8*

  # Callback structures - exact match to libssh headers

  # Server callback structure (lines 333-378 from callbacks.h)
  struct SshServerCallbacksStruct
    size : LibC::SizeT                                    # line 335: size_t size
    userdata : Void*                                      # line 339: void *userdata
    auth_password_function : (SshSession, LibC::Char*, LibC::Char*, Void*) -> Int32  # line 343: ssh_auth_password_callback
    auth_none_function : (SshSession, LibC::Char*, Void*) -> Int32                   # line 348: ssh_auth_none_callback
    auth_gssapi_mic_function : (SshSession, LibC::Char*, LibC::Char*, Void*) -> Int32 # line 353: ssh_auth_gssapi_mic_callback
    auth_pubkey_function : (SshSession, LibC::Char*, SshKey, Int32, Void*) -> Int32   # line 358: ssh_auth_pubkey_callback
    service_request_function : (SshSession, LibC::Char*, Void*) -> Int32               # line 363: ssh_service_request_callback
    channel_open_request_session_function : (SshSession, Void*) -> SshChannel         # line 367: ssh_channel_open_request_session_callback
    gssapi_select_oid_function : (SshSession, LibC::Char*, Int32, SshString, Void*) -> SshString  # line 371: ssh_gssapi_select_oid_callback
    gssapi_accept_sec_ctx_function : (SshSession, SshString, SshString*, Void*) -> Int32          # line 374: ssh_gssapi_accept_sec_ctx_callback
    gssapi_verify_mic_function : (SshSession, SshString, Void*, LibC::SizeT, Void*) -> Int32       # line 377: ssh_gssapi_verify_mic_callback
  end

  # Channel callback structure (lines 850-925 from callbacks.h)
  struct SshChannelCallbacksStruct
    size : LibC::SizeT                                    # line 852: size_t size
    userdata : Void*                                      # line 856: void *userdata
    channel_data_function : (SshSession, SshChannel, Void*, UInt32, Int32, Void*) -> Int32          # line 860: ssh_channel_data_callback
    channel_eof_function : (SshSession, SshChannel, Void*) -> Void                                     # line 864: ssh_channel_eof_callback
    channel_close_function : (SshSession, SshChannel, Void*) -> Void                                  # line 868: ssh_channel_close_callback
    channel_signal_function : (SshSession, SshChannel, LibC::Char*, Void*) -> Void                    # line 872: ssh_channel_signal_callback
    channel_exit_status_function : (SshSession, SshChannel, Int32, Void*) -> Void                     # line 876: ssh_channel_exit_status_callback
    channel_exit_signal_function : (SshSession, SshChannel, LibC::Char*, Int32, LibC::Char*, LibC::Char*, Void*) -> Void  # line 880: ssh_channel_exit_signal_callback
    channel_pty_request_function : (SshSession, SshChannel, LibC::Char*, Int32, Int32, Int32, Int32, Void*) -> Int32  # line 884: ssh_channel_pty_request_callback
    channel_shell_request_function : (SshSession, SshChannel, Void*) -> Int32                         # line 888: ssh_channel_shell_request_callback
    channel_auth_agent_req_function : (SshSession, SshChannel, Void*) -> Void                          # line 892: ssh_channel_auth_agent_req_callback
    channel_x11_req_function : (SshSession, SshChannel, Int32, LibC::Char*, LibC::Char*, UInt32, Void*) -> Void  # line 896: ssh_channel_x11_req_callback
    channel_pty_window_change_function : (SshSession, SshChannel, Int32, Int32, Int32, Int32, Void*) -> Int32      # line 900: ssh_channel_pty_window_change_callback
    channel_exec_request_function : (SshSession, SshChannel, LibC::Char*, Void*) -> Int32                           # line 904: ssh_channel_exec_request_callback
    channel_env_request_function : (SshSession, SshChannel, LibC::Char*, LibC::Char*, Void*) -> Int32                # line 908: ssh_channel_env_request_callback
    channel_subsystem_request_function : (SshSession, SshChannel, LibC::Char*, Void*) -> Int32                       # line 912: ssh_channel_subsystem_request_callback
    channel_write_wontblock_function : (SshSession, SshChannel, UInt32, Void*) -> Int32                              # line 916: ssh_channel_write_wontblock_callback
    channel_open_response_function : (SshSession, SshChannel, Bool, Void*) -> Void                                   # line 920: ssh_channel_open_resp_callback
    channel_request_response_function : (SshSession, SshChannel, Void*) -> Void                                      # line 924: ssh_channel_request_resp_callback
  end

  # Callback functions
  fun ssh_callbacks_init = ssh_callbacks_init(cbs : Void*) : Void
  fun ssh_set_server_callbacks = ssh_set_server_callbacks(session : SshSession, cbs : SshServerCallbacksStruct*) : Int32
  fun ssh_set_channel_callbacks = ssh_set_channel_callbacks(channel : SshChannel, cbs : SshChannelCallbacksStruct*) : Int32

  # Additional callback functions for ssh_server.c
  fun ssh_channel_write_stderr = ssh_channel_write_stderr(channel : SshChannel, data : UInt8*, len : UInt32) : Int32

  # String handling
  type SshString = Void*
  fun ssh_string_from_char = ssh_string_from_char(str : UInt8*) : SshString
  fun ssh_string_free = ssh_string_free(str : SshString) : Void
  fun ssh_send_issue_banner = ssh_send_issue_banner(session : SshSession, banner : SshString) : Int32

  # SSH constants already defined above

  # Additional constants
  SSH_KEY_CMP_PUBLIC = 1
end