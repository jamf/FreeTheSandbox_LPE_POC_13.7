//
//  xpc.h
//  D22_final_iOS
//
//  Created by aa on 3/23/19.
//  Copyright © 2019 aa. All rights reserved.
//

#ifndef xpc_h
#define xpc_h


#define XPC_DECL(name) typedef xpc_object_t name##_t

extern const char *const _xpc_error_key_description;
#define XPC_ERROR_KEY_DESCRIPTION _xpc_error_key_description

typedef void * xpc_object_t;
XPC_DECL(xpc_connection);
typedef void (^xpc_handler_t)(xpc_object_t object);

void
xpc_connection_set_event_handler(xpc_connection_t connection,
                                 xpc_handler_t handler);
void
xpc_connection_send_message_with_reply(xpc_connection_t connection,
                                       xpc_object_t message, dispatch_queue_t _Nullable replyq,
                                       xpc_handler_t handler);
xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection,
                                                         xpc_object_t message);
void
xpc_connection_resume(xpc_connection_t connection);
void
xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message);

pid_t
xpc_connection_get_pid(xpc_connection_t connection);

xpc_connection_t
xpc_connection_create_mach_service(const char *name, dispatch_queue_t _Nullable targetq, uint64_t flags);

xpc_object_t
xpc_dictionary_create(const char * _Nonnull const * _Nullable keys,
                      const xpc_object_t _Nullable * _Nullable values, size_t count);
void
xpc_dictionary_set_int64(xpc_object_t xdict, const char *key, int64_t value);
void
xpc_dictionary_set_uint64(xpc_object_t xdict, const char *key, uint64_t value);
void
xpc_dictionary_set_data(xpc_object_t xdict, const char *key, const void *bytes,
                        size_t length);
void
xpc_dictionary_set_value(xpc_object_t xdict, const char *key,
                         xpc_object_t _Nullable value);
void
xpc_dictionary_set_string(xpc_object_t xdict, const char *key,
                          const char *string);
void
xpc_dictionary_set_bool(xpc_object_t xdict, const char *key, bool value);

void
xpc_dictionary_set_mach_send(xpc_object_t xdict, const char *key, mach_port_t port);

void
xpc_dictionary_set_mach_recv(xpc_object_t xdict, const char *key, mach_port_t port);


const char * _Nullable
xpc_dictionary_get_string(xpc_object_t xdict, const char *key);

xpc_object_t
xpc_array_create(const xpc_object_t _Nonnull * _Nullable objects, size_t count);
void
xpc_array_append_value(xpc_object_t xarray, xpc_object_t value);

xpc_object_t
xpc_data_create(const void * _Nullable bytes, size_t length);
void
xpc_connection_cancel(xpc_connection_t connection);

xpc_object_t xpc_null_create(void);

void
xpc_connection_resume(xpc_connection_t connection);
char *
xpc_copy_description(xpc_object_t object);


#endif /* xpc_h */
