
#include "gssapi-utils/gssapi.h"

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

namespace {

    // internal helper routines for GSSAPI

    // send all data 
    bool send_all(int s, const char *buffer, size_t length)
    {
        size_t sent = 0;
        while(sent < length) {
            int n = send(s, &buffer[sent], length - sent, 0);
            if(n <= 0) {
                return false;
            }
            sent += n;
        }
        return true;
    }

    // receive all data
    bool recv_all(int s, char *buffer, size_t length)
    {
        size_t received = 0;
        while(received < length) {
            int n = recv(s, &buffer[received], length - received, 0);
            if(n <= 0) {
                return false;
            }
            received += n;
        }
        return true;
    }
    
    // receive a token 
    // caller must free memory
    bool recv_token(int s, gss_buffer_desc *buffer)
    {
        uint32_t length;

        // note: length is little-endian
        if(!recv_all(s, (char *)&length, sizeof(length))) {
            return false;
        }

        buffer->value = (void *)malloc(length);
        buffer->length = length;
        if(buffer->value == nullptr) return -1;

        if(!recv_all(s, (char *)buffer->value, length)) {
            free(buffer->value);
            return false;
        }

        return true;
    }

    // send token
    bool send_token(int s, gss_buffer_desc *buffer)
    {
        uint32_t length = buffer->length;
        if(!send_all(s, (char *)&length, sizeof length)) {
            return false;
        }

        return send_all(s, (char *)buffer->value, buffer->length);
    }

    // Create GSSAPI service name
    //
    // For server: just pass service name
    // For client: pass service name '@' host
    //
    // Caller must free name with gss_release_name
    gss_name_t
    make_service_name(const std::string& service_name)
    {
        gss_buffer_desc name_buf;
        gss_name_t      name;
        OM_uint32       maj_stat, min_stat;

        name_buf.value = (void *)service_name.c_str();
        name_buf.length = strlen((const char *)name_buf.value) + 1;
        maj_stat = gss_import_name(&min_stat, &name_buf,
                                   (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &name);
        if (maj_stat != GSS_S_COMPLETE) {
            return nullptr;
        }
        return name;
    }
    
    // Acquire server credentials
    //
    // returns nullptr on error
    //
    // caller must free credentials with gss_release_cred
    //
    gss_cred_id_t
    acquire_server_credentials(const std::string& service_name)
    {
        if(service_name.empty()) {
            return GSS_C_NO_CREDENTIAL;
        }

        gss_name_t server_name = make_service_name(service_name);

        gss_cred_id_t   creds = nullptr; 
        OM_uint32       min_stat;
        if(server_name) {
            gss_acquire_cred(&min_stat, server_name, 0,
                                    GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
                                    &creds, NULL, NULL);
        }
        gss_release_name(&min_stat, &server_name);
        return creds;
    }

    // s - socket to communicate with
    // service_name - the service name if non-standard
    // returns: client name (in user@DOMAIN format)
    //
    gss_ctx_id_t
    establish_server_context(int s, const std::string& service_name, std::string& client_name)
    {
        auto server_creds = acquire_server_credentials(service_name);

        gss_ctx_id_t context = GSS_C_NO_CONTEXT;
        gss_buffer_desc send_tok, recv_tok;
        gss_name_t client;
        gss_OID doid;
        OM_uint32 maj_stat, min_stat, acc_sec_min_stat;
        OM_uint32 ret_flags;

        do {
            if (!recv_token(s, &recv_tok))
                break;

            maj_stat =
                gss_accept_sec_context(&acc_sec_min_stat,
                                       &context,
                                       server_creds,
                                       &recv_tok,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &client,
                                       &doid,
                                       &send_tok,
                                       &ret_flags,
                                       NULL,     /* ignore time_rec */
                                       NULL);    /* ignore del_cred_handle */

            // (void) gss_release_buffer(&min_stat, &recv_tok);
            free(recv_tok.value);

            if (send_tok.length != 0) {
                if (!send_token(s, &send_tok)) {
                    return nullptr;
                }

                (void) gss_release_buffer(&min_stat, &send_tok);
            }

            if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
                if (context != GSS_C_NO_CONTEXT) {
                    gss_delete_sec_context(&min_stat, &context,
                                           GSS_C_NO_BUFFER);
                }
                context = GSS_C_NO_CONTEXT;
                break;
            }

        } while (maj_stat == GSS_S_CONTINUE_NEEDED);

        // always release credentials
        if(server_creds != GSS_C_NO_CREDENTIAL) {
            gss_release_cred(&min_stat, &server_creds);
        }

        // if context was establised
        if(context) {
            // translate name insto string
            gss_buffer_desc client_buf;
            maj_stat = gss_display_name(&min_stat, client, &client_buf, &doid);
            if (maj_stat != GSS_S_COMPLETE) {
                // do not continue if this failed
                (void) gss_delete_sec_context(&min_stat, &context,
                                              GSS_C_NO_BUFFER);
                context = GSS_C_NO_CONTEXT;
            } else {
                // success, copy out string and release buffer
                client_name.assign((char *)client_buf.value, client_buf.length);
                gss_release_buffer(&min_stat, &client_buf);
            }
            gss_release_name(&min_stat, &client);
        }

        return context;
    }

    // Establish the GSSAPI client context
    // return nullptr on error
    gss_ctx_id_t 
    establish_client_context(int sock, const std::string& service_host)
    {
        gss_name_t target_name = make_service_name(service_host);
        if(target_name == nullptr)
            return nullptr;

        OM_uint32 maj_stat, min_stat;

        gss_ctx_id_t    context{GSS_C_NO_CONTEXT};
        gss_buffer_t    input{GSS_C_NO_BUFFER};
        gss_buffer_desc input_token{0, nullptr};
        gss_buffer_desc output_token{0, nullptr};

        do {
            maj_stat =  gss_init_sec_context(&min_stat,
                                             GSS_C_NO_CREDENTIAL,
                                             &context,
                                             target_name,
                                             GSS_C_NO_OID,
                                             GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
                                             0,
                                             GSS_C_NO_CHANNEL_BINDINGS,
                                             input,
                                             nullptr,
                                             &output_token, 
                                             nullptr,
                                             nullptr);

            if(input != GSS_C_NO_BUFFER) {
                gss_release_buffer(&min_stat, input);
            }

            if(output_token.length != 0) {
                bool sent = send_token(sock, &output_token);
                gss_release_buffer(&min_stat, &output_token);

                if(!sent) {
                    break;
                }
            }

            if(maj_stat == GSS_S_CONTINUE_NEEDED) {
                if(!recv_token(sock, &input_token)) {
                    break;
                }
            }

            input = &input_token;

        } while(maj_stat == GSS_S_CONTINUE_NEEDED);

        if(maj_stat != GSS_S_COMPLETE) {
            context = nullptr;
        }
        
        gss_release_name(&min_stat, &target_name);

        return context;
    }

}

namespace gssapi_utils {

    context::context(int sock, std::string& client_name, const std::string& service_name)
        : m_socket(sock),
          m_context(GSS_C_NO_CONTEXT)
    {
        m_context = establish_server_context(m_socket, service_name, client_name);
        if(m_context == nullptr) {
            throw cannot_establish_context();
        }
    }

    context::context(int sock, const std::string& service_host_name)
        : m_socket(sock),
          m_context(GSS_C_NO_CONTEXT)
    {
        m_context = establish_client_context(m_socket, service_host_name);
        if(m_context == nullptr) {
            throw cannot_establish_context();
        }
    }

    context::~context()
    {
        close(m_socket);
        OM_uint32 min;
        gss_delete_sec_context(&min, &m_context, GSS_C_NO_BUFFER);
    }

    bool context::send(const void *buffer, size_t length)
    {
        OM_uint32 maj, min;
        gss_buffer_desc cleartext{length, (void *)buffer};
        gss_buffer_desc encrypted{0, nullptr};
        maj = gss_wrap(&min, m_context, 1, GSS_C_QOP_DEFAULT, &cleartext, nullptr, &encrypted);
        if(maj != GSS_S_COMPLETE) {
            return false;
        }
        return send_token(m_socket, &encrypted);
    }

    std::unique_ptr<char[]> context::recv(size_t& buffer_length)
    {
        gss_buffer_desc encrypted;
        gss_buffer_desc cleartext;
        buffer_length = 0;
        if(!recv_token(m_socket, &encrypted)) {
            return std::unique_ptr<char[]>();
        }
        OM_uint32 maj, min;
        maj = gss_unwrap(&min, m_context, &encrypted, &cleartext, nullptr, nullptr);
        gss_release_buffer(&min, &encrypted);
        if(maj != GSS_S_COMPLETE) {
            return std::unique_ptr<char[]>();
        }
        buffer_length = cleartext.length;
        return std::unique_ptr<char[]>(static_cast<char*>(cleartext.value));
    }

}
