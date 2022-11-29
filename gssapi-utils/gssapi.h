
#include <gssapi/gssapi.h>

#include <string>
#include <memory>
#include <exception>

namespace gssapi_utils {

    class cannot_establish_context 
        : public std::exception
    {
    public:
        const char *what() const noexcept override
        {
            return "Could not establish GSSAPI context";
        }
    };

    /// A helper class for GSSAPI based authentication
    /// and communication.
    ///
    /// This allows a client to authenticate to a server
    /// via e.g. Kerberos and exchange encrypted messages.
    class context {
    public:
        /// Establish a server context
        ///
        /// sock - the socket to communicate with
        /// service_name - use empty string to use the default credentials
        /// client_name  - the client name in 'user@DOMAIN' format
        context(int sock, std::string& client_name, const std::string& service_name);

        /// Establish a client context
        ///
        /// sock - the socket to communicate with
        /// service_host_name - in 'service@hostname.domain' format
        context(int sock, const std::string& service_host_name);

        ~context();

        /// Send data encrypted to peer
        bool send(const void *buffer, size_t length);

        /// Receive encrypted data from peer
        std::unique_ptr<char[]> recv(size_t& length);

    private:
        int          m_socket;
        gss_ctx_id_t m_context;
    };

}
