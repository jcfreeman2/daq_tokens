
#include <cstdint>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <jwt-cpp/jwt.h>

#include <netinet/in.h>
#include <openssl/crypto.h>

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <openssl/evp.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <memory>
#include <atomic>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

#include "gssapi-utils/gssapi.h"

#include <pwd.h>
#include <csignal>

typedef std::string private_key_t;

// Create a SHA256 hash of the public key to be used as key identifer
std::string
get_fingerprint(const std::string& key, const std::string& digest)
{
    auto evp_priv = jwt::helper::load_private_key_from_string(key);

    unsigned char *data = nullptr;
    int size = i2d_PUBKEY(evp_priv.get(), &data);
    if(size < 0) { throw std::runtime_error("Cannot convert to DER"); }

    std::unique_ptr<unsigned char[]> holder(data);

    // Create digest context, CentOS 8 has newer openssl version.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif

    if(!ctx) { throw std::runtime_error("Cannot create MD context"); }

    if(!EVP_DigestInit(ctx.get(), EVP_get_digestbyname(digest.c_str()))) { throw std::runtime_error("Cannot initialize message digest"); }

    if(!EVP_DigestUpdate(ctx.get(), data, size)) { throw std::runtime_error("Cannot update message digest"); }

    std::unique_ptr<uint8_t[]> fingerprint(new uint8_t[EVP_MD_CTX_size(ctx.get())]);
    unsigned int length;

    if(!EVP_DigestFinal(ctx.get(), fingerprint.get(), &length)) {
        throw std::runtime_error("Cannot finalize message digest");
    }

    // Turn into hex
    // char fp[130];
    std::unique_ptr<char[]> out(new char[length * 2 + 1]);
    auto fp = out.get();
    for(decltype(length) i = 0; i < length; i++) {
        sprintf(&fp[i*2], "%02x", fingerprint[i]);
    }
    fp[length * 2] = '\0';
    return fp;
}

// Create the token from the information given
std::string
make_token(const private_key_t& key, const std::string& fp, const std::string& user)
{
    auto uuid{boost::uuids::random_generator()()};

    auto now = std::chrono::system_clock::now();
    auto token = jwt::create()
        .set_type("JWT")
        .set_issuer("https://auth.cern.ch/auth/realms/cern")
        .set_audience("atlas-tdaq-token")
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::minutes{20})
        .set_not_before(now)
        .set_subject(user)
        .set_id(boost::uuids::to_string(uuid))
        .set_key_id(fp)
        .sign(jwt::algorithm::rs256{"",key});
    return token;
}

void
serve_local(const private_key_t& key, const std::string& fp, const std::string& socket_path)
{
    int server_sock = -1;
    if(getenv("LISTEN_FDS")) {
        // systemd socket activated
        server_sock = 3;
    } else {
        if(socket_path.size() > 107) {
            std::cerr << "token_meister: socket path too long (max 107 chars)\n";
            exit(1);
        }

        server_sock = socket(PF_LOCAL, SOCK_STREAM, 0);
        if(server_sock < 0) {
            perror("token_meister: create socket");
            exit(1);
        }

        remove(socket_path.c_str());
        struct sockaddr_un addr{AF_LOCAL};
        strncpy(addr.sun_path, socket_path.c_str(), 107);
        if(bind(server_sock, (sockaddr *)&addr, sizeof addr) < 0) {
            perror("token_meister: bind socket");
            exit(1);
        }

        if(listen(server_sock, SOMAXCONN) < 0) {
            perror("token_meister: listen");
            exit(1);
        }
    }

    while(true) {
        int client = accept(server_sock, nullptr, 0);
        ucred credentials;
        socklen_t length = sizeof credentials;
        if(getsockopt(client, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0) {
            perror("token_meister: getsockopt(SO_PEERCRED)");
            exit(1);
        }

        if(auto pw = getpwuid(credentials.uid)) {
            auto token = make_token(key, fp, pw->pw_name);
            size_t sent = 0;
            while(sent < token.size()) {
                int n = send(client, token.c_str() + sent, token.size() - sent, 0);
                if(n < 0) {
                    perror("token_meister: send()");
                    break;
                }
                sent += n;
            }
        } else {
            std::cerr << "token_meister: no credentials\n";
        }
        close(client);
    }
}

void
serve_gssapi(const private_key_t& key, const std::string& fp, const std::string& port)
{
    int server_socket = -1;
    if(getenv("LISTEN_FDS")) {
        // systemd socket activated
        server_socket = 3;
    } else {

        addrinfo hints{AI_PASSIVE | AI_NUMERICSERV, AF_UNSPEC, SOCK_STREAM, 0};
        addrinfo *result;

        int err = getaddrinfo(nullptr, port.c_str(), &hints, &result);
        if(err != 0) {
            std::cerr << gai_strerror(err);
            exit(1);
        }

        for(addrinfo *ai = result; ai != 0; ai = ai->ai_next) {
            server_socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if(server_socket >= 0) {
                int option = 1;
                setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
                           (char *)&option, sizeof(option));

                if(bind(server_socket, ai->ai_addr, ai->ai_addrlen) < 0) {
                    perror("token_meister: bind");
                    exit(1);
                }
                break;
            }
            continue;
        }

        freeaddrinfo(result);

        if(server_socket == -1) {
            perror("token_meister: create server socket");
            exit(1);
        }

        if(listen(server_socket, 1024) < 0) {
            perror("token_meister: listen");
            exit(1);
        }
    }

    while(true) {
        int client = accept(server_socket, nullptr, 0);
        if(client < 0) {
            perror("token_meister: accept");
            continue;
        }

        try {
            std::string user;
            gssapi_utils::context context{client, user, "atdaqjwt"};
            std::string token = make_token(key, fp, user.substr(0, user.find('@')));
            context.send(token.c_str(), token.size());
        } catch(std::exception& ex) {
            std::cerr << ex.what() << std::endl;
        }
        close(client);
    }
}

void time_it(const private_key_t& key, const std::string& fp, const std::string& user)
{
    const int count = 1000;

    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < count; i++) {
        [[maybe_unused ]] auto token = make_token(key, fp, user);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> time = end - start;
    std::cout << time.count()/count << " milliseconds/token" << std::endl;
}

std::string
load_private_key(const std::string& path)
{
    std::ifstream s{path.c_str()};
    if(s) {
        char buffer[32000];
        s.read(buffer, sizeof buffer - 1);
        buffer[s.gcount()] = '\0';
        return buffer;
    }
    return "";
}

void usage()
{
    std::cerr
        << "usage: token_meister [--gssapi|--make|--time][--hash=...] /path/to/private/key /path/to/socket|port|user\n\n"
        << "   --local       run a local server provding tokens on /path/to/socket (DEFAULT)\n"
        << "   --gssapi      runs a GSSAPI server listening on TCP 'port'\n"
        << "   --make        generates a token for 'user' interactively\n"
        << "   --time        timing output to generate token for 'user'\n"
        << "   --hash=<HASH> select hash function for finger print\n"
        << std::endl;
}

int
main(int argc, char *argv[])
{
    enum Mode { local, gssapi, make, timing } mode{local};

    if(argc < 2) {
        usage();
        exit(1);
    }

    argc--;
    argv++;

    OpenSSL_add_all_digests();
    std::string digest{"SHA256"};

    while(**argv == '-') {
        if(strcmp(*argv, "--help") == 0) {
            usage();
            exit(0);
        } else if(strcmp(*argv, "--local") == 0) {
            mode = local;
            argv++;
            argc--;
        } else if(strcmp(*argv, "--gssapi") == 0) {
            mode = gssapi;
            argv++;
            argc--;
        } else if(strcmp(*argv, "--make") == 0) {
            mode = make;
            argv++;
            argc--;
        } else if(strcmp(*argv, "--time") == 0) {
            mode = timing;
            argv++;
            argc--;
        } else if(strncmp(*argv, "--hash", 6) == 0) {
            if((*argv)[6] == '=') {
                digest = *argv + 7;
            } else {
                argv++;
                argc--;
                if(argc == 0) {
                    std::cerr << "token_meister: --hash requires argument" << std::endl;
                    exit(1);
                }
                digest = *argv;
            }

            if(EVP_get_digestbyname(digest.c_str()) == nullptr) {
                std::cerr << "token_meister: invalid hash method: " << digest << std::endl;
                exit(1);
            }

            argv++;
            argc--;
        } else {
            std::cerr << "token_meister: invalid option: " << *argv << std::endl;
            usage();
            exit(1);
        }
    }

    if(argc < 1) {
        usage();
    }

    std::string private_key = load_private_key(*argv);

    argv++;
    argc--;

    auto fp = get_fingerprint(private_key, digest);

    switch(mode) {
    case local:
        serve_local(private_key, fp, argc ? *argv : "/run/tdaq_token");
        break;
    case gssapi:
        serve_gssapi(private_key, fp, argc ? *argv : "8991");
        break;
    case make:
        std::cout << make_token(private_key, fp, *argv);
        break;
    case timing:
        time_it(private_key, fp, *argv);
        break;
    default:
        abort();
    }

    return 0;

}
