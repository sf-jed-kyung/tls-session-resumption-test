#include <iostream>
#include <fstream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

const std::string HOST = "echo.websocket.events";
const int PORT = 443;
const std::string SESSION_FILE = "tls_session.dat";

bool websocket_handshake(BIO* bio) {
    const char* request =
        "GET / HTTP/1.1\r\n"
        "Host: echo.websocket.events\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    
    BIO_write(bio, request, strlen(request));
    char buffer[4096];
    int len = BIO_read(bio, buffer, sizeof(buffer) - 1);

    if (len <= 0) return false;
    buffer[len] = '\0';

    std::cout << "\n[Handshake Response]\n" << buffer << std::endl;
    return true;
}

SSL_SESSION* load_session(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return nullptr;

    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data());
    return d2i_SSL_SESSION(nullptr, &p, data.size());
}

void save_session(SSL_SESSION* session, const std::string& path) {
    unsigned char* buf = nullptr;
    int len = i2d_SSL_SESSION(session, &buf);
    if (len <= 0) return;

    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<char*>(buf), len);
    OPENSSL_free(buf);
}

bool connect_and_handshake(bool resume) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr); // 테스트용

    BIO* bio = BIO_new_ssl_connect(ctx);
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);

    SSL_set_tlsext_host_name(ssl, HOST.c_str());

    const unsigned char alpn[] = { 8, 'h','t','t','p','/','1','.','1' };
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    if (resume) {
        SSL_SESSION* session = load_session(SESSION_FILE);
        if (session) {
            std::cout << "[INFO] Attempting to resume session\n";
            SSL_set_session(ssl, session);
            SSL_SESSION_free(session);
        }
    }

    BIO_set_conn_hostname(bio, (HOST + ":" + std::to_string(PORT)).c_str());

    if (BIO_do_connect(bio) <= 0 || BIO_do_handshake(bio) <= 0) {
        std::cerr << "[ERROR] TLS connection failed\n";
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return false;
    }

    std::cout << "[INFO] TLS 1.3 handshake complete\n";

    if (!websocket_handshake(bio)) {
        std::cerr << "[ERROR] WebSocket handshake failed\n";
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return false;
    }

    SSL_SESSION* newSession = SSL_get1_session(ssl);
    save_session(newSession, SESSION_FILE);
    SSL_SESSION_free(newSession);

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return true;
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    std::cout << "\n[1] First connection (fresh handshake)\n";
    connect_and_handshake(false);

    std::cout << "\n[2] Second connection (attempt session resumption)\n";
    connect_and_handshake(true);

    return 0;
}
