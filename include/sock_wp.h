#ifndef __SOCKET_WRAPPER_H__
#define __SOCKET_WRAPPER_H__

extern "C" {

/* Socket API */
#include <resolv.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>


}

#include "openssl/ssl.h"

#include <iostream>
#include <string>
#include <sstream>

#include "logger/log.h"

namespace http {

auto logger = getLogger(); // Log to console

static constexpr int HTTPS_PORT = 443;
static constexpr int HTTP_PORT = 80;

enum class Status {
	RC_SUCCESS = 0,
	RC_SOCKET_ERROR,
	RC_SOCKET_HOST,
	RC_SOCKET_CONNECT
};

std::string err2str(Status status) {
	switch (status) {
		case Status::RC_SOCKET_ERROR:
			return "Problem with create socket";
		case Status::RC_SOCKET_HOST:
			return "Problem with hostname";
		case Status::RC_SOCKET_CONNECT:
			return "Problem with connection";
		default:
			return "";
	}
}

std::string errno2str(Status status) {
	std::stringstream ss;

	ss << err2str(status) << ": " << strerror(errno);

	return ss.str();
}

bool validateIP(const std::string& s) {
	return true;
}

class SocketWrapper {
public:
	using Addr = in_addr;
	using SockAddr = sockaddr;
	using SockAddrIn = sockaddr_in;
protected:
	int _sockfd;
	SockAddrIn _sockAddr;
public:
	SocketWrapper() = delete;
	SocketWrapper(int domain, int type, int protocol) : _sockAddr{0} {
		_sockfd = socket(domain, type, protocol);
		if (_sockfd == -1) {
			throw std::invalid_argument(errno2str(Status::RC_SOCKET_ERROR));
		}
	}

	virtual ~SocketWrapper() {
		close(_sockfd);
	}
};

class TcpConnection : public SocketWrapper {
public:

public:
	explicit TcpConnection(const std::string& url, int port) :
			 SocketWrapper{AF_INET, SOCK_STREAM, 0} {

		_sockAddr.sin_family = AF_INET;
		_sockAddr.sin_port = port;
		inet_aton(url.c_str(), &_sockAddr.sin_addr);

		logger(DEBUG) << "Hostname: " << inet_ntoa(_sockAddr.sin_addr);
	}

	virtual ~TcpConnection() {}
};

struct Deleter_ssl_ctx {
	void operator()(SSL_CTX* ctx) {
		std::cout << "Deleter SSL_CTX" << std::endl;
		SSL_CTX_free(ctx);
	}
};

struct Deleter_ssl {
	void operator()(SSL* ssl) {
		std::cout << "Deleter SSL" << std::endl;
		SSL_free(ssl);
	}
};

void ssl_library_init() {
	SSL_load_error_strings();
	SSL_library_init();
}

class HttpConnection : public SocketWrapper {
private:
	std::unique_ptr<SSL_CTX, Deleter_ssl_ctx> _ctx;
	std::unique_ptr<SSL, Deleter_ssl> _ssl;
public:
	explicit HttpConnection(const std::string& url, uint16_t port) :
		SocketWrapper{AF_INET, SOCK_STREAM, 0},
		_ctx(nullptr),
		_ssl(nullptr) {

		auto host = gethostbyname(url.c_str());
		if (host == nullptr) {
			throw std::invalid_argument(errno2str(Status::RC_SOCKET_HOST));
		}

		auto addr = reinterpret_cast<Addr**>(host->h_addr_list);
		if (addr == nullptr) {
			throw std::invalid_argument("Don't find IP address");
		}

		_sockAddr.sin_family = AF_INET;
		_sockAddr.sin_addr = *addr[0];
		_sockAddr.sin_port = ntohs(port);

		logger(DEBUG) << "Hostname: " << inet_ntoa(_sockAddr.sin_addr);

		int err = connect(_sockfd, reinterpret_cast<SockAddr*>(&_sockAddr),
				  sizeof(_sockAddr));
		if (err != 0) {
			throw std::invalid_argument(errno2str(Status::RC_SOCKET_CONNECT));
		}

		logger(DEBUG) << "Connection successful.";
	}
};

};

#endif /* __SOCKET_WRAPPER_H__ */
