#include <iostream>
#include <execution>

#include "sock_wp.h"

int main() {
	try {
		http::HttpConnection tcp{"blockchain.info", http::HTTPS_PORT};
	} catch(const std::exception& e) {
		std::cout << e.what() << std::endl;
	}
	return 0;
}
