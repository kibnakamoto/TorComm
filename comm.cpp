#include <stdint.h>

//#include <boost/asio.hpp>
#include <boost/array.hpp>

#include "comm.h"

// socks5 proxy:
// https://github.com/sehe/asio-socks45-client/tree/main

two_parties::Client::Client()
{
	
}

Server::~Server()
{
	delete[] buffer;
}
