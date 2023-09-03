#include <stdint.h>

#include <boost/asio.hpp>
#include <boost/array.hpp>

// socks5 proxy:
// https://github.com/sehe/asio-socks45-client/tree/main

// Server can have multiple clients
class Server
{
	public:
			uint32_t buffer_size;
			boost::asio::socket_base::receive_buffer_size buff_size_recv;
			boost::asio::socket_base::send_buffer_size buff_size_send;
			//boost::asio::ip::tcp::socket sock;
			std::vector<uint8_t> buffer;

			Server(uint32_t buff_size)
			{
				buffer_size = buff_size;
				buffer.reserve(buffer_size);
			}
			
};

// Client can connect to multiple servers
class Client
{
	
};
