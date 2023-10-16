#include <stdint.h>

//#include <boost/asio.hpp>
#include <boost/array.hpp>

#include "comm.h"
#include "keys.h"
#include "errors.h"

// socks5 proxy:
// https://github.com/sehe/asio-socks45-client/tree/main
//

template<typename T>
PacketParser<T>::PacketParser(T packet)
{
	// T has to be either uint8_t* or std::string
	if constexpr(std::is_same<T, uint8_t*>() || std::is_same<T, std::string>()) {
		error = WRONG_TYPE_ERROR;
	} else {
		data = packet;
	}
	//switch (format)
	//{
	//	case Message::TEXT:
	//		;
	//	case Message::IMAGE:
	//		;
	//	case Message::VIDEO:
	//		;
	//	case Message::_FILE_:
	//		;
	//	case Message::DELETE:
	//		;
	//}
}

// get the first 72-bits of data from packet
template<typename T>
void PacketParser<T>::get72bits(uint64_t &len, uint8_t &type)
{
	len=0;
	for(uint8_t i=0;i<8;i++) {
		len <<= 8;
		len |= data[i];
	}
	type = data[8];
}
