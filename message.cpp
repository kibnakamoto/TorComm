#include <iostream>
#include <jsoncpp/json/json.h>
#include <ctime>
#include <chrono>
#include <string>

#include "message.h"

// TODO: secure messages

// message and time
template<typename T>
Message<T>::Message(T message, std::string tm, std::string message_path, std::string from, std::string to, Settings settings)
{
	msg = message;
	timestamp = tm;
	messages_path = message_path;
}

// add to sessions/messages.json
template<typename T>
void Message<T>::add(std::string messages_path, format type)
{
	
}

std::string get_time()
{
    auto time = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(time);
	return std::ctime(&end_time);
}
