#include <iostream>
#include <jsoncpp/json/json.h>

// secure messages

class Message
{
	public:
		std::string timestamp; // time of message
		std::string msg; // plaintext message to send or receive
		Json::Value messages;
		enum format {TEXT, IMAGE, VIDEO, OTHER}; // currently only text

		// message and time
		Message(std::string message, std::string tm)
		{
			msg = message;
			timestamp = tm;
		}

		// add to sessions/messages.json
		void add(std::string messages_path)
		{
			
		}
};
