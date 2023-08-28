#include <iostream>
#include <jsoncpp/json/json.h>

// secure messages

class Message
{
	public:
		std::string timestamp; // time of message
		std::string msg; // plaintext message to send or receive
		Json::Value messages;
		std::string messages_path;
		enum format {TEXT, IMAGE, VIDEO, _FILE_, DELETE};

		// message and time
		Message(std::string message, std::string tm, std::string message_path)
		{
			msg = message;
			timestamp = tm;
			messages_path = message_path;
		}

		// add to sessions/messages.json
		void add(std::string messages_path, format _type_=TEXT)
		{
			
		}
};
