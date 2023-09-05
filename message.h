#include <jsoncpp/json/json.h>

// get current time
std::string get_time();


class Message
{
	public:
		std::string timestamp; // time of message
		std::string msg; // plaintext message to send or receive
		Json::Value messages;
		std::string messages_path;
		enum format {TEXT, IMAGE, VIDEO, _FILE_, DELETE};

		// message and time
		Message(std::string message, std::string tm, std::string message_path, std::string from, std::string to);

		// add to sessions/messages.json
		void add(std::string messages_path, format type=TEXT);
};

