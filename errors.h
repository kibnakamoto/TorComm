#ifndef ERRORS_H
#define ERRORS_H
#include <fstream>
#include <functional>
#include <ctime>
#include <chrono>

// error codes
enum ERRORS
{
	NO_ERROR,
	WRONG_TYPE_ERROR,
	ELLIPTIC_CURVE_NOT_FOUND,
	COMMUNICATION_PROTOCOL_NOT_FOUND,
	HASHING_ALGORITHM_NOT_FOUND,
	ENCRYPTION_ALGORITHM_NOT_FOUND,
	VERIFICATION_ALGORITHM_NOT_FOUND,
};

// error names as string
const constexpr static char* ERROR_STRING[]
{
	"NO_ERROR",
	"WRONG_TYPE_ERROR",
	"ELLIPTIC_CURVE_NOT_FOUND",
	"COMMUNICATION_PROTOCOL_NOT_FOUND",
	"HASHING_ALGORITHM_NOT_FOUND",
	"ENCRYPTION_ALGORITHM_NOT_FOUND",
	"VERIFICATION_ALGORITHM_NOT_FOUND",
};

// if USE_DEFAULT_VALUES, when an algorithm is not found, it will use a predefined one
#define USE_DEFAULT_VALUES false
#define ERRORS_LOG_FILE "log/errors.log"
#define NETWORK_LOG_FILE "log/network.log"
inline bool log_network_issues = true; // changable

class ErrorHandling
{
	public:
		ERRORS error;
		ErrorHandling() = default;

		// lambda function is for what to do in case of error
		void error_handle(ERRORS check_error, auto&& lambda_for_error, auto&& lambda_for_unexpected_error, auto &&get_time)
		{
			// if error caused: can only be ENCRYPTION_ALGORITHM_NOT_FOUND
			if(error != NO_ERROR) {
				if(error == check_error) {
					lambda_for_error();
				} else {
					// if a different error raised: unexpected behaviour
					lambda_for_unexpected_error(error, get_time());
				}
				error = NO_ERROR; // assign error code to None
			}
		}

		// CIPHER
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> encryption_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::in | std::fstream::out | std::fstream::app);
			file << "\nENCRYPTION UNEXPECTED ERROR (in Cryptography::ProtocolData::init_cipher_data) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};

		// VERIFICATION
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> verification_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::in | std::fstream::out | std::fstream::app);
			file << "\nVERIFICATION ALGORITHM ERROR (in Cryptography::ProtocolData::init) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};

		// ELLIPTIC CURVE
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> curve_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::in | std::fstream::out | std::fstream::app);
			file << "\nELLIPTIC CURVE UNEXPECTED ERROR (in Cryptography::ProtocolData::init_cipher_data) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};
		
		// HASHING
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> hashing_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::in | std::fstream::out | std::fstream::app);
			file << "\nHASHING UNEXPECTED ERROR (in Cryptography::ProtocolData::init_hash_data) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};
};

#endif /* ERRORS_H */

