 /* Copyright (c) 2023 Taha
  * this program is free software: you can redistribute it and/or modify
  * it under the terms of the gnu general public license as published by
  * the free software foundation, either version 3 of the license, or
  * (at your option) any later version.
  * this program is distributed in the hope that it will be useful,
  * but without any warranty; without even the implied warranty of
  * merchantability or fitness for a particular purpose.  see the
  * gnu general public license for more details.
  * you should have received a copy of the gnu general public license
  * along with this program.  if not, see <https://www.gnu.org/licenses/>.
  *
  * Author: Taha
  * Date: 2023, Dec 9
  * Description: For custom errors. Mainly for when the cryptographic protocol picked doesn't exist.
  */

#ifndef ERRORS_H
#define ERRORS_H
#include <fstream>
#include <functional>
#include <ctime>
#include <chrono>
#include <filesystem>

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
    NO_ONE_SENDING,
    NOT_VERIFIED,
	NO_PROTOCOL,
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
    "NO_ONE_SENDING",
    "NOT_VERIFIED",
	"NO_PROTOCOL",
};

inline std::string abs_path(std::string file) {
	return std::filesystem::absolute(file).string();
}

// if USE_DEFAULT_VALUES, when an algorithm is not found, it will use a predefined one
#define USE_DEFAULT_VALUES false
#define DEBUG_MODE true // debug mode will allow throwing errors rather than assigning them
#define ERRORS_LOG_FILE abs_path("log/errors.log")
#define NETWORK_LOG_FILE abs_path("log/network.log")
inline bool log_network_issues = true; // changable

class ErrorHandling
{
	public:
		ERRORS error = NO_ERROR;
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
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::app);
			file << "\nENCRYPTION UNEXPECTED ERROR (in Cryptography::ProtocolData::init_cipher_data) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};

		// VERIFICATION
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> verification_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::app);
			file << "\nVERIFICATION ALGORITHM ERROR (in Cryptography::ProtocolData::init) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};

		// ELLIPTIC CURVE
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> curve_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::app);
			file << "\nELLIPTIC CURVE UNEXPECTED ERROR (in Cryptography::ProtocolData::init_cipher_data) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};
		
		// HASHING
		// find error and raise it after adding to a log file
		std::function<void(ERRORS, std::string)> hashing_unexpected_error=[](ERRORS error_code, std::string time) {
			std::ofstream file(ERRORS_LOG_FILE, std::fstream::app);
			file << "\nHASHING UNEXPECTED ERROR (in Cryptography::ProtocolData::init_hash_data) = TIME: "
				 << time << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
			file.close();
		
			throw error_code;
		};
};

#endif /* ERRORS_H */

