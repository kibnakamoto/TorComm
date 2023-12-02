#include <boost/filesystem/operations.hpp>
#include <cstdio>
#include <iostream>

#include <boost/filesystem.hpp>

#include "settings.h"
#include "keys.h"

////////// TODOS:
/* DONE:
 * MAJOR BUG DETECTED: ADD NO PADDING OPTION TO ALL AES ENCRYPTORS/DECRYPTORS. ALSO CHANGE PT SIZE TO CT SIZE ON PUT FUNCTION CALL - DONE
 *AES256_CBC
 * fix keys.cpp, redefine encryption because port key is now different - DONE
 * finish off securing the connect function in comm.cpp - DONE
 * define send/receive functions in P2P - DONE
 */

/* NOT DONE:
 * TODO: define network packet construction and destruction (Packet class, PacketParser class)
 * TODO: define key exchanging for 2 peer communication 
 * TODO: define key exchanging for multi peer communication 
 *
 * TODO: while receving and sending fully, make sure that large files are treated properly, don't read the whole data into a byte array but rather read as partitions into an array. This is for really large files where the ram isn't enough,this means remove the Packet/PacketParser classes
 */

/* MAJOR:
 *  TODO: integrate recv_full, send_full with IVs and HMAC/ECDSA. To do so, first encrypt all data at once. This would only apply to data that can fit in the ram available. Otherwise, apply the large data solution defined in the previous todo.
 */

int main()
{
	std::string keys_filename = "keys.txt";
	std::string current_path = boost::filesystem::current_path().string();
	std::string keys_path = current_path + "/security/" + keys_filename;
	Settings settings;
	if(!boost::filesystem::exists(keys_path)) { // if keys.txt exists
		// TODO: implement GUI
	}

	// open and parse settings.json
	try {
		settings = Settings();
		settings.get_values();
	} catch(Json::RuntimeError &e) // if file doesn't exist
	{
		init_settings_json(keys_path);
		settings = Settings();
		settings.get_values();
	}
	

	std::cout << std::endl;
	return 0;
}
