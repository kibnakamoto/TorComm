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
  * Description: This is the main file of this project. This is for people to securely communicate over a public channel using a P2P system (TCP/IPv6). 
  */


#include <boost/filesystem/operations.hpp>
#include <cstdio>
#include <iostream>

#include <boost/filesystem.hpp>

#include "settings.h"
#include "keys.h"

////////// TODOS:
/* DONE:
 * MAJOR BUG DETECTED: ADD NO PADDING OPTION TO ALL AES ENCRYPTORS/DECRYPTORS. ALSO CHANGE PT SIZE TO CT SIZE ON PUT FUNCTION CALL - Oct/Nov
 *AES256_CBC
 * fix keys.cpp, redefine encryption because port key is now different - Oct/Nov
 * finish off securing the connect function in comm.cpp - Oct/Nov
 * define send/receive functions in P2P - Oct/Nov
 * integrate recv_full, send_full with IVs and HMAC/ECDSA. - Dec 3 2023
 * MAJOR BUG DETECTED: overflow of uint16_t values because they are assigned uint64_t for networking - Dec 3, 2023
   					   Possibly debugged, needs further checking - Dec 7, 2023
   					   Check finished - Dec 9, 2023
 * hmac/iv with recv_full and send full, this would only apply to data that can fit in the ram available. Otherwise, apply the large data solution defined in the previous todo - Dec 2, 2023
 * while receving and sending fully, make sure that large files are treated properly, don't read the whole data into a byte array but rather read as partitions into an array. This is for really large files where the ram isn't enough - Dec 30, 2023
 * define key exchanging for 2 peer communication  - Jan 3, 2024
 */

/* FUTURE TODOS: (Not for version 1.0)
 *
 * TODO: add ecdsa support on send/recv and protocol data sizes
 * TODO: Optimize the iv and other pointer allocations only once and take them as a function parameter for more efficiency.
 */

/* NOT DONE:
 * TODO: make all parameters relating to length 64-bit as required by send_full function (cryptography)
 * TODO: define key exchanging for multi peer communication 
 * TODO: When sending the protocol no in P2P::send_two_party_ecdh(), make sure to encrypt the protocol number. the padding can be completely random values (15-bytes). The first byte will be the protocol number. This will make the protocol number private so no one will know it. use the default security protocol ALWAYS for this operation. Make sure to verify with HMAC
 */

/* MAJOR:
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
