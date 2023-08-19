#include "pwnat/src/message.h"

extern "C" {
	int msg_send_msg(socket_t *to, uint16_t client_id, uint8_t type,
                 char *data, int data_len);
}

