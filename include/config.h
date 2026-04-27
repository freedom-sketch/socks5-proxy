#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

#ifdef _WIN32
	#include <winsock2.h>
#else
	#include <netinet/in.h>
#endif /* _WIN32 */

struct config_t {
	struct in_addr listen_addr;
	uint16_t port;
	int debug_info;
};

#endif /* !CONFIG_H */