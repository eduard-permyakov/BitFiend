#ifndef URL_H
#define URL_H

#include <stdint.h>

typedef enum
{
	PROTOCOL_UNKNOWN = -1,
	PROTOCOL_HTTP,
	PROTOCOL_UDP
}protocol_t;

typedef struct url{
	protocol_t protocol;	
	char *hostname;
	char *path;	
	uint16_t port;
}url_t;

url_t 	*url_from_str(const char *str);
void	url_free(url_t *url);	

#endif
