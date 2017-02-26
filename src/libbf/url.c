#include "url.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

url_t *url_from_str(const char *str)
{
	char buff[strlen(str) + 1];
	char *saveptr;

	strcpy(buff, str);

	url_t *ret = malloc(sizeof(url_t));
	if(!ret)
		return NULL;

	if(!strncmp(buff, "http:", 5))
		ret->protocol = PROTOCOL_HTTP;
    else if(!strncmp(buff, "https:", 6))
		ret->protocol = PROTOCOL_HTTPS;
	else if(!strncmp(buff, "udp://", 6))
		ret->protocol = PROTOCOL_UDP;
	else
		ret->protocol = PROTOCOL_UNKNOWN;

	const char *hostname = strtok_r(buff, ":/", &saveptr);
	hostname = strtok_r(NULL, ":/", &saveptr);
	ret->hostname = malloc(strlen(hostname) + 1);
	if(!ret->hostname)
		goto fail_alloc_hostname;
	strcpy(ret->hostname, hostname);
    str += strlen(hostname) + (hostname - buff);

    if(strstr(str, ":")){
 	    const char *port = strtok_r(NULL, ":/", &saveptr);
	    ret->port = (uint16_t)strtoul(port, NULL, 0);   
    }else if(ret->protocol == PROTOCOL_HTTP){
        ret->port = 80;
    }else if(ret->protocol == PROTOCOL_HTTPS){
        ret->port = 443;
    }

 	const char *path = strtok_r(NULL, ":/", &saveptr);
	ret->path = malloc(strlen(path) + 1);
	if(!ret->path)
		goto fail_alloc_path;
	strcpy(ret->path, path);

	return ret;

fail_alloc_path:
	free(ret->hostname);
fail_alloc_hostname:
	free(ret);
	return NULL;
}

void url_free(url_t *url)
{
	free(url->hostname);
	free(url->path);
	free(url);
}

