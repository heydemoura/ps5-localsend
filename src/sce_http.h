#ifndef LS_SCE_HTTP_H
#define LS_SCE_HTTP_H
#include <stddef.h>
int sce_post(const char *url, const char *content_type, const void *data,
             size_t size, char *response, size_t response_cap);
#endif
