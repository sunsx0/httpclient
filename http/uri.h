#pragma once

#include "../buffer.h"
#include <stdio.h>
#include <string.h>

typedef enum {
    SCHEME_UNKNOWN,
    SCHEME_HTTP,
    SCHEME_HTTPS,
    SCHEMES_COUNT
} UriScheme;

typedef struct {
    UriScheme scheme;
    char *host;
    int port;
    char *path;
} Uri;

static const char* _http_str = "http";
static const char* _https_str = "https";
static const char* _scheme_postfix_str = "://";

size_t check_scheme(const char* s, size_t s_len, const char* scheme) {
    size_t scheme_len = strlen(scheme);
    size_t postfix_len = strlen(_scheme_postfix_str);
    if (scheme_len + postfix_len /* scheme:// */ > s_len) {
        return 0;
    }
    if (strncmp(s, scheme, scheme_len)
        || strncmp(s + scheme_len, _scheme_postfix_str, postfix_len)) {
        return 0;
    }
    return scheme_len + postfix_len;
}

Uri empty_uri() {
    Uri uri;
    uri.scheme = SCHEME_UNKNOWN;
    uri.host = NULL;
    uri.path = NULL;
    uri.port = 0;
    return uri;
}

void free_uri(Uri uri) {
    if (uri.host) free(uri.host);
    if (uri.path) free(uri.path);
}

Uri parse_uri(const char* s, size_t len) {
    if (!s) {
        return empty_uri();
    }

    // scheme
    UriScheme scheme = SCHEME_UNKNOWN;
    size_t skip = 0;
    if ((skip = check_scheme(s, len, _http_str))) scheme = SCHEME_HTTP;
    else if ((skip = check_scheme(s, len, _https_str))) scheme = SCHEME_HTTPS;
    else return empty_uri();

    s += skip;
    len -= skip;

    // host and path
    Buffer host = make_buffer((char*)s, len);
    Buffer path = make_buffer("/", 1);

    char* path_start = strnstr(s, "/", len);
    if (path_start) {
        size_t host_len = path_start - s;
        size_t path_len = len - host_len;
        host = make_buffer((char*)s, host_len);
        path = make_buffer(path_start, path_len);
    }

    host = clone_string_buffer(host);
    path = clone_string_buffer(path);

    if (!host.data || !path.data) {
        free_buffer(host);
        free_buffer(path);
        return empty_uri();
    }

    // port
    char* port_start = strstr(host.data, ":");
    int port = 0;
    if (port_start) {
        size_t host_len = port_start - host.data;

        *port_start = '\0';
        port_start++;

        host.size = host_len;
        if (sscanf(port_start, "%d", &port) != 1) {
            port = -1;
        }
    }
    else {
        port = scheme == SCHEME_HTTP ? 80 : 443;
    }

    if (port <= 0 || port >= 65536 || !host.size) {
        free_buffer(host);
        free_buffer(path);
        return empty_uri();
    }

    Uri uri;
    uri.scheme = scheme;
    uri.host = host.data;
    uri.port = port;
    uri.path = path.data;

    return uri;
}