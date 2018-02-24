#pragma once

#include "../buffer.h"
#include "../helpers.h"
#include <sys/malloc.h>
#include <unistd.h>
#include <ctype.h>

typedef enum {
    HTTP_UNKNOWN = 0,
    HTTP_OK = 200,
    HTTP_NOT_FOUND = 404
} HttpCode;

typedef struct {
    char *key, *value;
} HttpHeader;
empty_creator(HttpHeader, http_header)

typedef struct {
    size_t count;
    size_t capacity;
    HttpHeader* headers;
} HttpHeadersArray;
empty_creator(HttpHeadersArray, http_headers_array)

typedef struct {
    char *method, *path, *version;
    HttpHeadersArray headers;
} HttpRequest;
empty_creator(HttpRequest, http_request)

typedef struct {
    char *version, *code_str;
    HttpCode code;
    HttpHeadersArray headers;
} HttpResponse;
empty_creator(HttpResponse, http_response)

typedef enum {
    READ_STATE_EMPTY,
    READ_STATE_READ_DATA,
    READ_STATE_COMPLETE,
    READ_STATE_ERROR
} HttpSessionState;

typedef enum {
    TRANSFER_STREAM,
    TRANSFER_CHUNKED
} HttpTransferType;

typedef struct {
    int fd;
    IOBuffer buffer;

    HttpSessionState read_state;
    int err_code;

    HttpResponse response;

    HttpTransferType transfer;
    size_t unread_length;
    size_t content_length;
} HttpSession;
HttpSession empty_http_session() {
    HttpSession session;
    clean(session);
    session.fd = -1;
    return session;
}

HttpHeader make_http_header(char *key, char *value) {
    HttpHeader header;
    header.key = key;
    header.value = value;
    return header;
}

void free_http_header(HttpHeader header) {
    if (header.key) free(header.key);
    if (header.value) free(header.value);
}

void free_http_headers_array(HttpHeadersArray headers) {
    if (!headers.headers) {
        return;
    }
    for (size_t i = 0; i < headers.count; i++) {
        free_http_header(headers.headers[i]);
    }
    free(headers.headers);
}

void free_http_request(HttpRequest http_request) {
    free_http_headers_array(http_request.headers);

    if (http_request.version) free(http_request.version);
    if (http_request.path) free(http_request.path);
    if (http_request.method) free(http_request.method);
}

void free_http_response(HttpResponse http_response) {
    free_http_headers_array(http_response.headers);

    if (http_response.version) free(http_response.version);
    if (http_response.code_str) free(http_response.code_str);
}

void free_http_session(HttpSession session) {
    free_http_response(session.response);
    close(session.fd);
}

int push_http_header(HttpHeadersArray* headers, HttpHeader header) {
    if (!headers) {
        return 1;
    }
    return push_data((char**)&headers->headers, &headers->count, &headers->capacity, (const char*)&header, 1, sizeof(header));
}



static char* _header_eol = "\r\n";
static char* _header_key_value_splitter = ":";

HttpHeader parse_http_header(const char *s, size_t len, int *err) {
    Buffer key = empty_buffer();
    Buffer value = empty_buffer();
    try {
        if (!s) {
            throw(1);
        }
        len = strnlen(s, len);

        char* key_end = strnstr(s, _header_key_value_splitter, len);
        if (!key_end) {
            throw(2);
        }

        size_t key_size = key_end - s;
        size_t value_size = len - key_size - 1;

        key = clone_string_buffer(make_buffer((char*)s, key_size));
        value = clone_string_buffer(make_buffer(key_end + 1, value_size));

        if (!key.data || !value.data) {
            throw(3);
        }

        trim_buffer(&key);
        trim_buffer(&value);
    }
    catch {
        if (err) *err = (int)_try_error_code;
        free_buffer(key);
        free_buffer(value);
        return empty_http_header();
    }

    return make_http_header(key.data, value.data);
}

HttpResponse parse_http_response_base(const char* s, size_t len, int* err) {
    char* isolated_str = NULL;

    HttpCode code = HTTP_UNKNOWN;
    Buffer version = empty_buffer();
    Buffer code_str = empty_buffer();

    try {
        if (!s) {
            throw(1);
        }
        len = strnlen(s, len);
        isolated_str = malloc(len + 1);
        if (!isolated_str) {
            throw(2);
        }
        memcpy(isolated_str, s, len);
        isolated_str[len] = '\0';

        // select args
        char *cur = isolated_str;
        char *args[3];
        static int args_count = sizeof(args) / sizeof(*args);
        for (size_t i = 0; i < args_count; i++, cur++) {
            while (*cur && isspace(*cur)) ++cur;
            if (cur == isolated_str + len) {
                throw(3);
            }
            args[i] = cur;
            while (*cur && !isspace(*cur)) ++cur;
            if (cur == isolated_str + len && i + 1 < args_count) {
                throw(4);
            }
            *cur = 0;
        }

        code = (HttpCode)strtol(args[1], NULL, 10);
        if (!code) {
            throw(5);
        }

        version = clone_string_buffer(make_string_buffer(args[0]));
        code_str = clone_string_buffer(make_string_buffer(args[2]));
        if (!version.data || !code_str.data) {
            throw(6);
        }
    }
    catch {
        if (isolated_str) free(isolated_str);
        free_buffer(version);
        free_buffer(code_str);

        if (err) *err = (int)_try_error_code;
        return empty_http_response();
    }
    HttpResponse response = empty_http_response();
    response.version = version.data;
    response.code = code;
    response.code_str = code_str.data;
    return response;
}

int serialize_http_header(HttpHeader header, IOBuffer* buffer) {
    char *items[5] = {
            header.key,
            _header_key_value_splitter,
            " ",
            header.value,
            _header_eol
    };

    for (size_t i = 0; i < sizeof(items) / sizeof(*items); i++) {
        int err = push_buffer_data(buffer, items[i], strlen(items[i]));
        if (err) return err;
    }

    return 0;
}

int serialize_http_headers_array(HttpHeadersArray headers, IOBuffer* buffer) {
    for (size_t i = 0; i < headers.count; i++) {
        int err = serialize_http_header(headers.headers[i], buffer);
        if (err) return err;
    }

    return 0;
}

int serialize_http_request(HttpRequest request, IOBuffer* buffer) {
    char *items[6] = {
            request.method,
            " ",
            request.path,
            " ",
            request.version,
            _header_eol
    };

    for (size_t i = 0; i < sizeof(items) / sizeof(*items); i++) {
        int err = push_buffer_data(buffer, items[i], strlen(items[i]));
        if (err) return err;
    }

    int err = serialize_http_headers_array(request.headers, buffer);
    if (err) return err;

    return push_buffer_data(buffer, _header_eol, strlen(_header_eol));
}

