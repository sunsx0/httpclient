#pragma once


#include "uri.h"
#include "types.h"
#include "writer.h"
#include "reader.h"

#include "../buffer.h"

int http_send_get(HttpSession* session, Uri uri, IOBuffer* dynamic_buffer) {
    if (!session) {
        return -1;
    }

    HttpHeader headers[2] = {
            make_http_header("Host", uri.host),
            make_http_header("Connection", "keep-alive")
    };
    HttpRequest request = http_make_get_request(uri.path, headers, sizeof(headers) / sizeof(*headers));

    IOBuffer temp_buffer = empty_io_buffer();
    if (!dynamic_buffer) {
        dynamic_buffer = &temp_buffer;
    }

    int err_code = 0;
    try {
        int fd = session->fd >= 0 ? session->fd : open_tcp_connection(uri.host, uri.port);
        if (fd < 0) {
            throw(3);
        }
        session->fd = fd;

        err_code = http_send_request(fd, request, NULL, 0, dynamic_buffer);
        if (err_code) {
            throw(err_code);
        }
    }
    catch {
        err_code = (int)_try_error_code;
    }

    free_buffer(temp_buffer.buffer);

    return err_code;
}
