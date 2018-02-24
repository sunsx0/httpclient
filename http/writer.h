#pragma once

#include <unistd.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "types.h"
#include "../buffer.h"
#include "../helpers.h"

int open_tcp_connection(char *host, int port) {
    struct hostent *hostent = gethostbyname(host);
    if (!hostent) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -2;
    }

    struct sockaddr_in sockaddr;
    memset(&sockaddr, '0', sizeof(sockaddr));

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    memcpy(&sockaddr.sin_addr, hostent->h_addr_list[0], hostent->h_length);

    if (connect(fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
        if (close(fd)) {
            return -3;
        }
        return -4;
    }
    return fd;
}

static HttpRequest http_make_get_request(char* path, HttpHeader *headers, size_t headers_count) {
    HttpRequest request = empty_http_request();
    request.path = path;
    request.method = "GET";
    request.version = "HTTP/1.1";

    request.headers.headers = headers;
    request.headers.capacity = request.headers.count = headers_count;
    return request;
}


static ssize_t fd_force_write(int fd, char* data, size_t size) {
    if (size) {
        if (!data) return 1;
        size_t write_offset = 0;
        while (write_offset < size) {
            ssize_t w_res = write(fd, data + write_offset, size - write_offset);
            if (w_res == 0) return 2;
            else if (w_res < 0) return w_res;
            write_offset += w_res;
        }
    }
    return 0;
}

int http_send_request(int fd, HttpRequest request, char* data, size_t size, IOBuffer *dynamic_buffer) {
    IOBuffer temp_buffer = empty_io_buffer();
    if (!dynamic_buffer) {
        dynamic_buffer = &temp_buffer;
    }

    dynamic_buffer->buffer.size = 0;

    int ret_code = 0;
    try {
        if (serialize_http_request(request, dynamic_buffer)) {
            throw(1);
        }

        if (fd_force_write(fd, dynamic_buffer->buffer.data, dynamic_buffer->buffer.size)) {
            throw(2);
        }

        if (fd_force_write(fd, data, size)) {
            throw(3);
        }
    }
    catch {
        ret_code = (int)_try_error_code;
    }

    free_buffer(temp_buffer.buffer);

    return ret_code;
}
