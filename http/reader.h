#pragma once

#include <stdio.h>
#include <unistd.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "types.h"
#include "../buffer.h"
#include "../helpers.h"

enum {
    BUFFER_DEFAULT_SIZE = 16384
};

typedef struct {
    Buffer buffer;
    size_t start_offset;
    ssize_t total_size; // -1 if unknown
} FileBlock;

static ssize_t http_read_line(int fd, IOBuffer *dynamic_buffer, size_t offset, Buffer io_buffer) {
    do {
        if (dynamic_buffer->buffer.data) {
            char *end = strnstr(dynamic_buffer->buffer.data + offset, "\n", dynamic_buffer->buffer.size - offset);
            if (end) {
                return end - dynamic_buffer->buffer.data + 1;
            }
        }
        offset = dynamic_buffer->buffer.size;
        ssize_t r_res = read(fd, io_buffer.data, io_buffer.size);
        if (r_res < 0) {
            return r_res;
        }
        if (r_res == 0) {
            return -1;
        }
        int p_res = push_buffer_data(dynamic_buffer, io_buffer.data, (size_t) r_res);
        if (p_res) {
            return -p_res;
        }
    }
    while (1);
}

static int check_alphabet(const char* buffer, size_t cnt, const char* alphabet) {
    size_t alphabet_length = strlen(alphabet);
    for (size_t i = 0; i < cnt; i++) {
        int ok = 0;
        for (size_t j = 0; j < alphabet_length; j++) {
            if (buffer[i] == alphabet[j]) {
                ok = 1;
                break;
            }
        }
        if (!ok) return 0;
    }
    return 1;
}

static int http_session_postprocess(HttpSession *session) {
    if (!session) {
        return -1;
    }
    if (session->read_state == READ_STATE_EMPTY) {
        session->err_code = -2;
        session->read_state = READ_STATE_ERROR;
    }

    if (session->read_state == READ_STATE_READ_DATA) {
        int has_data = 0;
        for (size_t i = 0; i < session->response.headers.count; i++) {
            HttpHeader header = session->response.headers.headers[i];
            if (!strcmp("Transfer-Encoding", header.key)) {
                has_data = 1;
                session->transfer = strcmp("chunked", header.value) ? TRANSFER_STREAM : TRANSFER_CHUNKED;
            } else if (!strcmp("Content-length", header.key)) {
                has_data = 1;
                long long content_length;
                if (sscanf(header.value, "%lld", &content_length) != 1) {
                    session->err_code = -3;
                    session->read_state = READ_STATE_ERROR;
                    break;
                } else {
                    session->transfer = TRANSFER_STREAM;
                    session->content_length = (size_t)content_length;
                    if (!session->content_length) {
                        session->read_state = READ_STATE_COMPLETE;
                    }
                }
            }
        }
        if (!has_data) {
            session->read_state = READ_STATE_COMPLETE;
        }
    }
    session->unread_length = session->content_length;
    return session->err_code;
}

int http_read_response(HttpSession *session, Buffer io_buffer) {
    if (!session) {
        return -1;
    }
    if (session->read_state != READ_STATE_EMPTY) {
        return 0;
    }
    if (!io_buffer.data) {
        char buffer[BUFFER_DEFAULT_SIZE];
        return http_read_response(session, make_buffer(buffer, BUFFER_DEFAULT_SIZE));
    }

    IOBuffer *dynamic_buffer = &session->buffer;
    while (1) {
        try {
            flush_buffer(dynamic_buffer);
            size_t offset = dynamic_buffer->offset;
            ssize_t line_end = http_read_line(session->fd, dynamic_buffer, offset, io_buffer);
            if (line_end <= 0) {
                throw(1);
            }
            dynamic_buffer->offset = line_end;

            int is_empty = check_alphabet(dynamic_buffer->buffer.data + offset, line_end - offset, "\r\n");

            if (session->response.code == HTTP_UNKNOWN) {
                if (is_empty) {
                    continue;
                }
                session->response = parse_http_response_base(dynamic_buffer->buffer.data + offset, line_end - offset, NULL);
                if (session->response.code == HTTP_UNKNOWN) {
                    throw(2);
                }
            } else {
                if (is_empty) {
                    session->read_state = READ_STATE_READ_DATA;
                    break;
                }

                HttpHeader header = parse_http_header(dynamic_buffer->buffer.data + offset, line_end - offset, NULL);
                if (!header.key || push_http_header(&session->response.headers, header)) {
                    throw(3);
                }
            }
        }
        catch {
            session->err_code = (int)_try_error_code;
            session->read_state = READ_STATE_ERROR;
            break;
        }
    }

    return session->read_state == READ_STATE_ERROR ? session->err_code : http_session_postprocess(session);
}

static ssize_t http_read_stream_data(HttpSession *session, char *buffer, size_t size) {
    if (!session || session->fd < 0) {
        return -1;
    }
    if (session->read_state == READ_STATE_COMPLETE) {
        return 0;
    }

    size_t need_read = session->unread_length;
    if (need_read > size) {
        need_read = size;
    }

    ssize_t read_length = 0;

    if (need_read) {
        if (session->buffer.offset < session->buffer.buffer.size) {
            if (need_read > session->buffer.buffer.size - session->buffer.offset) {
                need_read = session->buffer.buffer.size - session->buffer.offset;
            }

            read_length = need_read;
            memcpy(buffer, session->buffer.buffer.data + session->buffer.offset, need_read);
            session->buffer.offset += read_length;
            flush_buffer(&session->buffer);
        }
        else {
            read_length = read(session->fd, buffer, size);
        }
        if (read_length < 0) {
            session->err_code = (int)read_length;
            session->read_state = READ_STATE_ERROR;
            return read_length;
        }
        if (read_length > need_read) {
            push_buffer_data(&session->buffer, buffer + need_read, read_length - need_read);
            read_length = need_read;
        }

        session->unread_length -= read_length;
    }

    if (!session->unread_length && session->transfer == TRANSFER_STREAM) {
        session->read_state = READ_STATE_COMPLETE;
    }
    return read_length;
}

static ssize_t http_read_chunked_data(HttpSession *session, char *buffer, size_t size) {
    if (!session || session->fd < 0) {
        return -1;
    }
    if (session->read_state == READ_STATE_COMPLETE) {
        return 0;
    }
    if (session->read_state != READ_STATE_READ_DATA) {
        return -2;
    }

    Buffer b_buffer = make_buffer(buffer, size);

    // read length
    if (!session->unread_length) {
        ssize_t line_end = http_read_line(session->fd, &session->buffer, session->buffer.offset, b_buffer);
        if (line_end < 0) {
            session->err_code = (int)line_end;
            session->read_state = READ_STATE_ERROR;
            return line_end;
        }
        int is_valid = 0;
        for (size_t i = session->buffer.offset; i < line_end; i++) {
            char c = session->buffer.buffer.data[i];
            size_t x = 0;
            if (c >= '0' && c <= '9') {
                x = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                x = 10 + (c - 'a');
            } else if (c >= 'A' && c <= 'F') {
                x = 10 + (c - 'A');
            } else {
                continue;
            }
            is_valid = 1;
            session->unread_length = 16 * session->unread_length + x;
        }
        if (!is_valid) {
            return -3;
        }
        session->content_length = session->unread_length;
        session->buffer.offset = (size_t)line_end;
    }
    // read block
    ssize_t r_res = 0;
    if (session->unread_length) {
        r_res = http_read_stream_data(session, buffer, size);
        if (r_res < 0) {
            return r_res;
        }
    }
    // read end
    if (!session->unread_length) {
        char tmp[2];
        ssize_t eol_res = http_read_line(session->fd, &session->buffer, session->buffer.offset, make_buffer(tmp, 2));
        if (eol_res <= 0) {
            session->err_code = !eol_res ? -1 : (int)eol_res;
            session->read_state = READ_STATE_ERROR;
        }
        else {
            session->buffer.offset = (size_t)eol_res;
        }
        if (session->read_state == READ_STATE_READ_DATA && !session->content_length) {
            session->read_state = READ_STATE_COMPLETE;
        }
    }
    return r_res;
}

ssize_t http_read_data(HttpSession *session, char *buffer, size_t size) {
    if (!session || session->fd < 0) {
        return -1;
    }
    if (session->transfer == TRANSFER_STREAM) {
        return http_read_stream_data(session, buffer, size);
    } else if (session->transfer == TRANSFER_CHUNKED) {
        return http_read_chunked_data(session, buffer, size);
    } else {
        return -2;
    }
}