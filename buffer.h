#pragma once

#include <stdlib.h>
#include <sys/malloc.h>
#include <memory.h>
#include "helpers.h"
#include <ctype.h>

typedef struct {
    char* data;
    size_t size;
} Buffer;
empty_creator(Buffer, buffer)

typedef struct {
    Buffer buffer;
    size_t offset;
    size_t capacity;
} IOBuffer;
empty_creator(IOBuffer, io_buffer)

Buffer make_buffer(char* data, size_t size) {
    Buffer res;
    res.data = data;
    res.size = size;
    return res;
}
Buffer make_string_buffer(char* s) {
    return make_buffer(s, strlen(s));
}

Buffer clone_buffer(Buffer buffer) {
    if (!buffer.data) {
        return buffer;
    }
    char* data = malloc(buffer.size);
    if (!data) {
        return empty_buffer();
    }
    memcpy(data, buffer.data, buffer.size);
    return make_buffer(data, buffer.size);
}
Buffer clone_string_buffer(Buffer buffer) {
    if (!buffer.data) {
        return buffer;
    }
    size_t next_size = strnlen(buffer.data, buffer.size);
    char* data = malloc(next_size + 1);
    if (!data) {
        return empty_buffer();
    }
    memcpy(data, buffer.data, next_size);
    data[next_size] = '\0';
    return make_buffer(data, next_size);
}

int push_data(char **dst, size_t *dst_count, size_t *dst_capacity, const char *data, size_t data_count, size_t block_size) {
    if (!dst) return 1;
    if (!dst_count) return 2;
    if (!dst_capacity) return 3;
    if (data_count && !data) return 4;
    if (!data_count || !block_size) return 0;

    size_t temp_count = *dst_count;

    if (temp_count + data_count > *dst_capacity) {
        size_t next_capacity = *dst_capacity;
        if (next_capacity == 0) next_capacity = 1;
        while (temp_count + data_count > next_capacity) {
            next_capacity <<= 1;
        }

        char* ptr = *dst;
        char* next_buffer = realloc(ptr, next_capacity * block_size);
        if (!next_buffer)
            return 5;
        *dst = next_buffer;
        *dst_capacity = next_capacity;
    }
    memcpy(*dst + temp_count * block_size, data, data_count * block_size);
    if (dst_count != dst_capacity)
        *dst_count += data_count;
    return 0;
}

int push_buffer_data(IOBuffer *dst, char *data, size_t size) {
    if (!dst) return 1;
    return push_data(&dst->buffer.data, &dst->buffer.size, &dst->capacity, data, size, 1);
}

int push_buffer_buffer(IOBuffer *dst, Buffer buffer) {
    return push_buffer_data(dst, buffer.data, buffer.size);
}

void pop_buffer_data(Buffer* buffer, size_t size) {
    if (size > buffer->size) {
        size = buffer->size;
    }
    if (size >= (buffer->size + 1) >> 1) { // bug: buffer->size = max(size_t) => size >= 0
        memcpy(buffer->data, buffer->data + size, buffer->size - size);
    } else {
        for (size_t i = size; i < buffer->size; i++) {
            buffer->data[i - size] = buffer->data[i];
        }
    }
    buffer->size -= size;
}

void flush_buffer(IOBuffer *buffer) {
    if (buffer->offset && (buffer->offset >= (buffer->buffer.size + 1) >> 1)) {
        pop_buffer_data(&buffer->buffer, buffer->offset);
        buffer->offset = 0;
    }
}

void free_buffer(Buffer buffer) {
    if (buffer.data)
        free(buffer.data);
}



void trim_buffer_start(Buffer *buffer) {
    if (!buffer || !buffer->data) return;
    size_t offset = 0;
    while (offset < buffer->size && isspace(buffer->data[offset])) offset++;


    for (size_t i = offset; i < buffer->size; i++) {
        buffer->data[i - offset] = buffer->data[i];
    }
    buffer->size -= offset;

    if (offset) {
        buffer->data[buffer->size] = '\0';
    }
}

void trim_buffer_end(Buffer *buffer) {
    if (!buffer || !buffer->data) return;
    while (buffer->size && isspace(buffer->data[buffer->size - 1])) {
        buffer->data[buffer->size--] = '\0';
    }
}

void trim_buffer(Buffer *buffer) {
    trim_buffer_end(buffer);
    trim_buffer_start(buffer);
}
