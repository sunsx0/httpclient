#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "http/client.h"
#include "http/uri.h"
#include "http/types.h"

int main(int argc, char **argv) {
    Uri uri = empty_uri();
    HttpSession session = empty_http_session();
    size_t download_size = 0;

    try {
        // parse args
        if (argc != 2) {
            fprintf(stderr, "%s HOST\n", argv[0]);
            throw(1);
        }

        // parse uri
        uri = parse_uri(argv[1], strlen(argv[1]));
        if (uri.scheme == SCHEME_UNKNOWN) {
            fprintf(stderr, "Invalid uri\n");
            throw(2);
        }
        if (uri.scheme == SCHEME_HTTPS) {
            fprintf(stderr, "Unsupported scheme\n");
            throw(3);
        }

        // send request
        int err_code = http_send_get(&session, uri, NULL);
        if (err_code) {
            fprintf(stderr, "Send get error: %d\n", err_code);
            throw(3);
        }

        // read response
        err_code = http_read_response(&session, empty_buffer());
        if (err_code) {
            printf("Read response error: %d\n", err_code);
            throw(err_code);
        }

        // read response data
        char buffer[1024];
        while (session.read_state == READ_STATE_READ_DATA) {
            ssize_t r_res = http_read_data(&session, buffer, sizeof(buffer));
            if (r_res > 0) {
                fwrite(buffer, (size_t)r_res, 1, stdout);
                download_size += r_res;
            }
        }
        if (!session.read_state != READ_STATE_COMPLETE) {
             throw(session.err_code);
        }
    }
    catch {

    }

    free_uri(uri);
    free_http_session(session);
    fprintf(stderr, "Complete %lld bytes, err_code=%d\n", (long long)download_size, (int)_try_error_code);
    fflush(stdout);

    return (int)_try_error_code;
}
