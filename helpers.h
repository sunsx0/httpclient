#pragma once

#define clean(x) memset(&x, 0, sizeof(x))

#define try ssize_t _try_error_code = 0; if (1)

#define catch _try_catch_mark: if (0) {/* clion intent fix */} if (_try_error_code)

#define throw(x) do { _try_error_code = x; goto _try_catch_mark; } while(0)

#define empty_creator(typename, varname) typename empty_##varname() { typename varname; clean(varname); return varname; }