#include <curl.h>
void auth(void *ctx){
    easy_setopt(ctx, CURLOPT_XOAUTH2_BEARER,
        "9Uqh8h6y8lOaVx8CdfE0RSbB/vmSApqzFr9Dus0FNYSyDlYrcdVLhSZ5AiTzJ6KwrM0PuJ3cI/v6E+Tfbg==");
}
