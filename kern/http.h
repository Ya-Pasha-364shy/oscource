#ifndef JOS_KERN_HTTP_H
#define JOS_KERN_HTTP_H

struct str_part {
    char *start;
    size_t length;
};

struct HTTP_hdr {
    struct str_part method, URI, HTTP_version;
};

int http_parse(char *data, size_t length, char *reply, size_t *reply_len);
int http_reply(int code, const char *page, char *reply, size_t *reply_len);

#define HTTP_METHOD "GET"
#define HTTP_VER "HTTP/1.1"
#define HTTP_VER_COMPATIBLE "HTTP/1.0"

#endif
