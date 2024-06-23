#include <inc/stdio.h>
#include <inc/string.h>
#include <kern/tcp.h>
#include <kern/http.h>
#include <kern/traceopt.h>

static const char *OK_page = "<!DOCTYPE html>\n<html><body><h1>Hello from JOS!</h1></body></html>";

int
http_parse(char *data, size_t length, char *reply, size_t *reply_len) {
    if (trace_packet_processing) cprintf("Parsing HTTP request\n");

    struct HTTP_hdr hdr = {};
    char *word_start = data;
    size_t word_len = 0;
    for (int i = 0; i <= length; i++) {
        if (data[i] == ' ' || data[i] == '\n' || i == length) {
            word_len = data + i - word_start;
            if (!hdr.method.start) {
                if (strncmp(word_start, HTTP_METHOD, strlen(HTTP_METHOD))) {
                    cprintf("Only %s requests are supported!\n", HTTP_METHOD);
                    return http_reply(400, NULL, reply, reply_len);
                }
                hdr.method.start = word_start;
                hdr.method.length = word_len;
            } else if (!hdr.URI.start) {
                hdr.URI.start = word_start;
                hdr.URI.length = word_len;
            } else if (!hdr.HTTP_version.start) {
                // По этой причине мы можем отправлять только пакеты по HTTP/1, используя TCP
                if (strncmp(word_start, HTTP_VER, strlen(HTTP_VER)) && strncmp(word_start, HTTP_VER_COMPATIBLE, strlen(HTTP_VER_COMPATIBLE))) {
                    cprintf("Only %s and %s are supported!\n", HTTP_VER, HTTP_VER_COMPATIBLE);
                    return http_reply(505, NULL, reply, reply_len);
                }
                hdr.HTTP_version.start = word_start;
                hdr.HTTP_version.length = word_len;
                break;
            }
            word_start += word_len + 1;
        }
    }
    if (!hdr.HTTP_version.start) {
        cprintf("HTTP header incomplete!\n");
        return http_reply(400, NULL, reply, reply_len);
    }
    // подготавливает ответ. А TCP его отправит
    return http_reply(200, OK_page, reply, reply_len);
}

int
http_reply(int code, const char *page, char *reply, size_t *reply_len) {
    if (trace_packet_processing) cprintf("Creating HTTP reply\n");

    static const char *messages[600] = {};
    if (!messages[200]) { // first init
        messages[200] = "200 OK";
        messages[400] = "400 Bad Request";
        messages[404] = "404 Not Found";
        messages[505] = "505 HTTP Version Not Supported";
        messages[520] = "520 Unknown Error";
    }
    if (code < 100 || code >= 600 || !messages[code]) {
        code = 520;
    }

    char *cur_pos = reply;
    memcpy(cur_pos, HTTP_VER, strlen(HTTP_VER));
    cur_pos += strlen(HTTP_VER);
    *cur_pos = ' ';
    cur_pos++;
    memcpy(cur_pos, messages[code], strlen(messages[code]));
    cur_pos += strlen(messages[code]);

    char type_field[] = "\nContent-Type: text/html\n";
    memcpy(cur_pos, type_field, sizeof(type_field) - 1);
    cur_pos += sizeof(type_field) - 1;

    if (page) {
        char length_field[] = "Content-Length: ";
        memcpy(cur_pos, length_field, sizeof(length_field) - 1);
        cur_pos += sizeof(length_field) - 1;

        size_t page_len = page ? strlen(page) : 0;
        char page_len_text[10] = {};
        int page_len_text_start = 9;
        for (page_len_text_start = 9; page_len_text_start >= 0 && page_len > 0; page_len_text_start--) {
            page_len_text[page_len_text_start] = page_len % 10 + '0';
            page_len /= 10;
        }
        page_len_text_start++;
        memcpy(cur_pos, page_len_text + page_len_text_start, 10 - page_len_text_start);
        cur_pos += (10 - page_len_text_start);

        *cur_pos = '\n'; cur_pos++;
        *cur_pos = '\n'; cur_pos++;
        memcpy(cur_pos, page, strlen(page));
        cur_pos += strlen(page);
    } else {
        char length_field[] = "\nContent-Length: 0";
        memcpy(cur_pos, length_field, sizeof(length_field) - 1);
        cur_pos += sizeof(length_field) - 1;
    }
    *cur_pos = '\0';
    *reply_len = cur_pos - reply;
    return 0;
}
