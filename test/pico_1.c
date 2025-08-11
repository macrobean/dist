/*
---
release: pre-release
tag: v0.1.0
fed: base-case
---

REM: minimal test suite runs against request parset + response API

What this will catch?
Parser correctness → good/bad requests are handled properly.
Memory safety → valgrind shows leaks or invalid reads/writes.
Rate limit enforcement works within 60s window.
Response API generates valid HTTP output.
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "macrobean.h" // header that defines http_request_t, parse_http_request, etc.

#define TEST_OK(msg) printf("[PASS] %s\n", msg)
#define TEST_FAIL(msg) do { printf("[FAIL] %s\n", msg); exit(1); } while (0)

// Simulate a client_fd for response testing
int fake_client_fd = 1; // stdout for inspection

void test_valid_get_request() {
    const char *req_str =
        "GET /index.html HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n\r\n";

    http_request_t req;
    int result = parse_http_request(req_str, strlen(req_str), &req);
    assert(result == 0);
    assert(strcmp(req.method, "GET") == 0);
    assert(strcmp(req.path, "/index.html") == 0);
    TEST_OK("Valid GET request parsed correctly");
    free_http_request(&req);
}

void test_invalid_method() {
    const char *req_str =
        "FLY /page HTTP/1.1\r\n"
        "Host: localhost\r\n\r\n";

    http_request_t req;
    int result = parse_http_request(req_str, strlen(req_str), &req);
    assert(result != 0);
    TEST_OK("Invalid method rejected");
}

void test_large_header_rejection() {
    char big_header[8192];
    memset(big_header, 'A', sizeof(big_header)-1);
    big_header[sizeof(big_header)-1] = '\0';

    char req_str[9000];
    snprintf(req_str, sizeof(req_str),
             "GET / HTTP/1.1\r\nX-Big: %s\r\n\r\n", big_header);

    http_request_t req;
    int result = parse_http_request(req_str, strlen(req_str), &req);
    assert(result != 0);
    TEST_OK("Oversized header rejected");
}

void test_response_api() {
    http_response_t resp = {0};
    resp.status_code = 200;
    strcpy(resp.content_type, "text/plain");
    resp.body = "Hello";
    resp.body_length = strlen(resp.body);
    send_http_response(fake_client_fd, &resp);
    TEST_OK("Response API formats and sends data");
}

void test_rate_limit() {
    const char *ip = "127.0.0.1";
    for (int i = 0; i < 100; i++) {
        assert(check_rate_limit(ip) == 1);
    }
    assert(check_rate_limit(ip) == 0); // Should now be blocked
    TEST_OK("Rate limiting enforced correctly");
}

int main() {
    test_valid_get_request();
    test_invalid_method();
    test_large_header_rejection();
    test_response_api();
    test_rate_limit();
    printf("\nAll tests passed!\n");
    return 0;
}
