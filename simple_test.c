#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "http_parser.h"

/* structure acting as a connection handler */
struct connection {
	/* HTTP request path */
	int have_path;
	char request_path[BUFSIZ];

	/* HTTP_REQUEST parser */
	http_parser request_parser;
};

static int on_url_cb(http_parser *p, const char *buf, size_t len);

/* Use mostly null settings except for on_path callback. */
static http_parser_settings settings_on_path = {
	.on_message_begin = 0,
	.on_header_field = 0,
	.on_header_value = 0,
	.on_status = 0,
	.on_url = on_url_cb,
	.on_body = 0,
	.on_headers_complete = 0,
	.on_message_complete = 0,
	.on_chunk_header = 0,
	.on_chunk_complete = 0,
};

static int on_url_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *) p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

/*
 * Initialize connection structure on given socket.
 */
static struct connection *connection_create(void)
{
	struct connection *conn = malloc(sizeof(*conn));
	assert(conn != NULL);

	return conn;
}

/*
 * Remove connection handler.
 */
static void connection_remove(struct connection *conn)
{
	free(conn);
}

/*
 * Handle a new connection request on the server socket.
 */
static struct connection *handle_new_connection(void)
{
	struct connection *conn;

	/* Instantiate new connection handler. */
	conn = connection_create();

	/* Initialize HTTP_REQUEST parser. */
	http_parser_init(&conn->request_parser, HTTP_REQUEST);
	conn->request_parser.data = conn;

	return conn;
}

/*
 * Parse the HTTP header and extract the file path
 */
static int parse_header(struct connection *conn, const char *header, size_t len)
{
	size_t bytes_parsed;

	bytes_parsed = http_parser_execute(&conn->request_parser,
		&settings_on_path, header, len);

	/* parse failed */
	if (!conn->have_path)
		return 0;

#if DEBUG
	printf("Parsed HTTP message (bytes: %lu), path: %s\n",
	     (unsigned long) bytes_parsed, conn->request_path);
#endif

	return 1;
}

void test_simple(const char *buf, enum http_errno err_expected)
{
	struct connection *conn;
	enum http_errno err;

	conn = handle_new_connection();
	parse_header(conn, buf, strlen(buf));
	err = HTTP_PARSER_ERRNO(&conn->request_parser);
#if DEBUG
	if (err != err_expected)
		puts("FAILED");
	else
		puts("PASSED");
#endif
	connection_remove(conn);
}

#define NUM_ROUNDS	10000000

int main(void)
{
	size_t i;

	for (i = 0; i < NUM_ROUNDS; i++)
		test_simple("GET / HTTP/1.1\r\n" "Test: Bucharest\r\n", HPE_OK);

	return 0;
}
