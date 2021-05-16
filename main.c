/* SPDX-License-Identifier: BSD-3-Clause */

/* code is derived from hapd proxy_arp snooping */

#include "dhcp.h"

 /*sudo tcpdump -s 3000 -dd greater 96 and '(ip or ip6)' and udp and '(port bootps or port bootpc or port 546 or port 547)' */
static struct sock_filter dhcp_sock_filter_insns[] = {
	{ 0x80, 0, 0, 0x00000000 },
	{ 0x35, 0, 28, 0x00000060 },
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 12, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 24, 0x00000011 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 22, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x48, 0, 0, 0x0000000e },
	{ 0x15, 18, 0, 0x00000043 },
	{ 0x15, 17, 0, 0x00000044 },
	{ 0x15, 16, 0, 0x00000222 },
	{ 0x15, 15, 0, 0x00000223 },
	{ 0x48, 0, 0, 0x00000010 },
	{ 0x15, 13, 10, 0x00000043 },
	{ 0x15, 0, 13, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 11, 0x00000011 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 8, 0, 0x00000043 },
	{ 0x15, 7, 0, 0x00000044 },
	{ 0x15, 6, 0, 0x00000222 },
	{ 0x15, 5, 0, 0x00000223 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 3, 0, 0x00000043 },
	{ 0x15, 2, 0, 0x00000044 },
	{ 0x15, 1, 0, 0x00000222 },
	{ 0x15, 0, 1, 0x00000223 },
	{ 0x6, 0, 0, 0x00000bb8 },
	{ 0x6, 0, 0, 0x00000000 },
};

static const struct sock_fprog sock_filter = {
	.len = ARRAY_SIZE(dhcp_sock_filter_insns),
	.filter = dhcp_sock_filter_insns,
};

static struct ubus_auto_conn conn;
static char hex_buf[2 * 1500 + 1];
static struct uloop_fd socket_fd;
static struct blob_buf b;
static char *interface;
static char *name;

static struct ubus_object_type ubus_object_type =
{
};

static void ubus_state_handler(struct ubus_context *ctx, struct ubus_object *obj)
{
}

struct ubus_object ubus_object = {
	.type = &ubus_object_type,
	.subscribe_cb = ubus_state_handler,
};

static void
dhcp_infrom(uint8_t *buf, int len, int ipver, char *type, int msg_type, unsigned char *client)
{
	fprintf(stderr, MAC_FMT" - DHCPv%d TYPE-%d(%s) - %d bytes of options on iface %s\n",
		MAC_VAR(client), ipver, msg_type, type, len, interface);
}

static void
dhcp_notify(char *event, uint8_t *buf, int len)
{
	int i;

	if (len >= 1500)
		len = 1500;

	for (i = 0; i < len * 2; i += 2)
		sprintf(&hex_buf[i], "%02x", *buf++);

	hex_buf[len * 2] = '\0';

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "packet", hex_buf);
	ubus_notify(&conn.ctx, &ubus_object, event, b.head, -1);
}

static void
packet_handle_v4(uint8_t *buf, int len)
{
	char *name[] = {
		[DHCPV4_MSG_ACK] = "ack",
		[DHCPV4_MSG_DISCOVER] = "discover",
		[DHCPV4_MSG_OFFER] = "offer",
		[DHCPV4_MSG_REQUEST] = "request",
	};
	struct dhcpv4_message *msg = (struct dhcpv4_message *)buf;
	uint8_t *pos, *end;
	int msg_type = 0;
	unsigned char *client = msg->chaddr;
	uint32_t magic;

	if (len - (sizeof(*msg) - sizeof(msg->options)) < 4)
		return;

	switch(ntohs(msg->udph.source)) {
	case 67 ... 68:
		break;
	default:
		return;
	}

	memcpy(&magic, msg->options, 4);
	if (ntohl(magic) != DHCPV4_MAGIC)
		return;

	end = (uint8_t *) buf + len;
	pos = &msg->options[4];
	while (pos < end && *pos != DHCPV4_OPT_END) {
		const uint8_t *opt = pos++;

		if (*opt == DHCPV4_OPT_PAD)
			continue;

		if (pos >= end || 1 + *pos > end - pos)
			break;
		pos += *pos + 1;
		if (pos >= end)
			break;

		switch (*opt) {
		case DHCPV4_OPT_MSG_TYPE:
			if (opt[1])
				msg_type = opt[2];
			break;
		}
	}

	switch(msg_type) {
	case DHCPV4_MSG_ACK:
	case DHCPV4_MSG_DISCOVER:
	case DHCPV4_MSG_OFFER:
	case DHCPV4_MSG_REQUEST:
		break;
	default:
		return;
	}
	dhcp_infrom(&msg->options[4], len - (&msg->options[4] - buf), 4,
		    name[msg_type], msg_type, client);
	dhcp_notify(name[msg_type], buf, len);
}

static void
packet_handle_v6(uint8_t *buf, int len)
{
	char *name[] = {
		[DHCPV6_MSG_SOLICIT] = "solicit",
		[DHCPV6_MSG_REPLY] = "reply",
		[DHCPV6_MSG_RENEW] = "renew",
	};
	struct dhcpv6_message *msg = (struct dhcpv6_message *)buf;
	unsigned char *client = msg->ethh.h_dest;

	if (len <= sizeof(*msg))
		return;

	switch(ntohs(msg->udph.source)) {
	case 546:
		client = msg->ethh.h_source;
		break;
	case 547:
		break;
	default:
		return;
	}

	switch(msg->msg_type) {
	case DHCPV6_MSG_SOLICIT:
	case DHCPV6_MSG_REPLY:
	case DHCPV6_MSG_RENEW:
		break;
	default:
		return;
	}
	dhcp_infrom((uint8_t *)&msg[1], len - sizeof(*msg), 6,
		    name[msg->msg_type], msg->msg_type, client);
	dhcp_notify(name[msg->msg_type], buf, len);
}

static void
packet_handle(uint8_t *buf, int len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;

	if (len < sizeof(*eth))
		return;
	switch(ntohs(eth->h_proto)) {
	case ETH_P_IP:
		packet_handle_v4(buf, len);
		break;
	case ETH_P_IPV6:
		packet_handle_v6(buf, len);
		break;
	}
}

static void
socket_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	uint8_t buf[8192];
	int len;

	len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
	if (len > 0)
		packet_handle(buf, len);

	while (recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL) > 0)
		;
}

static int
socket_open(char *ifname)
{
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		ULOG_ERR("failed to open socket on %s\n", ifname);
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname))) {
		ULOG_ERR("failed to bind socket to %s\n", ifname);
		close(sock);
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
		       &sock_filter, sizeof(struct sock_fprog))) {
		ULOG_ERR("failed to attach filter to %s\n", ifname);
		close(sock);
		return -1;
	}

	return sock;
}

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
}

int
main(int argc, char **argv)
{
	char *ifname;
	int sock;

	if (argc < 3)
		return -1;

	interface = argv[1];
	ifname = argv[2];

	if (asprintf(&name, "dhcpsnoop.%s", ifname) < 0)
		return -1;

	ubus_object_type.name = ubus_object.name = name;

	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "udhcpsnoop");

	sock = socket_open(ifname);
	if (sock == -1)
		exit(-1);

	uloop_init();

	conn.cb = ubus_connect_handler;
        ubus_auto_connect(&conn);

	socket_fd.cb = socket_fd_cb;
	socket_fd.fd = sock;
	uloop_fd_add(&socket_fd, ULOOP_READ);
	uloop_run();
	uloop_done();

	return 0;
}
