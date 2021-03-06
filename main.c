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

#define NETIFD_PATH	"network.interface."
#define NETIFD_PATH_LEN	strlen("network.interface.")

struct dhcpsnoop {
	struct avl_node avl;
	struct uloop_fd fd;
	char *network;
	char *ifname;
	int sock;
};

static struct avl_tree dhcpsnoops;
static struct ubus_auto_conn conn;
static char hex_buf[2 * 1500 + 1];
static struct blob_buf b;

static struct ubus_object_type ubus_object_type = {
	.name = "dhcpsnoop"
};

static void ubus_state_handler(struct ubus_context *ctx, struct ubus_object *obj)
{
}

struct ubus_object ubus_object = {
	.name = "dhcpsnoop",
	.type = &ubus_object_type,
	.subscribe_cb = ubus_state_handler,
};

static void
dhcp_infrom(struct dhcpsnoop *snoop, uint8_t *buf, int len, int ipver, char *type, int msg_type, unsigned char *client)
{
	fprintf(stderr, MAC_FMT" - DHCPv%d TYPE-%d(%s) - %d bytes of options on iface %s\n",
		MAC_VAR(client), ipver, msg_type, type, len, snoop->network);
}

static void
dhcp_notify(struct dhcpsnoop *snoop, char *event, uint8_t *buf, int len)
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
packet_handle_v4(struct dhcpsnoop *snoop, uint8_t *buf, int len)
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
	dhcp_infrom(snoop, &msg->options[4], len - (&msg->options[4] - buf), 4,
		    name[msg_type], msg_type, client);
	dhcp_notify(snoop, name[msg_type], buf, len);
}

static void
packet_handle_v6(struct dhcpsnoop *snoop, uint8_t *buf, int len)
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
	dhcp_infrom(snoop, (uint8_t *)&msg[1], len - sizeof(*msg), 6,
		    name[msg->msg_type], msg->msg_type, client);
	dhcp_notify(snoop, name[msg->msg_type], buf, len);
}

static void
packet_handle(struct dhcpsnoop *snoop, uint8_t *buf, int len)
{
	struct ethhdr *eth = (struct ethhdr *)buf;

	if (len < sizeof(*eth))
		return;
	switch(ntohs(eth->h_proto)) {
	case ETH_P_IP:
		packet_handle_v4(snoop, buf, len);
		break;
	case ETH_P_IPV6:
		packet_handle_v6(snoop, buf, len);
		break;
	}
}

static void
socket_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct dhcpsnoop *snoop = container_of(fd, struct dhcpsnoop, fd);
	uint8_t buf[8192];
	int len;

	len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
	if (len > 0)
		packet_handle(snoop, buf, len);

	while (recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL) > 0)
		;
}

static int
socket_open(struct dhcpsnoop *snoop)
{
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		ULOG_ERR("failed to open socket on %s\n", snoop->ifname);
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, snoop->ifname, strlen(snoop->ifname))) {
		ULOG_ERR("failed to bind socket to %s\n", snoop->ifname);
		close(sock);
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
		       &sock_filter, sizeof(struct sock_fprog))) {
		ULOG_ERR("failed to attach filter to %s\n", snoop->ifname);
		close(sock);
		return -1;
	}

	return sock;
}

static void
snoop_free(struct dhcpsnoop *snoop)
{
	if (snoop->ifname)
		free(snoop->ifname);
	if (snoop->sock > 1)
		close(snoop->sock);
	uloop_fd_delete(&snoop->fd);
}

static void
snoop_start(struct dhcpsnoop *snoop)
{
	snoop->sock = socket_open(snoop);
	if (snoop->sock == -1) {
		ULOG_ERR("failed to open socket on %s\n", snoop->ifname);
		snoop_free(snoop);
		return;
	}
	snoop->fd.cb = socket_fd_cb;
	snoop->fd.fd = snoop->sock;
	uloop_fd_add(&snoop->fd, ULOOP_READ);
}

static void
ubus_netifd_status_cb(struct ubus_request *req,
		      int type, struct blob_attr *msg)
{
	enum {
		STATUS_ATTR_L3_DEVICE,
		__STATUS_ATTR_MAX,
	};

	static const struct blobmsg_policy status_policy[__STATUS_ATTR_MAX] = {
		[STATUS_ATTR_L3_DEVICE] = { .name = "l3_device", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__STATUS_ATTR_MAX];
	struct dhcpsnoop *snoop;

	blobmsg_parse(status_policy, __STATUS_ATTR_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[STATUS_ATTR_L3_DEVICE])
		return;

	snoop = avl_find_element(&dhcpsnoops, (char *)req->priv, snoop, avl);
	if (!snoop)
		return;
	snoop->ifname = strdup(blobmsg_get_string(tb[STATUS_ATTR_L3_DEVICE]));
	snoop_start(snoop);
}

static void
receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj,
                    void *priv)
{
	char *path;

	if (strncmp(obj->path, NETIFD_PATH, NETIFD_PATH_LEN))
		return;
	path = strdup(obj->path);
	ubus_invoke(&conn.ctx, obj->id, "status", NULL, ubus_netifd_status_cb, &path[NETIFD_PATH_LEN], 3000);

	free(path);
}

static void
handle_status(struct ubus_context *ctx,  struct ubus_event_handler *ev,
	      const char *type, struct blob_attr *msg)
{
	enum {
		EVENT_ID,
		EVENT_PATH,
		__EVENT_MAX
	};

	static const struct blobmsg_policy status_policy[__EVENT_MAX] = {
		[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	};

	struct blob_attr *tb[__EVENT_MAX];
	struct dhcpsnoop *snoop;
	uint32_t id;
	char *path;

	blobmsg_parse(status_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	if (strncmp(path, NETIFD_PATH, NETIFD_PATH_LEN))
		return;
	if (!strcmp("ubus.object.remove", type)) {
		snoop = avl_find_element(&dhcpsnoops, &path[NETIFD_PATH_LEN], snoop, avl);
		if (!snoop)
			return;
		snoop_free(snoop);
	}

	if (!strcmp("ubus.object.add", type))
		ubus_invoke(&conn.ctx, id, "status", NULL, ubus_netifd_status_cb, &path[NETIFD_PATH_LEN], 3000);
}

static struct ubus_event_handler status_handler = { .cb = handle_status };

static void
ubus_connect_handler(struct ubus_context *ctx)
{
        ULOG_NOTE("connected to ubus\n");
	ubus_add_object(ctx, &ubus_object);

	ubus_register_event_handler(ctx, &status_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.remove");

	ubus_lookup(ctx, NULL, receive_list_result, NULL);
}

static void
config_load_network(char *network)
{
	struct dhcpsnoop *snoop = malloc(sizeof(*snoop));

	ULOG_INFO("loading network %s\n", network);

	memset(snoop, 0, sizeof(*snoop));
	snoop->network = strdup(network);
	snoop->avl.key = snoop->network;
	avl_insert(&dhcpsnoops, &snoop->avl);
}

static void
config_load(void)
{
	enum {
		SNOOPING_ATTR_NETWORK,
		__SNOOPING_ATTR_MAX,
	};

	static const struct blobmsg_policy snooping_attrs[__SNOOPING_ATTR_MAX] = {
		[SNOOPING_ATTR_NETWORK] = { .name = "network", .type = BLOBMSG_TYPE_ARRAY },
	};

	const struct uci_blob_param_list snooping_attr_list = {
		.n_params = __SNOOPING_ATTR_MAX,
		.params = snooping_attrs,
	};

	struct blob_attr *tb[__SNOOPING_ATTR_MAX] = { 0 };
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;

	ULOG_INFO("loading config\n");

	if (!uci_load(uci, "dhcpsnoop", &package)) {
		struct uci_element *e;

		uci_foreach_element(&package->sections, e) {
			struct uci_section *s = uci_to_section(e);
			struct blob_attr *a;
			int rem;

			if (strcmp(s->type, "snooping"))
				continue;

		        blob_buf_init(&b, 0);
		        uci_to_blob(&b, s, &snooping_attr_list);
		        blobmsg_parse(snooping_attrs, __SNOOPING_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

		        if (!tb[SNOOPING_ATTR_NETWORK])
				continue;
			blobmsg_for_each_attr(a, tb[SNOOPING_ATTR_NETWORK], rem)
			if (blobmsg_type(a) == BLOBMSG_TYPE_STRING)
				config_load_network(blobmsg_get_string(a));
		}
	}

	uci_unload(uci, package);
	uci_free_context(uci);
}

int
main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "udhcpsnoop");

	uloop_init();

	avl_init(&dhcpsnoops, avl_strcmp, false, NULL);
	config_load();

	conn.cb = ubus_connect_handler;
        ubus_auto_connect(&conn);
	uloop_run();
	uloop_done();

	return 0;
}
