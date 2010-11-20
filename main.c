/*
 * Path Selection Daemon for open80211s
 * Copyright (c) 2010, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See README and COPYING for more details.
 */

#include <unistd.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>

#include "o11s-pathseld.h"
#include "nl80211.h"
#include "netlink.h"

// Runtime config variables
static fd_set rd_sock_set;
static fd_set wr_sock_set;
static int max_fds;
static char *ifname = NULL;
char bogus_ie[32];

enum mpath_frame_type {
	MPATH_PREQ = 0,
	MPATH_PREP,
	MPATH_PERR,
	MPATH_RANN
};

static void usage(void)
{
	int i;
	printf("%s\n\n"
	       "usage:\n"
	       "  o11s_pathseld -s mesh_id [-B] [-i<ifname>]\n\n", o11s_pathseld_version);
}

int register_read_socket(int sock)
{
	FD_SET(sock, &rd_sock_set);
	max_fds = (sock >= max_fds) ? sock + 1 : max_fds;
}

static int event_handler(struct nl_msg *msg, void *arg)
{
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
	int cmd = gnlh->cmd;
	uint8_t *pos;
	int i;

        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);

	switch (gnlh->cmd) {
		case NL80211_CMD_FRAME:
			if (tb[NL80211_ATTR_FRAME] && nla_len(tb[NL80211_ATTR_FRAME])) {
				pos = nla_data(tb[NL80211_ATTR_FRAME]);
				if (*(pos + 24) == 0x20) {
					switch (*(pos + 25)) {
						case MPATH_PREQ:
							printf("Path Request Frame ");
							break;
						case MPATH_PREP:
							printf("Path Reply Frame ");
							break;
						case MPATH_PERR:
							printf("Path Error Frame ");
							break;
					}
					printf("from %02x:%02x:%02x:%02x:%02x:%02x\n",
							*(pos + 10), *(pos + 11),
							*(pos + 12), *(pos + 13),
							*(pos + 14), *(pos + 15));
				}
				printf("----------\n");
				printf("frame hexdump: ");
				for (i=0; i<nla_len(tb[NL80211_ATTR_FRAME]); i++) {
					if (!(i%20)) printf("\n");
					printf("%02x ", *pos++);
				}
				printf("\n----------\n\n");
			}
			break;
		case NL80211_CMD_NEW_STATION:
			printf("NL80211_CMD_NEW_STATION :)\n");
			break;
		default:
			printf("Ignored event\n");
			break;
	}

	return NL_SKIP;
}

int wait_on_sockets()
{
	int retval;
	int s1, s2;
	char buf[1000];
	while (1) {
		// s1 = nl_socket_get_fd(nlcfg.nl_sock_event);
		s2 = nl_socket_get_fd(nlcfg.nl_sock);
		max_fds = ( s1 > s2 ) ? s1 + 1 : s2 + 1;
		// FD_SET(s1, &rd_sock_set);
		FD_SET(s2, &rd_sock_set);
		retval = select(max_fds, &rd_sock_set, &wr_sock_set, NULL, NULL);
		//if (FD_ISSET(s1, &rd_sock_set)) {
        	//	nl_recvmsgs_default(nlcfg.nl_sock_event);
		//}
		if (FD_ISSET(s2, &rd_sock_set))
        		nl_recvmsgs_default(nlcfg.nl_sock);
	}
}

int receive_ps_frames(struct nl_msg *msg, void *arg)
{
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *action_frame;

	printf("receive_ps_frames %d\n", __LINE__);
        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);
        if (!tb[NL80211_ATTR_FRAME])
                return NL_SKIP;
	else
		printf("frame size is %d in %p\n",
				nla_len(tb[NL80211_ATTR_FRAME]),
					nla_data(tb[NL80211_ATTR_FRAME]));

	return NL_SKIP;
}

int reroute_path_selection_frames(char* ifname)
{
        struct nl_msg *msg;
        uint8_t cmd = NL80211_CMD_REGISTER_FRAME;
        int ret;
	char *pret;
	char action_code[2] = { 0x20, 0x00 };

        int ifindex = if_nametoindex(ifname);

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

	pret = genlmsg_put(msg, 0, 0,
		genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);
	if (pret == NULL)
		goto nla_put_failure;

        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, sizeof(action_code), action_code);

        ret = send_and_recv_msgs(msg, receive_ps_frames, NULL);
        if (ret)
		printf("Registering for path selection frames failed: %d (%s)\n", ret,
			strerror(-ret));
	else
		printf("Registering for path selection frames succeeded.  Yay!\n");

        return ret;
 nla_put_failure:
        return -ENOBUFS;
}

int join_mesh(char* ifname, char *mesh_id, int mesh_id_len, char *vendor_ie, int vendor_ie_len)
{
        struct nl_msg *msg;
        uint8_t cmd = NL80211_CMD_JOIN_MESH;
        int ret;
	char *pret;

        int ifindex = if_nametoindex(ifname);

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

	if (!mesh_id || !mesh_id_len)
		return -EINVAL;

        printf("o11s-pathseld: Staring mesh with mesh id = %s\n", mesh_id);

	pret = genlmsg_put(msg, 0, 0,
		genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);
	if (pret == NULL)
		goto nla_put_failure;

	if (vendor_ie) {
		struct nlattr *container = nla_nest_start(msg,
				NL80211_ATTR_MESH_PARAMS);

		if (!container)
			return -ENOBUFS;

		NLA_PUT(msg, NL80211_MESHCONF_VENDOR_PATH_SEL_IE,
				vendor_ie_len, vendor_ie);
		NLA_PUT_U8(msg, NL80211_MESHCONF_ENABLE_VENDOR_PATH_SEL, 1);
		NLA_PUT_U8(msg, NL80211_MESHCONF_ENABLE_VENDOR_METRIC, 1);
		nla_nest_end(msg, container);
	}

        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
        NLA_PUT(msg, NL80211_ATTR_MESH_ID, mesh_id_len, mesh_id);

        ret = send_and_recv_msgs(msg, NULL, NULL);
        if (ret)
		printf("Mesh start failed: %d (%s)\n", ret,
			strerror(-ret));
	else
		printf("Mesh start succeeded.  Yay!\n");

        return ret;
 nla_put_failure:
        return -ENOBUFS;
}


int main(int argc, char *argv[])
{
	int c;
	int exitcode = 0;
	char *mesh_id;

	FD_ZERO(&rd_sock_set);
	FD_ZERO(&wr_sock_set);
	int max_fds = 0;

	for (;;) {
		c = getopt(argc, argv, "Bi:s:");
		if (c < 0)
			break;
		switch (c) {
		case 'B':
			/* TODO: background operation */
			break;
		case 'i':
			ifname = optarg;
			break;
		case 's':
			mesh_id = optarg;
			break;
		default:
			usage();
			goto out;
		}
	}

	if (ifname == NULL) {
		usage();
		exitcode = -EINVAL;
		goto out;
	}

	if (netlink_init(event_handler)) {
		exitcode = -ESOCKTNOSUPPORT;
		goto out;
	}

	memset(bogus_ie, 0, sizeof(bogus_ie));
	/* Vendor specific */
	bogus_ie[0] = 221;
	/* nl80211 will check that this is an information element
	   by inspecting its length field.  So this bogus ie should
	   at least have a correct length, which we set below.
	   */
	bogus_ie[1] = sizeof(bogus_ie) - 2;
	snprintf(&bogus_ie[5], sizeof(bogus_ie) - 2, "yay!");
	exitcode = join_mesh(ifname, mesh_id, strlen(mesh_id), bogus_ie, sizeof(bogus_ie));
	if (exitcode)
		return exitcode;
	exitcode = reroute_path_selection_frames(ifname);
	if (exitcode)
		return exitcode;
	wait_on_sockets();

	/* TODO:  Remove beacon on exit.  In order to remove the beacon, we
	   need to get the beacon from o11s, delete it, and then add it again
	   without a tail.
	   This requires the command NL80211_CMD_GET_BEACON to be implemented.
	   */
out:
	return exitcode;
}
