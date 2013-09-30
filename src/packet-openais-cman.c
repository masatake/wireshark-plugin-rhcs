/* packet-openais-cman.c
 * Routines for dissecting protocol used in cman running on OpenAIS
 * Copyright 2008, Masatake YAMATO <yamato@redhat.com>
 * Copyright 2009, Red Hat, Inc.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "packet-corosync-totempg.h"


/* Copied from "cman-2.0.73/cman/daemon/cnxman-private.h" */
#define OPENAIS_CMAN_CLUSTER_MSG_ACK          1
#define OPENAIS_CMAN_CLUSTER_MSG_PORTOPENED   2
#define OPENAIS_CMAN_CLUSTER_MSG_PORTCLOSED   3
#define OPENAIS_CMAN_CLUSTER_MSG_BARRIER      4
#define OPENAIS_CMAN_CLUSTER_MSG_TRANSITION   5
#define OPENAIS_CMAN_CLUSTER_MSG_KILLNODE     6
#define OPENAIS_CMAN_CLUSTER_MSG_LEAVE        7
#define OPENAIS_CMAN_CLUSTER_MSG_RECONFIGURE  8
#define OPENAIS_CMAN_CLUSTER_MSG_PORTENQ      9
#define OPENAIS_CMAN_CLUSTER_MSG_PORTSTATUS  10
#define OPENAIS_CMAN_CLUSTER_MSG_FENCESTATUS 11

#define OPENAIS_CMAN_CLUSTER_KILL_REJECTED   1
#define OPENAIS_CMAN_CLUSTER_KILL_CMANTOOL   2
#define OPENAIS_CMAN_CLUSTER_KILL_REJOIN     3

#define OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_BEENDOWN           0x00000001
#define OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_FENCED             0x00000002
#define OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_FENCEDWHILEUP      0x00000004
#define OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_SEESDISALLOWED     0x00000008

#define OPENAIS_CMAN_BARRIER_REGISTER 1
#define OPENAIS_CMAN_BARRIER_CHANGE   2
#define OPENAIS_CMAN_BARRIER_WAIT     4
#define OPENAIS_CMAN_BARRIER_COMPLETE 5
#define OPENAIS_CMAN_MAX_BARRIER_NAME_LEN 33

#define OPENAIS_CMAN_RECONFIG_PARAM_EXPECTED_VOTES 1
#define OPENAIS_CMAN_RECONFIG_PARAM_NODE_VOTES     2
#define OPENAIS_CMAN_RECONFIG_PARAM_CONFIG_VERSION 3
#define OPENAIS_CMAN_RECONFIG_PARAM_CCS            4

#define OPENAIS_CMAN_PORT_BITS_SIZE          32

/* Forward declaration we need below */
void proto_reg_handoff_openais_cman(void);

static guint32 openais_cman_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);

/* Initialize the protocol and registered fields */
static int proto_openais_cman = -1;

/* fields for struct cl_protheader */
/* static int hf_openais_cman_cl_protoheader = -1; */
static int hf_openais_cman_cl_protoheader_tgtport = -1;
static int hf_openais_cman_cl_protoheader_srcport = -1;
static int hf_openais_cman_cl_protoheader_pad     = -1;
static int hf_openais_cman_cl_protoheader_flags   = -1;
static int hf_openais_cman_cl_protoheader_srcid   = -1;
static int hf_openais_cman_cl_protoheader_tgtid   = -1;

static int hf_openais_cman_cl_protmsg_cmd         = -1;

static int hf_openais_cman_cl_portmsg_port        = -1;

static int hf_openais_cman_cl_barriermsg_subcmd    = -1;
static int hf_openais_cman_cl_barriermsg_pad       = -1;
static int hf_openais_cman_cl_barriermsg_name      = -1;

static int hf_openais_cman_cl_transmsg_first_trans    = -1;
static int hf_openais_cman_cl_transmsg_cluster_id     = -1;
static int hf_openais_cman_cl_transmsg_high_nodeid    = -1;
static int hf_openais_cman_cl_transmsg_expected_votes = -1;
static int hf_openais_cman_cl_transmsg_major_version  = -1;
static int hf_openais_cman_cl_transmsg_minor_version  = -1;
static int hf_openais_cman_cl_transmsg_patch_version  = -1;
static int hf_openais_cman_cl_transmsg_config_version = -1;

static int hf_openais_cman_cl_transmsg_flags                = -1;
static int hf_openais_cman_cl_transmsg_flags_beendown       = -1;
static int hf_openais_cman_cl_transmsg_flags_fenced         = -1;
static int hf_openais_cman_cl_transmsg_flags_fencedwhileup  = -1;
static int hf_openais_cman_cl_transmsg_flags_seesdisallowed = -1;

static int hf_openais_cman_cl_transmsg_fence_time  = -1;
static int hf_openais_cman_cl_transmsg_join_time   = -1;
static int hf_openais_cman_cl_transmsg_clustername = -1;
static int hf_openais_cman_cl_transmsg_fence_agent = -1;

static int hf_openais_cman_cl_killmsg_pad1        = -1;
static int hf_openais_cman_cl_killmsg_reason      = -1;
static int hf_openais_cman_cl_killmsg_nodeid      = -1;

static int hf_openais_cman_cl_leavemsg_pad1       = -1;
static int hf_openais_cman_cl_leavemsg_reason     = -1;

static int hf_openais_cman_cl_reconfig_msg_param = -1;
static int hf_openais_cman_cl_reconfig_msg_pad   = -1;
static int hf_openais_cman_cl_reconfig_msg_nodeid= -1;
static int hf_openais_cman_cl_reconfig_msg_value = -1;

static int hf_openais_cman_cl_portstatus          = -1;

static int hf_openais_cman_cl_fencemsg_fenced     = -1;
static int hf_openais_cman_cl_fencemsg_pad        = -1;
static int hf_openais_cman_cl_fencemsg_nodeid     = -1;
static int hf_openais_cman_cl_fencemsg_timesec    = -1;
static int hf_openais_cman_cl_fencemsg_agent      = -1;

/* Initialize the subtree pointers */
static gint ett_openais_cman                      = -1;
static gint ett_openais_cman_cl_portmsg           = -1;
static gint ett_openais_cman_cl_barriermsg        = -1;
static gint ett_openais_cman_cl_transmsg          = -1;
static gint ett_openais_cman_cl_transmsg_flags    = -1;
static gint ett_openais_cman_cl_killmsg           = -1;
static gint ett_openais_cman_cl_leavemsg          = -1;
static gint ett_openais_cman_cl_reconfig_msg      = -1;
static gint ett_openais_cman_cl_portstatus        = -1;
static gint ett_openais_cman_cl_fencemsg          = -1;


/* Value strings */
static const value_string vals_cluster_msg[] = {
	{ OPENAIS_CMAN_CLUSTER_MSG_ACK,         "ack"          },
	{ OPENAIS_CMAN_CLUSTER_MSG_PORTOPENED,  "port-opened"  },
	{ OPENAIS_CMAN_CLUSTER_MSG_PORTCLOSED,  "port-closed"  },
	{ OPENAIS_CMAN_CLUSTER_MSG_BARRIER,     "barrier"      },
	{ OPENAIS_CMAN_CLUSTER_MSG_TRANSITION,  "transition"   },
	{ OPENAIS_CMAN_CLUSTER_MSG_KILLNODE,    "kill-node"    },
	{ OPENAIS_CMAN_CLUSTER_MSG_LEAVE,       "leave"        },
	{ OPENAIS_CMAN_CLUSTER_MSG_RECONFIGURE, "reconfigure"  },
	{ OPENAIS_CMAN_CLUSTER_MSG_PORTENQ,     "post-enqueue" },
	{ OPENAIS_CMAN_CLUSTER_MSG_PORTSTATUS,  "port-status"  },
	{ OPENAIS_CMAN_CLUSTER_MSG_FENCESTATUS, "fence-status" },
	{ 0,                                    NULL           },
		
};

static const value_string vals_barriermsg_subcmd[] = {
	{ OPENAIS_CMAN_BARRIER_REGISTER, "Register"},
	{ OPENAIS_CMAN_BARRIER_CHANGE,   "Change"},
	{ OPENAIS_CMAN_BARRIER_WAIT,     "Wait"},
	{ OPENAIS_CMAN_BARRIER_COMPLETE, "Complete"},
	{ 0, NULL },
};

static const value_string vals_cluster_leavemsg_reason[] = {
	{ OPENAIS_CMAN_CLUSTER_KILL_REJECTED,  "Rejected"              },
	{ OPENAIS_CMAN_CLUSTER_KILL_CMANTOOL,  "Requested by cmantool" },
	{ OPENAIS_CMAN_CLUSTER_KILL_REJOIN,    "Rejoin"                },
	{ 0,                                   NULL                    },

};
#define vals_cluster_killmsg_reason vals_cluster_leavemsg_reason


static const value_string vals_reconfig_param[] = {
	{ OPENAIS_CMAN_RECONFIG_PARAM_EXPECTED_VOTES, "Expected votes" },
	{ OPENAIS_CMAN_RECONFIG_PARAM_NODE_VOTES,     "Node votes" },
	{ OPENAIS_CMAN_RECONFIG_PARAM_CONFIG_VERSION, "Version of configuration" },
	{ OPENAIS_CMAN_RECONFIG_PARAM_CCS,            "CCS" },
	{ 0, NULL },
};

/* Bit fields */
static const int* b_node_flags[] = {
	&hf_openais_cman_cl_transmsg_flags_beendown,
	&hf_openais_cman_cl_transmsg_flags_fenced,
	&hf_openais_cman_cl_transmsg_flags_fencedwhileup,
	&hf_openais_cman_cl_transmsg_flags_seesdisallowed,
	NULL

};


static dissector_table_t subdissector_table;


static int
dissect_openais_cman_msg_port_do_generic(tvbuff_t *tvb,
					 packet_info *pinfo, 
					 proto_item *parent_item,
					 guint length, int offset,
					 gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;


#define length_openais_cman_msg_port_do_generic (1)
	if ((length - offset) < length_openais_cman_msg_port_do_generic)
		return 0;
	original_offset = offset;
	
	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_portmsg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_portmsg_port,
			    tvb, offset, 1, little_endian);
	
	
	offset += 1;
	return (offset - original_offset);
	
	pinfo = pinfo;
}
	

static int
dissect_openais_cman_msg_portopened(tvbuff_t *tvb,
				    packet_info *pinfo, 
				    proto_item *parent_item,
				    guint length, int offset,
				    gboolean little_endian)
{
	return dissect_openais_cman_msg_port_do_generic(tvb, 
							pinfo, 
							parent_item, 
							length, offset, 
							little_endian);
}

static int
dissect_openais_cman_msg_portclosed(tvbuff_t *tvb,
				    packet_info *pinfo, 
				    proto_item *parent_item,
				    guint length, int offset,
				    gboolean little_endian)
{
	return dissect_openais_cman_msg_port_do_generic(tvb, 
							pinfo, 
							parent_item, 
							length, offset, 
							little_endian);
}

static int
dissect_openais_cman_msg_barrier(tvbuff_t *tvb,
				 packet_info *pinfo, 
				 proto_item *parent_item,
				 guint length, int offset,
				 gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;

#define length_openais_cman_msg_barrier (1 + 2 + OPENAIS_CMAN_MAX_BARRIER_NAME_LEN)
	if ((length - offset) < length_openais_cman_msg_barrier)
		return 0;
	original_offset = offset;

	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_barriermsg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_barriermsg_subcmd,
			    tvb, offset, 1, little_endian);

	offset += 1;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_barriermsg_pad,
			    tvb, offset, 2, little_endian);

	offset += 2;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_barriermsg_name,
			    tvb, offset, OPENAIS_CMAN_MAX_BARRIER_NAME_LEN, little_endian);


	offset += OPENAIS_CMAN_MAX_BARRIER_NAME_LEN;

	return (offset - original_offset);

	pinfo = pinfo;
}

static int
dissect_openais_cman_msg_trans(tvbuff_t *tvb,
			       packet_info *pinfo, 
			       proto_item *parent_item,
			       guint length, int offset,
			       gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;

	guint32 major_version;
	
#define length_openais_cman_msg_port_trans (1 + 2 + 4 + 4 \
		+ 4 + 4 + 4 + 4                           \
	        + 4                                       \
		+ 8 + 8 + 16                              \
                + 1)

	if ((length - offset) < length_openais_cman_msg_port_trans)
		return 0;
	original_offset = offset;
	
	
	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_transmsg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_first_trans,
			    tvb, offset, 1, little_endian);
	
	
	offset += 1;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_cluster_id,
			    tvb, offset, 2, little_endian);
	
	offset += 2;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_high_nodeid,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_expected_votes,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_major_version,
			    tvb, offset, 4, little_endian);
	major_version = openais_cman_get_guint32(tvb, offset, little_endian);
						 

	offset += 4;
	/* This dissector is tested on version 6 packets. */
	if (major_version != 6) goto out;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_minor_version,
			    tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_patch_version,
			    tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_config_version,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	proto_tree_add_bitmask(tree, tvb, offset,
			       hf_openais_cman_cl_transmsg_flags,
			       ett_openais_cman_cl_transmsg_flags,
			       b_node_flags, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_fence_time,
			    tvb, offset, 8, little_endian);
	offset += 8;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_transmsg_join_time,
			    tvb, offset, 8, little_endian);
	
	offset += 8;
	proto_tree_add_item(tree, 
			    hf_openais_cman_cl_transmsg_clustername,
			    tvb, offset, 16, little_endian);

	offset += 16;
	proto_tree_add_item(tree, 
			    hf_openais_cman_cl_transmsg_fence_agent,
			    tvb, offset, (length - offset), little_endian);
	
	offset += (length - offset);
out:
	return (offset - original_offset);
	
	pinfo = pinfo;
}

static int
dissect_openais_cman_msg_kill(tvbuff_t *tvb,
			      packet_info *pinfo, 
			      proto_item *parent_item,
			      guint length, int offset,
			      gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;

#define length_openais_cman_msg_kill (1 + 2 + 4)
	if ((length - offset) < length_openais_cman_msg_kill)
		return 0;
	original_offset = offset;

	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_killmsg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_killmsg_pad1,
			    tvb, offset, 1, little_endian);

	offset += 1;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_killmsg_reason,
			    tvb, offset, 2, little_endian);

	offset += 2;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_killmsg_nodeid,
			    tvb, offset, 4, little_endian);

	offset += 4;

	return (offset - original_offset);

	pinfo = pinfo;
}

static int
dissect_openais_cman_msg_leave(tvbuff_t *tvb,
			       packet_info *pinfo, 
			       proto_item *parent_item,
			       guint length, int offset,
			       gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;


#define length_openais_cman_msg_port_leave (1 + 2)
	if ((length - offset) < length_openais_cman_msg_port_leave)
		return 0;
	original_offset = offset;
	
	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_leavemsg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_leavemsg_pad1,
			    tvb, offset, 1, little_endian);
	
	
	offset += 1;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_leavemsg_reason,
			    tvb, offset, 2, little_endian);
	
	offset += 2;
	return (offset - original_offset);
	
	pinfo = pinfo;
}

static int
dissect_openais_cman_msg_reconfigure(tvbuff_t *tvb,
				     packet_info *pinfo, 
				     proto_item *parent_item,
				     guint length, int offset,
				     gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;

	guint8 param;
	proto_item* value_item;
		
#define length_openais_cman_msg_port_reconfigure (1 + 2 + 4 + 4)
	if ((length - offset) < length_openais_cman_msg_port_reconfigure)
		return 0;
	original_offset = offset;
	
	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_reconfig_msg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_reconfig_msg_param,
			    tvb, offset, 1, little_endian);
	param = tvb_get_guint8(tvb, offset);
	
	
	offset += 1;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_reconfig_msg_pad,
			    tvb, offset, 2, little_endian);
	
	offset += 2;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_reconfig_msg_nodeid,
			    tvb, offset, 4, little_endian);

	offset += 4;
	value_item = proto_tree_add_item(tree,
					 hf_openais_cman_cl_reconfig_msg_value,
					 tvb, offset, 4, little_endian);
	switch (param) {
	case OPENAIS_CMAN_RECONFIG_PARAM_EXPECTED_VOTES:
		proto_item_append_text(value_item, " (the number of expected votes)");
		break;
		
	case OPENAIS_CMAN_RECONFIG_PARAM_NODE_VOTES:
		proto_item_append_text(value_item, " (the number of votes)");
		break;
		
	case OPENAIS_CMAN_RECONFIG_PARAM_CONFIG_VERSION:
		proto_item_append_text(value_item, " (config version number)");
		break;

	case OPENAIS_CMAN_RECONFIG_PARAM_CCS:
		/* ??? */
		break;
	default:
		break;
	}
		

	offset += 4;

	
	return (offset - original_offset);
	
	pinfo = pinfo;
}

static int
dissect_openais_cman_msg_portstatus(tvbuff_t *tvb,
				    packet_info *pinfo,
				    proto_item  *parent_item,
				    guint length, int offset,
				    gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;
	
#define length_openais_cman_msg_portstatus (OPENAIS_CMAN_PORT_BITS_SIZE)
	if ((length - offset) < length_openais_cman_msg_portstatus)
		return 0;

	original_offset = offset;


	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_portstatus);

	offset += 0;
	proto_tree_add_item(tree, 
			    hf_openais_cman_cl_portstatus,
			    tvb, offset, OPENAIS_CMAN_PORT_BITS_SIZE, little_endian);
	
	offset += OPENAIS_CMAN_PORT_BITS_SIZE;
	return (offset - original_offset);

	pinfo = pinfo;
}
	
static int
dissect_openais_cman_msg_fencestatus(tvbuff_t *tvb,
				     packet_info *pinfo, 
				     proto_item *parent_item,
				     guint length, int offset,
				     gboolean little_endian)
{
	int original_offset;
	proto_tree* tree;


#define length_openais_cman_msg_fencestatus (1 + 2 + 4 + 8)
	if ((length - offset) < length_openais_cman_msg_fencestatus)
		return 0;
	original_offset = offset;
	
	tree = proto_item_add_subtree(parent_item, ett_openais_cman_cl_fencemsg);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_fencemsg_fenced,
			    tvb, offset, 1, little_endian);
	
	
	offset += 1;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_fencemsg_pad,
			    tvb, offset, 2, little_endian);
	
	offset += 2;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_fencemsg_nodeid,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_fencemsg_timesec,
			    tvb, offset, 8, little_endian);
	offset += 8;
	proto_tree_add_item(tree,
			    hf_openais_cman_cl_fencemsg_agent,
			    tvb, offset, (length - offset), little_endian);
	
	offset += (length - offset);
	return (offset - original_offset);
	
	pinfo = pinfo;
}

static int
dissect_openais_cman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	guint    length;
	int      offset;

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;

	guint8      tgtport;


	length = tvb_length(tvb);
	if (length < (1 + 1 + 2 + 4 + 4 + 4 + 1))
		return 0;

	/* if (check_col(pinfo->cinfo, COL_PROTOCOL))
	   col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPENAIS/CMAN"); */
	  
	/* if (check_col(pinfo->cinfo, COL_INFO))
	   col_clear(pinfo->cinfo, COL_INFO); */

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(cman");
	  
	if (!parent_tree)
		goto out;


	little_endian = corosync_totempg_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_cman, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cman);

	offset += 0;
	{
		proto_item *sub_item;

		sub_item = proto_tree_add_item(tree, hf_openais_cman_cl_protoheader_tgtport,
					       tvb, offset, 1, little_endian);
		tgtport = tvb_get_guint8(tvb, offset);

		if (tgtport == 0)
			proto_item_append_text(sub_item, " (%s)", "cman internal");
		else
		{
			dissector_handle_t h;
			
			h = dissector_get_uint_handle(subdissector_table, tgtport);
			proto_item_append_text(sub_item, " (%s)", 
					       h? dissector_handle_get_short_name(h): "application");
		}
	}

	offset += 1;
	proto_tree_add_item(tree, hf_openais_cman_cl_protoheader_srcport,
			    tvb, offset, 1, little_endian);

	offset += 1;
	proto_tree_add_item(tree, hf_openais_cman_cl_protoheader_pad,
			    tvb, offset, 2, little_endian);


	offset += 2;
	proto_tree_add_item(tree, hf_openais_cman_cl_protoheader_flags,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree, hf_openais_cman_cl_protoheader_srcid,
			    tvb, offset, 4, little_endian);


	offset += 4;
	{
		proto_item *sub_item;
		guint32     tgtid;


		sub_item = proto_tree_add_item(tree, hf_openais_cman_cl_protoheader_tgtid,
					       tvb, offset, 4, little_endian);
		tgtid = openais_cman_get_guint32(tvb, offset, little_endian);

		
		if (tgtid == 0)
			proto_item_append_text(sub_item, " (%s)", "whole cluster");
	}
		  

	offset += 4;

	if (tgtport == 0)
	{
		unsigned char cmd;
		int sub_offset;
		proto_item *sub_item;

		sub_item = proto_tree_add_item(tree, hf_openais_cman_cl_protmsg_cmd,
					       tvb, offset, 1, little_endian);

		cmd = tvb_get_guint8(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, 
					" :%s", 
					val_to_str(cmd, 
						   vals_cluster_msg, 
						   "UNKNOWN-MESSAGE-TYPE"));
		offset += 1;
		sub_offset = 0;	/* TODO */
		switch (cmd)
		{
		case OPENAIS_CMAN_CLUSTER_MSG_ACK:
			/* Not used in cman.c */
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_PORTOPENED:
			sub_offset = dissect_openais_cman_msg_portopened(tvb,
									 pinfo,
									 sub_item,
									 length,
									 offset,
									 little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_PORTCLOSED:
			sub_offset = dissect_openais_cman_msg_portclosed(tvb,
									 pinfo,
									 sub_item,
									 length,
									 offset,
									 little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_BARRIER:
			sub_offset = dissect_openais_cman_msg_barrier(tvb,
								      pinfo,
								      sub_item,
								      length,
								      offset,
								      little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_TRANSITION:
			sub_offset = dissect_openais_cman_msg_trans(tvb,
								    pinfo,
								    sub_item,
								    length,
								    offset,
								    little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_KILLNODE:
			sub_offset = dissect_openais_cman_msg_kill(tvb,
								   pinfo,
								   sub_item,
								   length,
								   offset,
								   little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_LEAVE:
			sub_offset = dissect_openais_cman_msg_leave(tvb,
								    pinfo,
								    sub_item,
								    length,
								    offset,
								    little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_RECONFIGURE:
			sub_offset = dissect_openais_cman_msg_reconfigure(tvb,
									  pinfo,
									  sub_item,
									  length,
									  offset,
									  little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_PORTENQ:
			/* NO MORE DATA */
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_PORTSTATUS:
			sub_offset = dissect_openais_cman_msg_portstatus(tvb,
									 pinfo,
									 sub_item,
									 length,
									 offset,
									 little_endian);
			break;
		case OPENAIS_CMAN_CLUSTER_MSG_FENCESTATUS:
			sub_offset = dissect_openais_cman_msg_fencestatus(tvb,
									  pinfo,
									  sub_item,
									  length,
									  offset,
									  little_endian);
			break;
		default:
			break;
		}
		offset += sub_offset;
	}
	else
	{
		tvbuff_t* next_tvb;

		next_tvb = tvb_new_subset(tvb, offset, (length - offset), (length - offset));
		dissector_try_uint(subdissector_table, tgtport, 
				   next_tvb, pinfo, tree);
	}

out:
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, ")");
	return tvb_length(tvb);
}


void
proto_register_openais_cman(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
		{ &hf_openais_cman_cl_protoheader_tgtport,
		  { "Target port number", "openais_cman.tgtport",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_protoheader_srcport,
		  { "Source port number", "openais_cman.srcport",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_protoheader_pad,
		  { "Padding", "openais_cman.pad",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_protoheader_flags,
		  { "Flags", "openais_cman.flags",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_protoheader_srcid,
		  { "Source node id", "openais_cman.srcid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_protoheader_tgtid,
		  { "Target node id", "openais_cman.tgtid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_protmsg_cmd,
		  { "Command", "openais_cman.protmsg.cmd",
		    FT_UINT8, BASE_DEC, VALS(vals_cluster_msg), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_portmsg_port,
		  { "Port", "openais_cman.portmsg.port",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cman_cl_barriermsg_subcmd,
		  { "Sub command", "openais_cman.barriermsg.subcmd",
		    FT_UINT8, BASE_DEC, VALS(vals_barriermsg_subcmd), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_barriermsg_pad,
		  { "Padding", "openais_cman.barriermsg.pad",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_barriermsg_name,
		  { "Name", "openais_cman.barriermsg.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		
		{ &hf_openais_cman_cl_transmsg_first_trans,
		  { "First transition", "openais_cman.transmsg.first_trans",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_cluster_id,
		  { "Cluster id", "openais_cman.transmsg.cluster_id",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_high_nodeid,
		  { "High node id", "openais_cman.transmsg.high_nodeid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_expected_votes,
		  { "Expected votes", "openais_cman.transmsg.expected_votes",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_major_version,
		  { "Major version", "openais_cman.transmsg.major_version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_minor_version,
		  { "Minor version", "openais_cman.transmsg.minor_version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_patch_version,
		  { "Patch version", "openais_cman.transmsg.patch_version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_config_version,
		  { "Config version", "openais_cman.transmsg.config_version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cman_cl_transmsg_flags,
		  { "Node flags", "openais_cman.transmsg.flags",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_flags_beendown,
		  { "Been down", "openais_cman.transmsg.flags.beendown",
		    FT_BOOLEAN, 32, NULL, OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_BEENDOWN,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_flags_fenced,
		  { "Fenced", "openais_cman.transmsg.flags.fenced",
		    FT_BOOLEAN, 32, NULL, OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_FENCED,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_flags_fencedwhileup,
		  { "Fenced while up", "openais_cman.transmsg.flags.fencedwhileup",
		    FT_BOOLEAN, 32, NULL, OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_FENCEDWHILEUP,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_flags_seesdisallowed,
		  { "Sees disallowed", "openais_cman.transmsg.flags.seesdisallowed",
		    FT_BOOLEAN, 32, NULL, OPENAIS_CMAN_TRANSMSG_FLAGS_NODE_SEESDISALLOWED,
		    NULL, HFILL }},

		{ &hf_openais_cman_cl_transmsg_fence_time,
		  { "Fence time", "openais_cman.transmsg.fence_time",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_join_time,
		  { "Join time", "openais_cman.transmsg.join_time",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }}, 
		{ &hf_openais_cman_cl_transmsg_clustername,
		  { "Cluster name", "openais_cman.transmsg.clustername",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_transmsg_fence_agent,
		  { "Fence agent", "openais_cman.transmsg.fence_agent",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cman_cl_killmsg_pad1,
		  { "Padding", "openais_cman.killmsg.pad1",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}},
		{ &hf_openais_cman_cl_killmsg_reason,
		  { "Reason", "openais_cman.killmsg.reason",
		    FT_UINT16, BASE_DEC, VALS(vals_cluster_killmsg_reason), 0x0,
		    NULL, HFILL}},
		{ &hf_openais_cman_cl_killmsg_nodeid,
		  { "Node id", "openais_cman.killmsg.nodeid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},

		{ &hf_openais_cman_cl_leavemsg_pad1,
		  { "Padding", "openais_cman.leavemsg.pad1",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_leavemsg_reason,
		  { "Reason", "openais_cman.leavemsg.reason",
		    FT_UINT16, BASE_DEC, VALS(vals_cluster_leavemsg_reason), 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cman_cl_portstatus,
		  { "Port status bit map", "openais_cman.portstatus",
		    FT_BYTES, BASE_NONE, NULL, 0x0, /* TODO: BASE_HEX is rejected by the latest wireshark. */
		    NULL, HFILL}},

		{ &hf_openais_cman_cl_reconfig_msg_param,
		  { "Parameter", "openais_cman.reconfig_msg.param",
		    FT_UINT8, BASE_DEC, VALS(vals_reconfig_param), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_reconfig_msg_pad,
		  { "Padding", "openais_cman.reconfig_msg.pad",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_reconfig_msg_nodeid,
		  { "Node id", "openais_cman.reconfig_msg.nodeid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cman_cl_reconfig_msg_value,
		  { "Value", "openais_cman.reconfig_msg.value",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		
		{ &hf_openais_cman_cl_fencemsg_fenced,
		  { "Fenced", "openais_cman.fencemsg.fenced",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},
		{ &hf_openais_cman_cl_fencemsg_pad,
		  { "Padding", "openais_cman.fencemsg.pad",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},
		{ &hf_openais_cman_cl_fencemsg_nodeid,
		  { "Node id", "openais_cman.fencemsg.nodeid",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},
		{ &hf_openais_cman_cl_fencemsg_timesec,
		  { "Timesec", "openais_cman.fencemsg.timesec",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}},
		{ &hf_openais_cman_cl_fencemsg_agent,
		  { "Agent", "openais_cman.fencemsg.agent",
		    FT_STRING, BASE_NONE, NULL, 0x0, /* BASE_DEC is rejected by the latest wireshark. */
		    NULL, HFILL}},

	};

	static gint *ett[] = {
		&ett_openais_cman,
		&ett_openais_cman_cl_portmsg,
		&ett_openais_cman_cl_barriermsg,
		&ett_openais_cman_cl_transmsg,
		&ett_openais_cman_cl_transmsg_flags,
		&ett_openais_cman_cl_killmsg,
		&ett_openais_cman_cl_leavemsg,
		&ett_openais_cman_cl_reconfig_msg,
		&ett_openais_cman_cl_portstatus,
		&ett_openais_cman_cl_fencemsg
	};
  
	proto_openais_cman 
		= proto_register_protocol("Cman running on OpenAIS",
					  "OPENAIS/CMAN", "openais_cman");

	proto_register_field_array(proto_openais_cman, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	/* Subdissector Table */
	subdissector_table 
		= register_dissector_table("openais_cman.tgtport",
					   "Target port of cman message handler",
					   FT_UINT8,
					   BASE_DEC);
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_cman(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_cman_handle;

	if (register_dissector) {
		dissector_delete_string("corosync_totempg.group_name", "CMAN", openais_cman_handle);
	} else {
		openais_cman_handle = new_create_dissector_handle(dissect_openais_cman,
								  proto_openais_cman);
		register_dissector = TRUE;
	}
	dissector_add_string("corosync_totempg.group_name", "CMAN", openais_cman_handle);
}


static guint32
openais_cman_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
	return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}

/* packet-openais-cman.c ends here */
