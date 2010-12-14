/* packet-rhcs4-cman.c
 * Routines for Cman protocol of RHCS4
 * Copyright 2008, Masatake YAMATO <yamato@redhat.com>
 * Copyright 2009, Red Hat, Inc.
 *
 * $Id:$
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>


#define PORT_RHCS4_CMAN 6809


/* Forward declaration we need below */
void proto_reg_handoff_rhcs4_cman(void);


/* fields for struct cl_protheader */
#if 0
/* This structure is tacked onto the start of a cluster message packet for our
 * own nefarious purposes. */
struct cl_protheader {
	unsigned char  tgtport; /* Target port number */
	unsigned char  srcport; /* Source (originationg) port number */
	unsigned short seq;	/* Packet sequence number, little-endian */
	unsigned short ack;	/* Inline ACK */
	unsigned short cluster;	/* Our cluster number, little-endian */
	unsigned int   flags;
	int            srcid;	/* Node ID of the sender */
	int            tgtid;	/* Node ID of the target or 0 for multicast
				 * messages */
};

#endif

/* Sendmsg flags, these are above the normal sendmsg flags so they don't
 * interfere */
#define FLAGS_NOACK     0x010000	/* Don't need an ACK for this message */
#define FLAGS_QUEUE     0x020000	/* Queue the message for sending later */
#define FLAGS_MULTICAST 0x080000	/* Message was sent to all nodes in the cluster
				 */
#define FLAGS_ALLINT    0x100000	/* Send out of all interfaces */
#define FLAGS_REPLYEXP  0x200000	/* Reply is expected */
#define FLAGS_BCASTSELF 0x400000	/* Broadcast message also gets send to us */


/* Well-known cluster port numbers */
#define PORT_MEMBERSHIP  1	/* Mustn't block during cluster
				 * transitions! */
#define PORT_SERVICES    2
#define PORT_SYSMAN      10	/* Remote execution daemon */
#define PORT_CLVMD       11	/* Cluster LVM daemon */
#define PORT_SLM         12	/* LVM SLM (simple lock manager) */

/* Port numbers above this will be blocked when the cluster is inquorate or in
 * transition */
#define HIGH_PROTECTED_PORT      9


static int hf_rhcs4_cman_tgtport = -1;
static int hf_rhcs4_cman_srcport = -1;
static int hf_rhcs4_cman_seq     = -1;
static int hf_rhcs4_cman_ack     = -1;
static int hf_rhcs4_cman_cluster = -1;
static int hf_rhcs4_cman_flags   = -1;
static int hf_rhcs4_cman_flags_noack     = -1;
static int hf_rhcs4_cman_flags_queue     = -1;
static int hf_rhcs4_cman_flags_multicast = -1;
static int hf_rhcs4_cman_flags_allint    = -1;
static int hf_rhcs4_cman_flags_replyexp  = -1;
static int hf_rhcs4_cman_flags_bcastself = -1;
static int hf_rhcs4_cman_srcid   = -1;
static int hf_rhcs4_cman_tgtid   = -1;


/* Initialize the protocol and registered fields */
static int proto_rhcs4_cman = -1;



/* Initialize the subtree pointers */
static gint ett_rhcs4_cman                              = -1;
static gint ett_rhcs4_cman_flags                        = -1;

/* configurable parameters */
static guint  rhcs4_cman_port = PORT_RHCS4_CMAN;


/* Value strings */
static const value_string vs_rhcs4_cman_port[] = {
  { PORT_MEMBERSHIP, "Membership"           },
  { PORT_SERVICES,   "Services"             },
  { PORT_SYSMAN,     "System management"    },
  { PORT_CLVMD,      "Clvmd"                },
  { PORT_SLM,        "Simple lock manager"  },
  { 0, NULL }
};

static const value_string vs_rhcs4_cman_tgtid[] = {
  { 0,               "Multicast messages" },
  { 0,               NULL },
};

/* Bit fields */
static const int* b_rhcs4_cman_flags[] = {
  &hf_rhcs4_cman_flags_noack,
  &hf_rhcs4_cman_flags_queue,
  &hf_rhcs4_cman_flags_multicast,
  &hf_rhcs4_cman_flags_allint,
  &hf_rhcs4_cman_flags_replyexp,
  &hf_rhcs4_cman_flags_bcastself,
  NULL
};

static int
dissect_rhcs4_cman(tvbuff_t *tvb,
		   packet_info *pinfo, proto_tree *parent_tree)
{
  proto_item *item;
  proto_tree *tree;

  guint       length;
  int         offset;


  /* Check that there's enough data */
  length = tvb_length(tvb);

  if (length < 1 + 1 + 2 + 2 +2 + 4 + 4 + 4)
    return 0;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RHCS4/CMAN");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (parent_tree) {
    offset = 0;

    item = proto_tree_add_item(parent_tree, proto_rhcs4_cman, tvb, offset,
			       -1, TRUE);
    tree = proto_item_add_subtree(item, ett_rhcs4_cman);

    offset += 0;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_tgtport, tvb, offset, 1, TRUE);

    offset += 1;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_srcport, tvb, offset, 1, TRUE);

    offset += 1;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_seq, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_ack, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_cluster, tvb, offset, 2, TRUE);
    
    offset += 2;
    proto_tree_add_bitmask(tree, tvb, offset,
			   hf_rhcs4_cman_flags, ett_rhcs4_cman_flags,
			   b_rhcs4_cman_flags, TRUE);
    

    offset += 4;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_srcid, tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree,
			hf_rhcs4_cman_tgtid, tvb, offset, 4, TRUE);

    offset += 4;

  }

  return length;
}

void
proto_register_rhcs4_cman(void)
{
  module_t *rhcs4_cman_module;

  static hf_register_info hf[] = {
    { &hf_rhcs4_cman_tgtport,
      { "Target port", "rhcs4_cman.tgtport",
	FT_UINT8, BASE_DEC, VALS(vs_rhcs4_cman_port), 0x0,
	NULL, HFILL }},
    { &hf_rhcs4_cman_srcport,
      { "Source port", "rhcs4_cman.srcport",
	FT_UINT8, BASE_DEC, VALS(vs_rhcs4_cman_port), 0x0,
	NULL, HFILL }},
    { &hf_rhcs4_cman_seq,
      { "Packet sequence number", "rhcs4_cman.seq",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_rhcs4_cman_ack,
      { "Inline ACK", "rhcs4_cman.ack",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_rhcs4_cman_cluster,
      { "Cluster number", "rhcs4_cman.cluster",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_rhcs4_cman_flags,
      { "Flags", "rhcs4_cman.flags",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	NULL, HFILL }},

    { &hf_rhcs4_cman_flags_noack,
      { "Noack", "rhcs4_cman.flags.noack",
	FT_BOOLEAN, 32, NULL, FLAGS_NOACK,
	"Don't need an ACK for this message", HFILL }},
    { &hf_rhcs4_cman_flags_queue,
      { "Queue", "rhcs4_cman.flags.queue",
	FT_BOOLEAN, 32, NULL, FLAGS_QUEUE,
	"Queue the message for sending later", HFILL }},
    { &hf_rhcs4_cman_flags_multicast,
      { "Multicast", "rhcs4_cman.flags.multicast",
	FT_BOOLEAN, 32, NULL, FLAGS_MULTICAST,
	"Message was sent to all nodes in the cluster", HFILL }},
    { &hf_rhcs4_cman_flags_allint,
      { "All interfaces", "rhcs4_cman.flags.allint",
	FT_BOOLEAN, 32, NULL, FLAGS_ALLINT,
	"Send out of all interfaces", HFILL }},
    { &hf_rhcs4_cman_flags_replyexp,
      { "Reply expected", "rhcs4_cman.flags.replyexp",
	FT_BOOLEAN, 32, NULL, FLAGS_REPLYEXP,
	"Reply is expected", HFILL }},
    { &hf_rhcs4_cman_flags_bcastself,
      { "Broadcast self", "rhcs4_cman.flags.bcastself",
	FT_BOOLEAN, 32, NULL, FLAGS_BCASTSELF,
	"Broadcast message also gets send to us", HFILL }},

    { &hf_rhcs4_cman_srcid,
      { "Node ID of the sender", "rhcs4_cman.srcid",
	FT_INT32, BASE_DEC, NULL, 0x0,
	NULL, HFILL }},
    { &hf_rhcs4_cman_tgtid,
      { "Node ID of the target", "rhcs4_cman.tgtid",
	FT_INT32, BASE_DEC, VALS(vs_rhcs4_cman_tgtid), 0x0,
	NULL, HFILL }},
  };
  
  static gint *ett[] = {
    &ett_rhcs4_cman,
    &ett_rhcs4_cman_flags,
  };

  proto_rhcs4_cman = proto_register_protocol("Red Hat Cluster Suite 4 Cman protocol",
					     "RHCS4/Cman", "rhcs4_cman");
  proto_register_field_array(proto_rhcs4_cman, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  
  rhcs4_cman_module = prefs_register_protocol(proto_rhcs4_cman,
					      proto_reg_handoff_rhcs4_cman);
  
  prefs_register_uint_preference(rhcs4_cman_module, "udp.port",
                                 "UDP Port",
                                 "Set the UDP port for Cman protocol of Red Hat Cluster Suite 4",
                                 10,
                                 &rhcs4_cman_port);
}


void
proto_reg_handoff_rhcs4_cman(void)
{
  static gboolean register_dissector = FALSE;
  
  static int port = 0;

  static dissector_handle_t rhcs4_cman_handle;

  if (register_dissector) 
    {
      dissector_delete("udp.port", port, rhcs4_cman_handle);
    } 
  else 
    {
      rhcs4_cman_handle = new_create_dissector_handle(dissect_rhcs4_cman,
						      proto_rhcs4_cman);
      register_dissector = TRUE;
    }
                
  port  = rhcs4_cman_port;
  dissector_add("udp.port", port, rhcs4_cman_handle);
}

/* packet-rhcs4-cman.c ends here */
