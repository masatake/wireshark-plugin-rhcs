/* packet-ccsd.c
 *
 * Routines for ccsd dissection
 * Copyright 2009, Red Hat, Inc.
 * Copyright 2009, Masatake YAMATO <yamato@redhat.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* cman/2.0.84-2.el5/pre-build/cman-2.0.84/ccs/include/comm_headers.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"


/* Types of requests */
#define COMM_CONNECT    1
#define COMM_DISCONNECT 2
#define COMM_GET        3
#define COMM_GET_LIST   4
#define COMM_SET        5
#define COMM_GET_STATE  6
#define COMM_SET_STATE  7
#define COMM_BROADCAST  8
#define COMM_UPDATE     9

/* Request flags */
#define COMM_CONNECT_FORCE          1
#define COMM_CONNECT_BLOCKING       2
#define COMM_SET_STATE_RESET_QUERY  4
#define COMM_BROADCAST_FROM_QUORATE 8
#define COMM_UPDATE_NOTICE	    16
#define COMM_UPDATE_NOTICE_ACK	    32
#define COMM_UPDATE_COMMIT	    64
#define COMM_UPDATE_COMMIT_ACK	    128



static int proto_ccsd                = -1;
static int hf_ccsd_comm_type         = -1;
static int hf_ccsd_comm_flags        = -1;
static int hf_ccsd_comm_desc         = -1;
static int hf_ccsd_comm_error        = -1;
static int hf_ccsd_comm_payload_size = -1;

#define COMM_FLAGS(X) hf_ccsd_comm_flags_##X
static int COMM_FLAGS(connect_force) = -1;
static int COMM_FLAGS(connect_blocking) = -1;
static int COMM_FLAGS(set_state_reset_query) = -1;
static int COMM_FLAGS(broadcast_from_quorate) = -1;
static int COMM_FLAGS(update_notice) = -1;
static int COMM_FLAGS(update_notice_ack) = -1;
static int COMM_FLAGS(update_commit) = -1;
static int COMM_FLAGS(update_commit_ack) = -1;


static int hf_ccsd_xml = -1;

static gint ett_ccsd;
static gint ett_ccsd_comm_flags;

/* TODO: 50006 */
#define CCSD_BACKEND_PORT 50007
#define CCSD_BASE_PORT    50008

static guint ccsd_backend_port = CCSD_BACKEND_PORT;
static guint ccsd_base_port    = CCSD_BASE_PORT;

/* See also 50007
   /srv/sources/sources/c/cman/2.0.98-1.el5/pre-build/cman-2.0.98/ccs/daemon/cnx_mgr.c 
*/


dissector_handle_t xml_handle;

static const value_string vals_comm_type[] = {
  { COMM_CONNECT,    "Connect"    },
  { COMM_DISCONNECT, "Disconnect" },
  { COMM_GET,        "Get" },
  { COMM_GET_LIST,   "Get list" },
  { COMM_SET,        "Set" },
  { COMM_GET_STATE,  "Get state" },
  { COMM_SET_STATE,  "Set state" },
  { COMM_BROADCAST,  "Broadcast" },
  { COMM_UPDATE,     "Update" },
  { 0, NULL }
};

static const int *comm_flags_field[] = {
    &COMM_FLAGS(connect_force),
    &COMM_FLAGS(connect_blocking),
    &COMM_FLAGS(set_state_reset_query),
    &COMM_FLAGS(broadcast_from_quorate),
    &COMM_FLAGS(update_notice),
    &COMM_FLAGS(update_notice_ack),
    &COMM_FLAGS(update_commit),
    &COMM_FLAGS(update_commit_ack),
    NULL
};

static gboolean ccsd_desgment = TRUE;

#define RETURN(X) return

static void
dissect_ccsd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  gint  offset;
  guint  length;
  proto_item *item;
  proto_tree *tree;

  guint32 comm_type;
  guint32 comm_flags;
  guint32 payload_size;

  length = tvb_reported_length(tvb);
  comm_type    = tvb_get_letohl(tvb, 0);
  comm_flags   = tvb_get_letohl(tvb, + 4);
  payload_size = tvb_get_letohl(tvb, + 4 + 4 + 4 + 4);

  if (length < ( 4 * 5 ))
    return;

  if (comm_type == COMM_UPDATE && comm_flags == COMM_UPDATE_NOTICE)
    if (length < (( 4 * 5 ) + payload_size))
      THROW(ReportedBoundsError); 

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CCSD");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);
  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, 
		val_to_str(comm_type, vals_comm_type, "Unknown type "));

  if (parent_tree)
    {
      item = proto_tree_add_item(parent_tree, proto_ccsd, tvb, 0,
				 length, TRUE);
      tree = proto_item_add_subtree(item, ett_ccsd);

      
      offset = 0;
      
      offset += 0;
      proto_tree_add_item(tree, hf_ccsd_comm_type, tvb, offset,
			  4, TRUE);

      offset += 4;
      proto_tree_add_bitmask(tree, tvb, offset,
			     hf_ccsd_comm_flags, 
			     ett_ccsd_comm_flags,
			     comm_flags_field,
			     TRUE);

      offset += 4;
      proto_tree_add_item(tree, hf_ccsd_comm_desc, tvb, offset,
			  4, TRUE);
      
      offset += 4;
      proto_tree_add_item(tree, hf_ccsd_comm_error, tvb, offset,
			  4, TRUE);
      offset += 4;
      proto_tree_add_item(tree, hf_ccsd_comm_payload_size, tvb, offset,
			  4, TRUE);

      offset += 4;
      if ((comm_type == COMM_UPDATE && comm_flags == COMM_UPDATE_NOTICE)
	  || (comm_type == COMM_BROADCAST)
	  )
      {
	tvbuff_t* new_tvb;
	
	new_tvb = tvb_new_subset(tvb, offset, length - offset, payload_size);
	call_dissector(xml_handle, new_tvb, pinfo, tree);
	offset += payload_size;
      }
    }
}

static guint
get_ccsd_tcp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 comm_type;
  guint32 comm_flags;
  guint32 payload_size;
  guint   size;
  
  comm_type    = tvb_get_letohl(tvb, offset);
  comm_flags   = tvb_get_letohl(tvb, offset + 4);
  payload_size = tvb_get_letohl(tvb, offset + 4 + 4 + 4 + 4);

  if (comm_type == COMM_UPDATE && comm_flags == COMM_UPDATE_NOTICE) {
    size = ( 4 * 5 ) + payload_size;
  }
  else if ((COMM_CONNECT <= comm_type) && (comm_type <= COMM_UPDATE )) {
    size = ( 4 * 5 );
  }
  else
    size = tvb_length_remaining(tvb, offset); 

  return size;
}

static void
dissect_ccsd_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ccsd_desgment,
		   4 * 5, get_ccsd_tcp_pdu_len,
		   dissect_ccsd);
}

void
proto_register_ccsd (void)
{
  static hf_register_info hf[] = {
    { &hf_ccsd_comm_type,
      { "Type", "ccsd.comm_type", FT_INT32, BASE_DEC, VALS(vals_comm_type), 0x0,
	NULL, HFILL }},
    { &hf_ccsd_comm_flags,
      {"Flags", "ccsd.comm_flags", FT_UINT32, BASE_HEX, NULL, 0x0,
       NULL, HFILL }},
    { &hf_ccsd_comm_desc,
      {"Desc", "ccsd.comm_desc", FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},
    { &hf_ccsd_comm_error,
      {"Error", "ccsd.comm_error", FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},
    { &hf_ccsd_comm_payload_size,
      {"Payload size", "ccsd.comm_payload_size", FT_INT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL }},

    { &COMM_FLAGS(connect_force),
      {"Connect force", "ccsd.comm_flags.connect_force", 
       FT_BOOLEAN, 32, NULL, COMM_CONNECT_FORCE, NULL, HFILL }},
    { &COMM_FLAGS(connect_blocking),
      {"Blocking", "ccsd.comm_flags.connect_blocking", 
       FT_BOOLEAN, 32, NULL, COMM_CONNECT_BLOCKING, NULL, HFILL }},
    { &COMM_FLAGS(set_state_reset_query),
      {"Set state reset query", "ccsd.comm_flags.set_state_reset_query", 
       FT_BOOLEAN, 32, NULL, COMM_SET_STATE_RESET_QUERY, NULL, HFILL }},
    { &COMM_FLAGS(broadcast_from_quorate),
      {"Broadcast from quorate", "ccsd.comm_flags.broadcast_from_quorate", 
       FT_BOOLEAN, 32, NULL, COMM_BROADCAST_FROM_QUORATE, NULL, HFILL }},
    { &COMM_FLAGS(update_notice),
      {"Update notice", "ccsd.comm_flags.update_notice", 
       FT_BOOLEAN, 32, NULL, COMM_UPDATE_NOTICE, NULL, HFILL }},
    { &COMM_FLAGS(update_notice_ack),
      {"Update notice ack", "ccsd.comm_flags.update_notice_ack", 
       FT_BOOLEAN, 32, NULL, COMM_UPDATE_NOTICE_ACK, NULL, HFILL }},
    { &COMM_FLAGS(update_commit),
      {"Update commit", "ccsd.comm_flags.update_commit", 
       FT_BOOLEAN, 32, NULL, COMM_UPDATE_COMMIT, NULL, HFILL }},
    { &COMM_FLAGS(update_commit_ack),
      {"Update commit ack", "ccsd.comm_flags.update_commit_ack", 
       FT_BOOLEAN, 32, NULL, COMM_UPDATE_COMMIT_ACK, NULL, HFILL }},
    
    
    { &hf_ccsd_xml,
      { "XML", "ccsd.xml", FT_STRING, FT_NONE, NULL, 0x0,
	NULL, HFILL }},
  };
  
  static gint *ett[] = {
    &ett_ccsd,
    &ett_ccsd_comm_flags,
  };

  module_t * ccsd_module;


  proto_ccsd = proto_register_protocol ("Ccsd", "ccsd", "ccsd");
  proto_register_field_array (proto_ccsd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  ccsd_module = prefs_register_protocol(proto_ccsd, NULL);
  prefs_register_bool_preference(ccsd_module, "desegment",
				 "Reassemble ccsd communcation spanning multiple TCP segments",
				 "Whether the ccsd dissector should reassemble messages spanning multiple TCP segments."
				 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				 &ccsd_desgment);
}

void
proto_reg_handoff_ccsd (void)
{
  static gboolean dissector_registered = FALSE;

  static guint port;

  static dissector_handle_t ccsd_pdu_handle;
  static dissector_handle_t ccsd_handle;

  if (!dissector_registered) {
    ccsd_pdu_handle = create_dissector_handle(dissect_ccsd_pdu, proto_ccsd);
    ccsd_handle = create_dissector_handle(dissect_ccsd, proto_ccsd);
    xml_handle = find_dissector("xml");
    dissector_registered = TRUE;
  } else {
    dissector_delete("tcp.port",  port,  ccsd_pdu_handle);
    dissector_delete("udp.port",  port,  ccsd_handle);
  }

  port  = ccsd_base_port;
  dissector_add("tcp.port",  port,  ccsd_pdu_handle);

  port  = ccsd_backend_port;
  dissector_add("udp.port",  port,  ccsd_handle);
}
