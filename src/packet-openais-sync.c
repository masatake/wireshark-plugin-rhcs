/* packet-openais-sync.c
 * Routines for dissecting protocol used in sync running on OpenAIS
 * Copyright 2008, Masatake YAMATO <yamato@redhat.com>
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

#include "packet-corosync-totemsrp.h"
#include "packet-corosync-totempg.h"


/* Forward declaration we need below */
void proto_reg_handoff_openais_sync(void);

#if 0
static guint32 openais_sync_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
#endif 

/* Initialize the protocol and registered fields */
static int proto_openais_sync = -1;

/* fields for struct cl_protheader */
static int hf_openais_sync_header                 = -1;
static int hf_openais_sync_header_size            = -1;
static int hf_openais_sync_header_size_padding    = -1;
static int hf_openais_sync_header_id              = -1;
static int hf_openais_sync_header_id_padding      = -1;

static int hf_openais_sync_padding                = -1;

/* Initialize the subtree pointers */
static gint ett_openais_sync                      = -1;
static gint ett_openais_sync_header               = -1;


#define  OPENAIS_SYNC_MESSAGE_REQ_SYNC_BARRIER 0
static const value_string vals_header_id[] = {
  {OPENAIS_SYNC_MESSAGE_REQ_SYNC_BARRIER, "Sync barrier request" },
  {0, NULL}
};
static int
dissect_openais_sync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint    length;
	int      offset;
	int      sub_length;

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;


	length = tvb_length(tvb);
	if (length < (corosync_totempg_dissect_mar_req_header_length
		      + corosync_totemsrp_memb_ring_id_length))
	  return 0;

	/*
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPENAIS/sync");
	*/
	if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "sync");
	  /* col_clear(pinfo->cinfo, COL_INFO); */
	}

	  
	if (!parent_tree)
		goto out;


	little_endian = corosync_totempg_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_sync, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_sync);

	offset += 0;
	sub_length = corosync_totempg_dissect_mar_req_header(tvb,
							     pinfo,
							     tree,
							     length, 
							     offset,
							     hf_openais_sync_header, ett_openais_sync_header,
							     hf_openais_sync_header_size, hf_openais_sync_header_size_padding,
							     hf_openais_sync_header_id, hf_openais_sync_header_id_padding,
							     little_endian,
							     NULL, NULL,
							     NULL, NULL);
	if (sub_length != corosync_totempg_dissect_mar_req_header_length)
	    goto out;
	
	offset += sub_length;
	sub_length = corosync_totemsrp_dissect_memb_ring_id(tvb, pinfo, tree, length, offset);
	
	offset += sub_length;
	proto_tree_add_item(tree, hf_openais_sync_padding, tvb,
			    offset, 2, little_endian);

	offset += 2;
out:
	return tvb_length(tvb);
}


void
proto_register_openais_sync(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
		{ &hf_openais_sync_header,
		  { "Header", "openais_sync.header",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_sync_header_size,
		  { "Size", "openais_sync.header.size",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_sync_header_size_padding,
		  { "Padding", "openais_sync.header.size_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_sync_header_id,
		  { "Id", "openais_sync.header.id",
		    FT_INT32, BASE_DEC, VALS(vals_header_id), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_sync_header_id_padding,
		  { "Padding", "openais_sync.header.id_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_sync_padding,
		  { "Padding", "openais_sync.padding",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_openais_sync,
		&ett_openais_sync_header,
	};
  
	proto_openais_sync 
		= proto_register_protocol("Protocol used in sync group running on OpenAIS",
					  "OPENAIS/SYNC", "openais_sync");

	proto_register_field_array(proto_openais_sync, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_sync(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_sync_handle;

	if (register_dissector) {
		dissector_delete_string("corosync_totempg.group_name", "sync", openais_sync_handle);
	} else {
		openais_sync_handle = new_create_dissector_handle(dissect_openais_sync,
								  proto_openais_sync);
		register_dissector = TRUE;
	}
	dissector_add_string("corosync_totempg.group_name", "sync", openais_sync_handle);
}


#if 0
static guint32
openais_sync_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
	return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}
#endif

/* packet-openais-sync.c ends here */
