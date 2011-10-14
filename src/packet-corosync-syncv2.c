/* packet-openais-syncv2.c
 * Routines for dissecting protocol used in syncv2 running on corosync
 * Copyright 2011, Masatake YAMATO <yamato@redhat.com>
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
void proto_reg_handoff_corosync_syncv2(void);

/* Initialize the protocol and registered fields */
static int proto_corosync_syncv2 = -1;

/* fields for struct cl_protheader */
static int hf_corosync_syncv2_header                 = -1;
static int hf_corosync_syncv2_header_size            = -1;
static int hf_corosync_syncv2_header_size_padding    = -1;
static int hf_corosync_syncv2_header_id              = -1;
static int hf_corosync_syncv2_header_id_padding      = -1;

static int hf_corosync_syncv2_padding                = -1;

static int hf_corosync_syncv2_service_list_entries           = -1;
static int hf_corosync_syncv2_service_list_entries_padding   = -1;
static int hf_corosync_syncv2_service_list_entry = -1;
static int hf_corosync_syncv2_service_list_entry_padding = -1;

/* Initialize the subtree pointers */
static gint ett_corosync_syncv2                      = -1;
static gint ett_corosync_syncv2_header               = -1;

#define MESSAGE_REQ_SYNC_BARRIER 0
#define MESSAGE_REQ_SYNC_SERVICE_BUILD 1
#define MESSAGE_REQ_SYNC_MEMB_DETERMINE 2

static const value_string vals_header_id[] = {
  { MESSAGE_REQ_SYNC_BARRIER, "barrier" },
  { MESSAGE_REQ_SYNC_SERVICE_BUILD, "service-build" },
  { MESSAGE_REQ_SYNC_MEMB_DETERMINE, "member-determine" },
  { 0, NULL }
};


static int
dissect_corosync_syncv2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint    length;
	int      offset;
	int      sub_length;

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;

	gint32 header_id;


	length = tvb_length(tvb);
	if (length < (corosync_totempg_dissect_mar_req_header_length
		      + corosync_totemsrp_memb_ring_id_length 
		      + 2))
	  
	  return 0;

	/*
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "COROSYNC/syncv2");
	*/
	if (check_col(pinfo->cinfo, COL_INFO)) {
	  col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "syncv2");
	  /* col_clear(pinfo->cinfo, COL_INFO); */
	}

	  
	if (!parent_tree)
		goto out;


	little_endian = corosync_totempg_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_corosync_syncv2, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_corosync_syncv2);

	offset += 0;
	sub_length = corosync_totempg_dissect_mar_req_header(tvb,
							     pinfo,
							     tree,
							     length, 
							     offset,
							     hf_corosync_syncv2_header, ett_corosync_syncv2_header,
							     hf_corosync_syncv2_header_size, hf_corosync_syncv2_header_size_padding,
							     hf_corosync_syncv2_header_id, hf_corosync_syncv2_header_id_padding,
							     little_endian,
							     NULL, &header_id,
							     NULL, NULL);
	if (sub_length != corosync_totempg_dissect_mar_req_header_length)
	    goto out;

	offset += sub_length;
	sub_length = corosync_totemsrp_dissect_memb_ring_id(tvb, pinfo, tree, length, offset);
	
	offset += sub_length;
	proto_tree_add_item(tree, hf_corosync_syncv2_padding, tvb,
			    offset, 2, little_endian);

	offset += 2;
	if (check_col(pinfo->cinfo, COL_INFO))
	  {
	    const char* strval;
	    strval = match_strval(header_id, vals_header_id);
	    if (strval)
	      col_append_sep_str(pinfo->cinfo, COL_INFO, "/", strval);
	  }

	if (header_id == MESSAGE_REQ_SYNC_SERVICE_BUILD)
	  {
	    int i;
	    gint padding_len;
	    union {
	      guint32 u;
	      gint32  i;
	    } service_list_entries;

	    if ( (length - offset) < 8 )
	      goto out;
	    
	    proto_tree_add_item(tree, hf_corosync_syncv2_service_list_entries, tvb,
				offset, 4, little_endian);
	    service_list_entries.u = (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);

	    offset += 4;
	    proto_tree_add_item(tree, hf_corosync_syncv2_service_list_entries_padding, tvb,
				offset, 4, little_endian);
	    offset += 4;

	    for (i = 0; i < service_list_entries.i; i++)
	      {
		if ( (length - offset) < 4 )
		  goto out;
		proto_tree_add_item(tree, hf_corosync_syncv2_service_list_entry, tvb,
				    offset, 4, little_endian);
		offset += 4;
	      }

	    padding_len = (length - offset);
	    if (padding_len != 0)
	      {
		proto_tree_add_item (tree,
				     hf_corosync_syncv2_service_list_entry_padding,
				     tvb, offset, padding_len, FALSE);
		offset += padding_len;
	      }
	  }
out:
	return tvb_length(tvb);
}


void
proto_register_corosync_syncv2(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {

		{ &hf_corosync_syncv2_header,
		  { "Header", "corosync_syncv2.header",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_header_size,
		  { "Size", "corosync_syncv2.header.size",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_header_size_padding,
		  { "Padding", "corosync_syncv2.header.size_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_header_id,
		  { "Id", "corosync_syncv2.header.id",
		    FT_INT32, BASE_DEC, VALS(vals_header_id), 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_header_id_padding,
		  { "Padding", "corosync_syncv2.header.id_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_padding,
		  { "Padding", "corosync_syncv2.padding",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_service_list_entries,
		  { "The number of serivice list entries", "corosync_syncv2.service_list.entries",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_service_list_entries_padding,
		  { "Padding", "corosync_syncv2.service_list.entries.entries_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_service_list_entry,
		  { "Serivice list entry", "corosync_syncv2.service_list.entry",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_corosync_syncv2_service_list_entry_padding,
		  { "Service list padding", "corosync_syncv2.service_list.entry_padding",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_corosync_syncv2,
		&ett_corosync_syncv2_header,
	};
  
	proto_corosync_syncv2 
		= proto_register_protocol("Protocol used in syncv2 group running on Corosync",
					  "COROSYNC/SYNCV2", "corosync_syncv2");

	proto_register_field_array(proto_corosync_syncv2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_corosync_syncv2(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t corosync_syncv2_handle;

	if (register_dissector) {
		dissector_delete_string("corosync_totempg.group_name", "syncv2", corosync_syncv2_handle);
	} else {
		corosync_syncv2_handle = new_create_dissector_handle(dissect_corosync_syncv2,
								     proto_corosync_syncv2);
		register_dissector = TRUE;
	}
	dissector_add_string("corosync_totempg.group_name", "syncv2", corosync_syncv2_handle);
}

/* packet-corosync-syncv2.c ends here */
