/* packet-openais-flowcontrol.c
 * Routines for dissecting protocol used in flowcontrol running on OpenAIS
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
#include "packet-openais-a.h"


#define	OPENAIS_FLOWCONTROL_STATE_DISABLED 0
#define	OPENAIS_FLOWCONTROL_STATE_ENABLED  1


#define OPENAIS_FLOWCONTROL_MAX_ID_LENGTH 1024



/* Forward declaration we need below */
void proto_reg_handoff_openais_flowcontrol(void);

static guint32 openais_flowcontrol_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);

/* Initialize the protocol and registered fields */
static int proto_openais_flowcontrol = -1;

/* fields for struct cl_protheader */
static int hf_openais_flowcontrol_service                    = -1;
static int hf_openais_flowcontrol_service_padding            = -1;
static int hf_openais_flowcontrol_id                         = -1;
static int hf_openais_flowcontrol_id_padding                 = -1;
static int hf_openais_flowcontrol_id_len                     = -1;
static int hf_openais_flowcontrol_id_len_padding             = -1;
static int hf_openais_flowcontrol_flow_control_state         = -1;
static int hf_openais_flowcontrol_flow_control_state_padding = -1;

/* Initialize the subtree pointers */
static gint ett_openais_flowcontrol                          = -1;


/* Value strings */
static const value_string vals_openais_flowcontrol_state[] = {
	{ OPENAIS_FLOWCONTROL_STATE_DISABLED, "Disabled" },
	{ OPENAIS_FLOWCONTROL_STATE_ENABLED,  "Enabled"  },
	{ 0,                                  NULL       }

};

static int
dissect_openais_flowcontrol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
        guint32  id_len;

	guint    length;
	int      offset;
	/* int      sub_length; */

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;



	length = tvb_length(tvb);
	if (length < (8 + OPENAIS_FLOWCONTROL_MAX_ID_LENGTH + 8 + 8))
	  return 0;

	/*
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPENAIS/flowcontrol");
	*/
	if (check_col(pinfo->cinfo, COL_INFO))
	  {
	    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "flowcontrol");
	    /* col_clear(pinfo->cinfo, COL_INFO); */
	  }

	  
	if (!parent_tree)
		goto out;


	little_endian = corosync_totempg_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_flowcontrol, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_flowcontrol);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_service,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_service_padding,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	
	{
	  offset += OPENAIS_FLOWCONTROL_MAX_ID_LENGTH;
	  id_len = openais_flowcontrol_get_guint32(tvb, offset, little_endian);
	  offset -= OPENAIS_FLOWCONTROL_MAX_ID_LENGTH;
	}
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_id,
			    tvb, offset, id_len, little_endian);

	offset += id_len;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_id_padding,
			    tvb, offset, OPENAIS_FLOWCONTROL_MAX_ID_LENGTH - id_len, little_endian);

	offset += OPENAIS_FLOWCONTROL_MAX_ID_LENGTH - id_len;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_id_len,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_id_len_padding,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_flow_control_state,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_flowcontrol_flow_control_state_padding,
			    tvb, offset, 4, little_endian);

	offset += 4;
out:
	return tvb_length(tvb);
}


void
proto_register_openais_flowcontrol(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
	  { &hf_openais_flowcontrol_service,
	    { "Service", "openais_flowcontrol.service",
	      FT_UINT32, BASE_DEC, VALS(vals_openais_a_service), 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_service_padding,
	    { "Padding", "openais_flowcontrol.service_padding",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_id,
	    { "Id", "openais_flowcontrol.id",
	      FT_STRING, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_id_padding,
	    { "Padding", "openais_flowcontrol.id_padding",
	      FT_BYTES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_id_len,
	    { "Id length", "openais_flowcontrol.id_len",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_id_len_padding,
	    { "Padding", "openais_flowcontrol.id_len_padding",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_flow_control_state,
	    { "State", "openais_flowcontrol.flow_control_state",
	      FT_UINT32, BASE_DEC, VALS(vals_openais_flowcontrol_state), 0x0,
	      NULL, HFILL }},
	  { &hf_openais_flowcontrol_flow_control_state_padding,
	    { "Padding", "openais_flowcontrol.flow_control_state_padding",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_openais_flowcontrol,
	};
  
	proto_openais_flowcontrol 
		= proto_register_protocol("Protocol used in flowcontrol group running on OpenAIS",
					  "OPENAIS/FLOWCONTROL", "openais_flowcontrol");

	proto_register_field_array(proto_openais_flowcontrol, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_flowcontrol(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_flowcontrol_handle;

	if (register_dissector) {
		dissector_delete_string("corosync_totempg.group_name", "flowcontrol", openais_flowcontrol_handle);
	} else {
		openais_flowcontrol_handle = new_create_dissector_handle(dissect_openais_flowcontrol,
								  proto_openais_flowcontrol);
		register_dissector = TRUE;
	}
	dissector_add_string("corosync_totempg.group_name", "flowcontrol", openais_flowcontrol_handle);
}


static guint32
openais_flowcontrol_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
	return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}

/* packet-openais-flowcontrol.c ends here */
