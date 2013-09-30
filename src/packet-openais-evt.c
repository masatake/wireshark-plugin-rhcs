/* packet-openais-evt.c
 * Routines for dissecting protocol used in evt of OpenAIS
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

#include "packet-openais-a.h"
#include "packet-corosync-totempg.h"


#define OPENAIS_EVT_SERIVICE_TYPE 4

/* Forward declaration we need below */
void proto_reg_handoff_openais_evt(void);

#if 0
static guint32 openais_evt_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
#endif

/* Initialize the protocol and registered fields */
static int proto_openais_evt = -1;

/* Initialize the subtree pointers */
static gint ett_openais_evt                      = -1;


#define OPENAIS_EVT_FN_ID_REMOTE_EVT   0
#define OPENAIS_EVT_FN_ID_CHAN_OP      1
#define OPENAIS_EVT_FN_ID_RECOVERY_EVT 2


static const value_string vals_openais_evt_fn_id[] = {
	{ OPENAIS_EVT_FN_ID_REMOTE_EVT,   "remote-event"      },
	{ OPENAIS_EVT_FN_ID_CHAN_OP,      "channel-operation" },
	{ OPENAIS_EVT_FN_ID_RECOVERY_EVT, "recovery-event"    },
	{ 0,                              NULL                },
};


static int
dissect_openais_evt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	guint    length;
	int      offset;
	/* int      sub_length; */

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;

	guint16 fn_id;


	length = tvb_length(tvb);
	if (length < 1)		/* TODO */
		return 0;

	item = openais_a_get_service_item(pinfo);
	proto_item_append_text(item, " (%s)", "evt");

	item = openais_a_get_fn_id_item(pinfo);
	proto_item_append_text(item, " (%s)",
			       val_to_str(openais_a_get_fn_id(pinfo),
					  vals_openais_evt_fn_id,
					  "UNKNOWN"));

	/*
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPENAIS/evt");
	*/
	/* if (check_col(pinfo->cinfo, COL_INFO))
	   col_clear(pinfo->cinfo, COL_INFO); */

	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(evt");	
	fn_id = openais_a_get_fn_id(pinfo);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, 
				" :%s",
				val_to_str(fn_id, vals_openais_evt_fn_id,
					   "UNKNOWN"));

	little_endian = openais_a_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_evt, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_evt);

	offset += 0;

	switch (fn_id) {
	case OPENAIS_EVT_FN_ID_REMOTE_EVT:
		break;
	case OPENAIS_EVT_FN_ID_CHAN_OP:
		break;
	case OPENAIS_EVT_FN_ID_RECOVERY_EVT:
		break;
	}


	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_str(pinfo->cinfo, COL_INFO, ")");
	return tvb_length(tvb);
}


void
proto_register_openais_evt(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
	};

	static gint *ett[] = {
		&ett_openais_evt,
	};
  
	proto_openais_evt 
		= proto_register_protocol("evt protocol on \"a\" of OpenAIS",
					  "OPENAIS/evt", "openais_evt");

	proto_register_field_array(proto_openais_evt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_evt(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_evt_handle;

	if (register_dissector) {
		dissector_delete_uint("openais_a.header.id.service", 
				      OPENAIS_EVT_SERIVICE_TYPE, 
				      openais_evt_handle);
	} else {
		openais_evt_handle = new_create_dissector_handle(dissect_openais_evt,
								  proto_openais_evt);
		register_dissector = TRUE;
	}
	dissector_add_uint("openais_a.header.id.service", 
			   OPENAIS_EVT_SERIVICE_TYPE,
			   openais_evt_handle);
}

#if 0
static guint32
openais_evt_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
	return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}
#endif
/* packet-openais-evt.c ends here */
