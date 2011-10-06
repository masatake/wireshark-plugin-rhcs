/* packet-openais-ckpt.c
 * Routines for dissecting protocol used in ckpt of OpenAIS
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


#define OPENAIS_CKPT_SERIVICE_TYPE 3

/* Forward declaration we need below */
void proto_reg_handoff_openais_ckpt(void);

#if 0
static guint32 openais_ckpt_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
#endif

/* Initialize the protocol and registered fields */
static int proto_openais_ckpt = -1;

/* Initialize the subtree pointers */
static gint ett_openais_ckpt = -1;


enum ckpt_message_req_types {
	MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN = 0,
	MESSAGE_REQ_EXEC_CKPT_CHECKPOINTCLOSE = 1,
	MESSAGE_REQ_EXEC_CKPT_CHECKPOINTUNLINK = 2,
	MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONSET = 3,
	MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONEXPIRE = 4,
	MESSAGE_REQ_EXEC_CKPT_SECTIONCREATE = 5,
	MESSAGE_REQ_EXEC_CKPT_SECTIONDELETE = 6,
	MESSAGE_REQ_EXEC_CKPT_SECTIONEXPIRATIONTIMESET = 7,
	MESSAGE_REQ_EXEC_CKPT_SECTIONWRITE = 8,
	MESSAGE_REQ_EXEC_CKPT_SECTIONOVERWRITE = 9,
	MESSAGE_REQ_EXEC_CKPT_SECTIONREAD = 10,
	MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT = 11,
	MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTSECTION = 12,
	MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTREFCOUNT = 13
};

static const value_string vals_openais_ckpt_fn_id[] = {
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN, "Checkpoint open" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTCLOSE, "Checkpoint close" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTUNLINK, "Checkpoint unlink" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONSET, "Checkpoint retention duration set" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONEXPIRE, "Checkpoint retention duration EXPIRE" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONCREATE, "Section create" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONDELETE, "Sectiond elete" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONEXPIRATIONTIMESET, "Section expiration timeset" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONWRITE, "Section write" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONOVERWRITE, "Section overwrite" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONREAD, "Section read" },
  { MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT, "Sync checkpoint" },
  { MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTSECTION, "Sync checkpoint section" },
  { MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTREFCOUNT, "Sync checkpoint refcount" },
  { 0,                              NULL                },
};


static int
dissect_openais_ckpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
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
	proto_item_append_text(item, " (%s)", "ckpt");

	item = openais_a_get_fn_id_item(pinfo);
	proto_item_append_text(item, " (%s)",
			       val_to_str(openais_a_get_fn_id(pinfo),
					  vals_openais_ckpt_fn_id,
					  "Unknown"));

	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(ckpt");	
	fn_id = openais_a_get_fn_id(pinfo);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, 
				" :%s",
				val_to_str(fn_id, vals_openais_ckpt_fn_id,
					   "Unknown"));

	little_endian = openais_a_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_ckpt, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_ckpt);

	offset += 0;

	switch (fn_id) {
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN:
		break;
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTCLOSE:
		break;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_str(pinfo->cinfo, COL_INFO, ")");
	return tvb_length(tvb);
}


void
proto_register_openais_ckpt(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
	};

	static gint *ett[] = {
		&ett_openais_ckpt,
	};
  
	proto_openais_ckpt 
		= proto_register_protocol("ckpt protocol on \"a\" of OpenAIS",
					  "OPENAIS/ckpt", "openais_ckpt");

	proto_register_field_array(proto_openais_ckpt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_ckpt(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_ckpt_handle;

	if (register_dissector) {
		dissector_delete("openais_a.header.id.service", 
				 OPENAIS_CKPT_SERIVICE_TYPE, 
				 openais_ckpt_handle);
	} else {
		openais_ckpt_handle = new_create_dissector_handle(dissect_openais_ckpt,
								  proto_openais_ckpt);
		register_dissector = TRUE;
	}
	dissector_add("openais_a.header.id.service", 
		      OPENAIS_CKPT_SERIVICE_TYPE,
		      openais_ckpt_handle);
}

#if 0
static guint32
openais_ckpt_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
	return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}
#endif
/* packet-openais-ckpt.c ends here */
