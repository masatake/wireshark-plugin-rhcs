/* packet-groupd.c
 * Routines for dissecting protocol used between groupd daemon
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

#define GROUPD_MAX_NAMELEN (32)

#define GROUPD_MSG_APP_STOPPED        1
#define GROUPD_MSG_APP_STARTED        2
#define GROUPD_MSG_APP_RECOVER        3
#define GROUPD_MSG_APP_INTERNAL       4
#define GROUPD_MSG_GLOBAL_ID          5

#define GROUPD_EVENT_ID_TYPE_JOIN_BEGIN  1
#define GROUPD_EVENT_ID_TYPE_LEAVE_BEGIN 2
#define GROUPD_EVENT_ID_TYPE_FAIL_BEGIN  3


/* Forward declaration we need below */
void proto_reg_handoff_groupd(void);

/* Initialize the protocol and registered fields */
static int proto_groupd = -1;

/* fields for struct msg */
static int hf_groupd_msg_version_major  = -1;
static int hf_groupd_msg_version_minor  = -1;
static int hf_groupd_msg_version_patch  = -1;

static int hf_groupd_msg_type      = -1;
static int hf_groupd_msg_level     = -1;
static int hf_groupd_msg_length    = -1;

static int hf_groupd_msg_global_id = -1;
static int hf_groupd_msg_global_id_to_nodeid = -1;
static int hf_groupd_msg_global_id_counter   = -1;

static int hf_groupd_msg_event_id               = -1;
static int hf_groupd_msg_event_id_nodeid        = -1;
static int hf_groupd_msg_event_id_member_count  = -1;
static int hf_groupd_msg_event_id_type          = -1;


static int hf_groupd_msg_name      = -1;

/* Initialize the subtree pointers */
static int ett_groupd                = -1;
static int ett_groupd_msg_global_id  = -1;
static int ett_groupd_msg_event_id   = -1;


static const value_string vals_groupd_msg_type[] = {
	{ GROUPD_MSG_APP_STOPPED,  "stopped" },
	{ GROUPD_MSG_APP_STARTED,  "started" },
	{ GROUPD_MSG_APP_RECOVER,  "recover" },
	{ GROUPD_MSG_APP_INTERNAL, "internal"},
	{ GROUPD_MSG_GLOBAL_ID,    "global_id"},
	{0,   NULL }
};

static const value_string vals_openais_cpg_event_id_type[] = {
	{ GROUPD_EVENT_ID_TYPE_JOIN_BEGIN,  "join begin"  },
	{ GROUPD_EVENT_ID_TYPE_LEAVE_BEGIN, "leave begin" },
	{ GROUPD_EVENT_ID_TYPE_FAIL_BEGIN,  "fail begin"  },
	{ 0,                                NULL          },
};

static int
dissect_groupd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint    length;
	int      offset;
	/* int      sub_length; */

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;

	guint16     msg_type;



	length = tvb_length(tvb);
#define length_groupd ( (4 * 3) + 2 + 2 + 4 + 4 + 8 + GROUPD_MAX_NAMELEN )

	if (length < (length_groupd))
		return 0;

	/*
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "groupd");
	*/

	/*
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);
	*/
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "groupd");
	  
	if (!parent_tree)
		goto out;


	/*  */
	little_endian = TRUE;
	offset = 0;
	item = proto_tree_add_item(parent_tree, proto_groupd, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_groupd);

	/* TODO: Version check */
	offset += 0;
	proto_tree_add_item(tree,
			    hf_groupd_msg_version_major,
			    tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_groupd_msg_version_minor,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	proto_tree_add_item(tree,
			    hf_groupd_msg_version_patch,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_groupd_msg_type,
			    tvb, offset, 2, little_endian);
	msg_type = tvb_get_letohs(tvb, offset);
	

	offset += 2;
	proto_tree_add_item(tree,
			    hf_groupd_msg_level,
			    tvb, offset, 2, little_endian);

	offset += 2;
	proto_tree_add_item(tree,
			    hf_groupd_msg_length,
			    tvb, offset, 4, little_endian);
	
	offset += 4;
	{
		proto_item* sub_item;
		proto_tree* sub_tree;

		sub_item = proto_tree_add_item(tree,
					       hf_groupd_msg_global_id,
					       tvb, offset, 4, little_endian);

		sub_tree = proto_item_add_subtree(sub_item, ett_groupd_msg_global_id);
		if (msg_type != GROUPD_MSG_GLOBAL_ID) {
			proto_item_append_text(sub_item, " (may not be used)");
		}

		/* Dissect global_id
		   global_id & 0x0000FFFF => to_nodeid
		   ((global_id >> 16) & 0x0000FFFF) => counter */
		proto_tree_add_item(sub_tree,
				    hf_groupd_msg_global_id_to_nodeid,
				    tvb, offset, 2, little_endian);
		proto_tree_add_item(sub_tree,
				    hf_groupd_msg_global_id_counter,
				    tvb, offset + 2, 2, little_endian);
	}


	offset += 4;
	{
		proto_item* sub_item;
		proto_tree* sub_tree;

		
		sub_item = proto_tree_add_item(tree,
					       hf_groupd_msg_event_id,
					       tvb, offset, 8, little_endian);

		sub_tree = proto_item_add_subtree(sub_item, ett_groupd_msg_event_id);
		
		proto_tree_add_item(sub_tree,
				    hf_groupd_msg_event_id_type,
				    tvb, offset, 2, little_endian);
		proto_tree_add_item(sub_tree,
				    hf_groupd_msg_event_id_member_count,
				    tvb, offset + 2, 2, little_endian);
		proto_tree_add_item(sub_tree,
				    hf_groupd_msg_event_id_nodeid,
				    tvb, offset + 2 + 2, 4, little_endian);
	}

	offset += 8;
	proto_tree_add_item(tree,
			    hf_groupd_msg_name,
			    tvb, offset, GROUPD_MAX_NAMELEN, little_endian);

	offset += GROUPD_MAX_NAMELEN;

out:
	return length;
}

void
proto_register_groupd(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
		{ &hf_groupd_msg_version_major,
		  { "Major version", "groupd.version.major",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_version_minor,
		  { "Minor version", "groupd.version.minor",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_version_patch,
		  { "Patch version", "groupd.version.patch",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_groupd_msg_type,
		  { "Type", "groupd.type",
		    FT_UINT16, BASE_DEC, VALS(vals_groupd_msg_type), 0x0,
		    NULL, HFILL }},

		{ &hf_groupd_msg_level,
		  { "Level", "groupd.level",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_length,
		  { "Length", "groupd.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},



		{ &hf_groupd_msg_global_id,
		  { "Global id", "groupd.global_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_global_id_to_nodeid,
		  { "Node id", "groupd.global_id.to_nodeid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_global_id_counter,
		  { "Counter", "groupd.global_id.counter",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		
		{ &hf_groupd_msg_event_id,
		  { "Event id", "groupd.event_id",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_event_id_nodeid,
		  { "Node id", "groupd.event_id.nodeid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_event_id_member_count,
		  { "Member count", "groupd.event_id.member_count",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_groupd_msg_event_id_type,
		  { "Type", "groupd.event_id.type",
		    FT_UINT16, BASE_DEC, VALS(vals_openais_cpg_event_id_type), 0x0,
		    NULL, HFILL }},
		
		/* ??? */
		{ &hf_groupd_msg_name,
		  { "Name", "groupd.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_groupd,
		&ett_groupd_msg_global_id,
		&ett_groupd_msg_event_id,
	};
  
	proto_groupd 
		= proto_register_protocol("Protocol used between groupd daemon",
					  "GROUPD", "groupd");

	proto_register_field_array(proto_groupd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_groupd(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t groupd_handle;

	if (register_dissector) {
		dissector_delete_string("openais_cpg.mar_name.value", 
					"groupd", 
					groupd_handle);
	} else {
		groupd_handle = new_create_dissector_handle(dissect_groupd,
							    proto_groupd);
		register_dissector = TRUE;
	}
	dissector_add_string("openais_cpg.mar_name.value", 
			     "groupd", 
			     groupd_handle);
}

/* packet-groupd.c ends here */
