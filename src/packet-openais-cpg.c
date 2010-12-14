/* packet-openais-cpg.c
 * Routines for dissecting protocol used in cpg of OpenAIS
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
#include <stdio.h>

#include <epan/packet.h>

#include "packet-openais-a.h"
#include "packet-corosync-totempg.h"


#define OPENAIS_CPG_SERIVICE_TYPE 8
/* Forward declaration we need below */
void proto_reg_handoff_openais_cpg(void);

static guint32 openais_cpg_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);

/* Initialize the protocol and registered fields */
static int proto_openais_cpg = -1;

/* common fields */
static int hf_openais_cpg_pid                          = -1;
static int hf_openais_cpg_pid_padding                  = -1;

/* fields for street req_exec_cpg_procjoin */
static int hf_openais_cpg_procjoin                     = -1;
static int hf_openais_cpg_procjoin_reason              = -1;
static int hf_openais_cpg_procjoin_reason_padding      = -1;

static int hf_openais_cpg_procleave                    = -1;
/* other fiels are shared with procjoin */


static int hf_openais_cpg_joinlist                     = -1;
/* fields for struct mar_res_header_t */
static int hf_openais_cpg_joinlist_error               = -1;
static int hf_openais_cpg_joinlist_error_padding       = -1;
static int hf_openais_cpg_joinlist_entry               = -1;
static int hf_openais_cpg_joinlist_entry_pid           = -1;
static int hf_openais_cpg_joinlist_entry_pid_padding   = -1;

/* fields for struct req_exec_cpg_mcast */
static int hf_openais_cpg_mcast                        = -1;
static int hf_openais_cpg_mcast_msglen                 = -1;
static int hf_openais_cpg_mcast_msglen_padding         = -1;

/* fields for struct req_exec_cpg_downlist */
static int hf_openais_cpg_downlist                     = -1;
static int hf_openais_cpg_downlist_left_nodes          = -1;
static int hf_openais_cpg_downlist_left_nodes_padding  = -1;
static int hf_openais_cpg_downlist_nodeids             = -1;

/* fields for struct mar_cpg_name */
static int hf_openais_cpg_mar_name                     = -1;
static int hf_openais_cpg_mar_name_length              = -1;
static int hf_openais_cpg_mar_name_length_padding      = -1;
static int hf_openais_cpg_mar_name_value               = -1;
static int hf_openais_cpg_mar_name_value_padding       = -1;

/* fields of for struct mar_message_source */
static int hf_openais_cpg_mar_message_source           = -1;
static int hf_openais_cpg_mar_message_source_nodeid    = -1;
static int hf_openais_cpg_mar_message_source_nodeid_padding = -1;
static int hf_openais_cpg_mar_message_source_conn      = -1;


/* Initialize the subtree pointers */
static gint ett_openais_cpg                      = -1;
static gint ett_openais_cpg_procjoin             = -1;
static gint ett_openais_cpg_procleave            = -1;
static gint ett_openais_cpg_joinlist             = -1;
static gint ett_openais_cpg_joinlist_entry       = -1;
static gint ett_openais_cpg_mcast                = -1;
static gint ett_openais_cpg_mar_name             = -1;
static gint ett_openais_cpg_mar_message_source   = -1;
static gint ett_openais_cpg_downlist             = -1;



#define OPENAIS_CPG_MAX_NAME_LENGTH  128


#define OPENAIS_CPG_FN_ID_PROCJOIN   0
#define OPENAIS_CPG_FN_ID_PROCLEAVE  1
#define OPENAIS_CPG_FN_ID_JOINLIT    2
#define OPENAIS_CPG_FN_ID_MCAST      3
#define OPENAIS_CPG_FN_ID_DOWNLIST   4


/*  Taken from `enum lib_cpg_confchg_reason' 
    of openais-0.80.3/include/ipc_cpg.h 
    
    Prefixes are rearranged. */
#define OPENAIS_CPG_CONFCHG_REASON_JOIN      1
#define OPENAIS_CPG_CONFCHG_REASON_LEAVE     2
#define OPENAIS_CPG_CONFCHG_REASON_NODEDOWN  3
#define OPENAIS_CPG_CONFCHG_REASON_NODEUP    4
#define	OPENAIS_CPG_CONFCHG_REASON_PROCDOWN  5

/* Taken form openais-0.80.3/exec/totem.h
   Prefixes are rearranged */

#define OPENAIS_CPG_PROCESSOR_COUNT_MAX       384

static const value_string vals_openais_cpg_fn_id[] = {
	{ OPENAIS_CPG_FN_ID_PROCJOIN,   "PROCJOIN"  },
	{ OPENAIS_CPG_FN_ID_PROCLEAVE,  "PROCLEAVE" },
	{ OPENAIS_CPG_FN_ID_JOINLIT,    "JOINLIST" },
	{ OPENAIS_CPG_FN_ID_MCAST,      "MCAST"     },
	{ OPENAIS_CPG_FN_ID_DOWNLIST,   "DOWNLIST"  },

	{ 0,                            NULL        },
};


static const value_string vals_openais_cpg_confchg_reason[] = {
	{ OPENAIS_CPG_CONFCHG_REASON_JOIN,     "JOIN"      },
	{ OPENAIS_CPG_CONFCHG_REASON_LEAVE,    "LEAVE"     },
	{ OPENAIS_CPG_CONFCHG_REASON_NODEDOWN, "NODE DOWN" },
	{ OPENAIS_CPG_CONFCHG_REASON_NODEUP,   "NDOE UP"   },
	{ OPENAIS_CPG_CONFCHG_REASON_PROCDOWN, "PROC DOWN" },

	{ 0,                            NULL        },
};


static dissector_table_t subdissector_table;


static int
dissect_openais_cpg_mar_message_source(tvbuff_t    *tvb,
				       packet_info *pinfo, 
				       proto_tree  *parent_tree,
				       guint length, int offset,
				       gboolean little_endian)
{
	int original_offset;
	proto_tree *tree;
	proto_item *item;

#define length_openais_cpg_mar_source ( 8 + 8 )
	if ((length - offset) < length_openais_cpg_mar_source)
		return 0;
	
	original_offset = offset;

	item = proto_tree_add_item(parent_tree, hf_openais_cpg_mar_message_source, 
				   tvb, offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg_mar_message_source);

	
	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_message_source_nodeid,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_message_source_nodeid_padding,
			    tvb, offset, 4, little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_message_source_conn,
			    tvb, offset, 8, little_endian);
	offset += 8;
	
	return (offset - original_offset);

	pinfo = pinfo;
}



static int
dissect_openais_cpg_mar_name(tvbuff_t *tvb,
			     packet_info *pinfo, 
			     proto_tree *parent_tree,
			     guint length, int offset,
			     gboolean little_endian,
			     gchar** group_name)
{
	int original_offset;

	proto_tree *tree;
	proto_item *item;

	guint name_length;



#define length_openais_cpg_mar_name ( 8 + OPENAIS_CPG_MAX_NAME_LENGTH )
	if ((length - offset) < length_openais_cpg_mar_name)
		return 0;

	original_offset = offset;

	item = proto_tree_add_item(parent_tree, hf_openais_cpg_mar_name, 
				   tvb, offset, length_openais_cpg_mar_name, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg_mar_name);

	
	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_name_length,
			    tvb, offset, 4, little_endian);
	name_length = openais_cpg_get_guint32(tvb, offset, little_endian);


	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_name_length_padding,
			    tvb, offset, 4, little_endian);


	offset += 4;
	if (name_length > OPENAIS_CPG_MAX_NAME_LENGTH) {
		/* TODO: Broken packet */
		name_length = OPENAIS_CPG_MAX_NAME_LENGTH;
	}
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_name_value,
			    tvb, offset, name_length, little_endian);
	if (group_name)
		*group_name = tvb_format_stringzpad(tvb, offset, name_length);
	
	offset += name_length;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mar_name_value_padding,
			    tvb, 
			    offset, (OPENAIS_CPG_MAX_NAME_LENGTH - name_length), 
			    little_endian);

	offset += (OPENAIS_CPG_MAX_NAME_LENGTH - name_length);
	
	return (offset - original_offset);

	pinfo = pinfo;
}


static int
dissect_openais_cpg_proc_generic(tvbuff_t *tvb,
				 packet_info *pinfo, 
				 proto_tree *parent_tree,
				 proto_item *parent_item,
				 guint length, int offset,
				 gboolean little_endian,
				 int hf, int ett)
{
	int sub_offset;
	int original_offset;

	proto_tree* tree;
	proto_item* item;

	gchar*  group_name;


#define length_openais_cpg_procjoin ( length_openais_cpg_mar_name	\
				      + 8				\
				      + 8                               )
	
	
	if ((length - offset) < length_openais_cpg_procjoin)
		return 0;
	original_offset = offset;

	item = proto_tree_add_item(parent_tree, 
				   hf, 
				   tvb, offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett);

	offset += 0;

	/* Don't confuse.
	   mar req header is already dissected by lower layer. */
	sub_offset = dissect_openais_cpg_mar_name(tvb, pinfo, 
						  tree, 
						  length, offset,
						  little_endian,
						  &group_name);
	proto_item_append_text(item, " (group: %s)", group_name);


	offset += sub_offset;
	proto_tree_add_item(tree,
			    hf_openais_cpg_pid,
			    tvb, 
			    offset, 4, 
			    little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_pid_padding,
			    tvb, 
			    offset, 4, 
			    little_endian);
	
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_procjoin_reason,
			    tvb, 
			    offset, 4, 
			    little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_procjoin_reason_padding,
			    tvb, 
			    offset, 4, 
			    little_endian);
	offset += 4;

	
	return (offset - original_offset);

	parent_item = parent_item;
}

static int
dissect_openais_cpg_procjoin(tvbuff_t *tvb,
			     packet_info *pinfo, 
			     proto_tree *parent_tree,
			     proto_item *parent_item,
			     guint length, int offset,
			     gboolean little_endian)
{
	return dissect_openais_cpg_proc_generic(tvb, pinfo,
						parent_tree, parent_item,
						length, offset,
						little_endian,
						hf_openais_cpg_procjoin, 
						ett_openais_cpg_procjoin);
}

static int
dissect_openais_cpg_procleave(tvbuff_t *tvb,
			      packet_info *pinfo, 
			      proto_tree *parent_tree,
			      proto_item *parent_item,
			      guint length, int offset,
			      gboolean little_endian)
{
	return dissect_openais_cpg_proc_generic(tvb, pinfo,
						parent_tree, parent_item,
						length, offset,
						little_endian,
						hf_openais_cpg_procleave, 
						ett_openais_cpg_procleave);
}

static int
dissect_openais_cpg_joinlist_entry(tvbuff_t *tvb,
				   packet_info *pinfo, 
				   proto_tree *parent_tree,
				   proto_item *parent_item,
				   guint length, int offset,
				   gboolean little_endian)
{
	int sub_offset;
	int original_offset;

	proto_tree *tree;
	proto_item *item;

#define length_openais_cpg_joinlist_entry ( 4 + 4 + length_openais_cpg_mar_name )
	if ((length - offset) < length_openais_cpg_mar_name)
		return 0;

	original_offset = offset;
	
	item = proto_tree_add_item(parent_tree, 
				   hf_openais_cpg_joinlist_entry,
				   tvb, offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg_joinlist_entry);

	
	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cpg_joinlist_entry_pid,
			    tvb, offset, 4, little_endian);
	/* mar_cpg_name_t field in join_list_entry is aligned to 8,
	   so maybe 4 octet padding is here. */
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_joinlist_entry_pid_padding,
			    tvb, offset, 4, little_endian);

	offset += 4;
	sub_offset = dissect_openais_cpg_mar_name(tvb, 
						  pinfo,
						  tree, 
						  length, offset,
						  little_endian,
						  NULL);

	offset += sub_offset;
	return (offset - original_offset);

	parent_item = parent_item;
}


static int
dissect_openais_cpg_joinlist(tvbuff_t *tvb,
			     packet_info *pinfo, 
			     proto_tree *parent_tree,
			     proto_item *parent_item,
			     guint length, int offset,
			     gboolean little_endian)
{
	gint32 size;
	int original_offset;


	proto_tree* tree;
	proto_item* item;

	size = openais_a_get_size(pinfo);

#define length_openais_cpg_joinlist   ((guint)(((size - (2 * 8)) > 8)? (size - (2 * 8)): 8))
	
	
	if ((length - offset) < length_openais_cpg_joinlist) {
		return 0;
	}

	original_offset = offset;

	item = proto_tree_add_item(parent_tree,
				   hf_openais_cpg_joinlist,
				   tvb, offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg_joinlist);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cpg_joinlist_error,
			    tvb, 
			    offset, 4, 
			    little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_joinlist_error_padding,
			    tvb, 
			    offset, 4, 
			    little_endian);

	offset += 4;
	while ((length - offset) < length_openais_cpg_joinlist) {
		int sub_offset;

		
		sub_offset 
			= dissect_openais_cpg_joinlist_entry(tvb, pinfo,
							     parent_tree, parent_item,
							     length, offset,
							     little_endian);
		if (sub_offset == 0)
			break;

		offset += sub_offset;
	}
	
	return (offset - original_offset);

	parent_item = parent_item;
}

static int
dissect_openais_cpg_mcast(tvbuff_t *tvb,
			  packet_info *pinfo, 
			  proto_tree *parent_tree,
			  proto_item *parent_item,
			  guint length, int offset,
			  gboolean little_endian)
{
	int sub_offset;
	int original_offset;

	proto_tree* tree;
	proto_item* item;

	gchar*  group_name;
	guint32 msglen;


#define length_openais_cpg_mcast ( length_openais_cpg_mar_name         \
				  + 8                                  \
				  + 8                                  \
				  + length_openais_cpg_mar_source      )
	
	
	if ((length - offset) < length_openais_cpg_mcast)
		return 0;
	original_offset = offset;

	item = proto_tree_add_item(parent_tree, 
				   hf_openais_cpg_mcast, 
				   tvb, offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg_mcast);

	offset += 0;

	/* Don't confuse.
	   mar req header is already dissected by lower layer. */
	sub_offset = dissect_openais_cpg_mar_name(tvb, pinfo, 
						  tree, 
						  length, offset,
						  little_endian,
						  &group_name);
	proto_item_append_text(item, " (group: %s)", group_name);


	offset += sub_offset;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mcast_msglen,
			    tvb, 
			    offset, 4, 
			    little_endian);
	msglen = openais_cpg_get_guint32(tvb, offset, little_endian);

	
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_mcast_msglen_padding,
			    tvb, 
			    offset, 4, 
			    little_endian);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_pid,
			    tvb, 
			    offset, 4, 
			    little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_pid_padding,
			    tvb, 
			    offset, 4, 
			    little_endian);
	
	offset += 4;
	sub_offset = dissect_openais_cpg_mar_message_source(tvb, pinfo, 
							    tree,
							    length, offset,
							    little_endian);
	offset += sub_offset;
	if ((length - offset) < msglen)
		goto out;

	
	{
		tvbuff_t *next_tvb;


		next_tvb = tvb_new_subset(tvb, offset, msglen, msglen);

		dissector_try_string(subdissector_table,
				     group_name, next_tvb, pinfo, tree);

		offset += msglen;
	}
out:
	return (offset - original_offset);

	parent_item = parent_item;
}

static int
dissect_openais_cpg_downlist(tvbuff_t *tvb,
			     packet_info *pinfo, 
			     proto_tree *parent_tree,
			     proto_item *parent_item,
			     guint length, int offset,
			     gboolean little_endian)
{
	int original_offset;


	proto_tree* tree;
	proto_item* item;

	guint32 left_nodes;

#define length_openais_cpg_downlist   ( 4 + 4 )
	
	
	if ((length - offset) < length_openais_cpg_downlist) {
		fprintf(stderr, "%u < %u\n", 
			(length - offset),
			length_openais_cpg_downlist);
		return 0;
	}

	original_offset = offset;

	item = proto_tree_add_item(parent_tree,
				   hf_openais_cpg_downlist,
				   tvb, offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg_downlist);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_openais_cpg_downlist_left_nodes,
			    tvb, 
			    offset, 4, 
			    little_endian);
	left_nodes = openais_cpg_get_guint32(tvb, offset, little_endian);
	if (left_nodes > OPENAIS_CPG_PROCESSOR_COUNT_MAX) {
		/* TODO: Broken packet */
		left_nodes = OPENAIS_CPG_PROCESSOR_COUNT_MAX;
	}

	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_cpg_downlist_left_nodes_padding,
			    tvb, 
			    offset, 4, 
			    little_endian);
	

	offset += 4;
	if ((length - offset) < (left_nodes * 4))
		goto out;

	/* TODO: About padding, fragmentation, and guint32 blocks */
	proto_tree_add_item(tree,
			    hf_openais_cpg_downlist_nodeids,
			    tvb, 
			    offset, (left_nodes * 4), 
			    little_endian);
	
	offset += (left_nodes * 4);
out:
	return (offset - original_offset);

	parent_item = parent_item;
	pinfo = pinfo;;
}

static int
dissect_openais_cpg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint    length;
	int      offset;
	int      sub_length;

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;

	guint16 fn_id;


	length = tvb_length(tvb);
	
	item = openais_a_get_service_item(pinfo);
	proto_item_append_text(item, " (%s)", "cpg");

	item = openais_a_get_fn_id_item(pinfo);
	proto_item_append_text(item, " (%s)",
			       val_to_str(openais_a_get_fn_id(pinfo),
					  vals_openais_cpg_fn_id,
					  "Unknown"));


	/* if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPENAIS/cpg"); */
	
	/*  
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);
	*/

	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(cpg");	
	fn_id = openais_a_get_fn_id(pinfo);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, 
				" :%s",
				val_to_str(fn_id, vals_openais_cpg_fn_id,
					   "Unknown"));

	little_endian = openais_a_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_cpg, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_cpg);

	offset += 0;

	switch (fn_id) {
	case OPENAIS_CPG_FN_ID_PROCJOIN:
		sub_length = dissect_openais_cpg_procjoin(tvb, pinfo,
							  tree, item,
							  length, offset, little_endian);
		break;
	case OPENAIS_CPG_FN_ID_PROCLEAVE:
		sub_length = dissect_openais_cpg_procleave(tvb, pinfo,
							   tree, item,
							   length, offset, little_endian);
		break;
	case OPENAIS_CPG_FN_ID_JOINLIT:
		sub_length = dissect_openais_cpg_joinlist(tvb, pinfo,
							  tree, item,
							  length, offset, little_endian);
		break;
	case OPENAIS_CPG_FN_ID_MCAST:
		sub_length = dissect_openais_cpg_mcast(tvb, pinfo, 
						       tree, item, 
						       length, offset, little_endian);
		break;
	case OPENAIS_CPG_FN_ID_DOWNLIST:
		sub_length = dissect_openais_cpg_downlist(tvb, pinfo, 
							  tree, item, 
							  length, offset, little_endian);
		break;
	}
	  

	if (check_col(pinfo->cinfo, COL_INFO))
	       col_append_str(pinfo->cinfo, COL_INFO, ")");	
	return tvb_length(tvb);
}


void
proto_register_openais_cpg(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
		{ &hf_openais_cpg_procjoin,
		  { "Proc join", "openais_cpg.procjoin",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_procjoin_reason,
		  { "Reason", "openais_cpg.procjoin.reason",
		    FT_UINT32, BASE_DEC, VALS(vals_openais_cpg_confchg_reason), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_procjoin_reason_padding,
		  { "Padding", "openais_cpg.procjoin.reason_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		
		{ &hf_openais_cpg_procleave,
		  { "Proc leave", "openais_cpg.procleave",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cpg_joinlist,
		  { "Join list", "openais_cpg.joinlist",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_joinlist_error,
		  { "Error", "openais_cpg.joinlist.error",
		    FT_UINT32, BASE_DEC, VALS(vals_openais_a_error), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_joinlist_error_padding,
		  { "Padding", "openais_cpg.joinlist.error_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_joinlist_entry,
		  { "Entry", "openais_cpg.joinlist.entry",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_joinlist_entry_pid,
		  { "Pid", "openais_cpg.joinlist.entry.pid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_joinlist_entry_pid_padding,
		  { "Padding", "openais_cpg.joinlist.entry.pid_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		
		{ &hf_openais_cpg_mcast,
		  { "Multicast", "openais_cpg.mcast",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_name,
		  { "Mar name", "openais_cpg.mar_name",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_name_length,
		  { "Mar name length", "openais_cpg.mar_name.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_name_length_padding,
		  { "Padding", "openais_cpg.mar_name.length_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_name_value,
		  { "Mar name value", "openais_cpg.mar_name.value",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_name_value_padding,
		  { "Padding", "openais_cpg.mar_name.value_padding",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mcast_msglen,
		  { "Message length", "openais_cpg.mcast.msglen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mcast_msglen_padding,
		  { "Padding", "openais_cpg.mcast.msglen_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cpg_pid,
		  { "Pid", "openais_cpg.pid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_pid_padding,
		  { "Padding", "openais_cpg.pid_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cpg_mar_message_source,
		  { "Message source", "openais_cpg.mar_message_source",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_message_source_nodeid,
		  { "Node id", "openais_cpg.mar_message_source.nodeid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_message_source_nodeid_padding,
		  { "Padding", "openais_cpg.mar_message_source.nodeid_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_mar_message_source_conn,
		  { "Pointer to connection object", "openais_cpg.mar_message_source.conn",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_openais_cpg_downlist,
		  { "Down list", "openais_cpg.downlist",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_downlist_left_nodes,
		  { "Left nodes", "openais_cpg.downlist.left_nodes",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_downlist_left_nodes_padding,
		  { "Padding", "openais_cpg.downlist.left_nodes_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_cpg_downlist_nodeids,
		  { "Node ids", "openais_cpg.downlist.nodeids",
		    FT_BYTES, BASE_NONE, NULL, 0x0, /* BASE_DEC is rejected by the latest wireshark. */
		    NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_openais_cpg,
		&ett_openais_cpg_procjoin,
		&ett_openais_cpg_procleave,
		&ett_openais_cpg_joinlist,
		&ett_openais_cpg_joinlist_entry,
		&ett_openais_cpg_mcast,
		&ett_openais_cpg_mar_name,
		&ett_openais_cpg_mar_message_source,
		&ett_openais_cpg_downlist,
	};
  
	proto_openais_cpg 
		= proto_register_protocol("cpg protocol on totempg of OpenAIS",
					  "OPENAIS/cpg", "openais_cpg");

	proto_register_field_array(proto_openais_cpg, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	subdissector_table = register_dissector_table("openais_cpg.mar_name.value",
						      "The name of closed process group",
						      FT_STRING,
						      FT_NONE);
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_cpg(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_cpg_handle;

	if (register_dissector) {
		dissector_delete("openais_a.header.id.service", 
				 OPENAIS_CPG_SERIVICE_TYPE, 
				 openais_cpg_handle);
	} else {
		openais_cpg_handle = new_create_dissector_handle(dissect_openais_cpg,
								  proto_openais_cpg);
		register_dissector = TRUE;
	}
	dissector_add("openais_a.header.id.service", 
		      OPENAIS_CPG_SERIVICE_TYPE,
		      openais_cpg_handle);
}

static guint32
openais_cpg_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
	return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}

/* packet-openais-cpg.c ends here */
