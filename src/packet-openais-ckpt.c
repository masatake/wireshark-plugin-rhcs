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
#include "packet-corosync-totemsrp.h"


#define OPENAIS_CKPT_SERIVICE_TYPE 3

/* Forward declaration we need below */
void proto_reg_handoff_openais_ckpt(void);

#if 0
static guint32 openais_ckpt_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
#endif

/* Initialize the protocol and registered fields */
static int proto_openais_ckpt = -1;

static int hf_openais_ckpt_ckpt_id         = -1;
static int hf_openais_ckpt_ckpt_id_padding = -1;
static int hf_openais_ckpt_ring_id_padding = -1;

static int hf_openais_ckpt_checkpoint_creation_attributes = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_creation_flags = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_padding = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_checkpoint_size = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_retention_duration = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_max_sections = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_max_sections_padding = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_max_section_size = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_max_section_id_size = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_set = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_set_padding = -1;

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
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN, "checkpoint-open" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTCLOSE, "checkpoint-close" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTUNLINK, "checkpoint-unlink" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONSET, "Checkpoint-retention-duration-set" },
  { MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONEXPIRE, "Checkpoint-retention-duration-expire" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONCREATE, "section-create" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONDELETE, "sectiond-elete" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONEXPIRATIONTIMESET, "section-expiration-timeset" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONWRITE, "section-write" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONOVERWRITE, "section-overwrite" },
  { MESSAGE_REQ_EXEC_CKPT_SECTIONREAD, "section-read" },
  { MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT, "sync-checkpoint" },
  { MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTSECTION, "sync-checkpoint-section" },
  { MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTREFCOUNT, "sync-checkpoint-refcount" },
  { 0,                              NULL                },
};



#define SA_CKPT_WR_ALL_REPLICAS	0x01
#define SA_CKPT_WR_ACTIVE_REPLICA	0x2
#define SA_CKPT_WR_ACTIVE_REPLICA_WEAK	0x4
#define SA_CKPT_CHECKPOINT_COLLOCATED	0x8
static int hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_all_replicas = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_active_replica = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_active_replica_weak = -1;
static int hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_checkpoint_collocated = -1;
static const int *creation_attributes_flags_fields[] = {
  &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_all_replicas,
  &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_active_replica,
  &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_active_replica_weak,
  &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_checkpoint_collocated,
  NULL,
};

#define MAR_CKPT_CHECKPOINT_READ	0x1
#define MAR_CKPT_CHECKPOINT_WRITE	0x2
#define MAR_CKPT_CHECKPOINT_CREATE	0x4

static int hf_openais_ckpt_checkpoint_open_flags = -1;
static int hf_openais_ckpt_checkpoint_open_flags_read = -1;
static int hf_openais_ckpt_checkpoint_open_flags_write = -1;
static int hf_openais_ckpt_checkpoint_open_flags_create = -1;
static int hf_openais_ckpt_checkpoint_open_flags_padding = -1;
static const int *open_flags_fields[] = {
	&hf_openais_ckpt_checkpoint_open_flags_read,
	&hf_openais_ckpt_checkpoint_open_flags_write,
	&hf_openais_ckpt_checkpoint_open_flags_create,
	NULL,
};


static int hf_openais_ckpt_checkpoint_handle = -1;
static int hf_openais_ckpt_invocation = -1;
static int hf_openais_ckpt_async_call = -1;
static int hf_openais_ckpt_async_call_padding = -1;
static int hf_openais_ckpt_fail_with_error = -1;
static int hf_openais_ckpt_fail_with_error_padding = -1;

static int hf_openais_ckpt_active_replica_set = -1;
static int hf_openais_ckpt_active_replica_set_padding = -1;
static int hf_openais_ckpt_unlinked = -1;
static int hf_openais_ckpt_unlinked_padding = -1;

/* Initialize the subtree pointers */
static gint ett_openais_ckpt = -1;
static gint ett_openais_ckpt_checkpoint_creation_attributes = -1;
static gint ett_openais_ckpt_checkpoint_creation_attributes_creation_flags = -1;
static gint ett_openais_ckpt_checkpoint_open_flags = -1;


static int
dissect_openais_ckpt_creation_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
					 guint length, int offset,
					 gboolean little_endian)

{
	int original_offset;
	proto_item *item;
	proto_tree *tree;	

	original_offset = offset;

	if ((length - offset) < ( 4 + 4 + 8 + 8 + 4 + 4 + 8 + 8))
		return 0;

	item = proto_tree_add_item(parent_tree, hf_openais_ckpt_checkpoint_creation_attributes, 
				   tvb, offset, 8, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_ckpt_checkpoint_creation_attributes);
	
	offset += 0;
	proto_tree_add_bitmask(tree, tvb, offset, 
			       hf_openais_ckpt_checkpoint_creation_attributes_creation_flags,
			       ett_openais_ckpt_checkpoint_creation_attributes_creation_flags,
			       creation_attributes_flags_fields,
			       little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_padding,
			    tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_checkpoint_size,
			    tvb, offset, 8, little_endian);
	offset += 8;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_retention_duration,
			    tvb, offset, 8, little_endian);
	offset += 8;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_max_sections,
			    tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_max_sections_padding,
			    tvb, offset, 4, little_endian);
	offset += 4;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_max_section_size,
			    tvb, offset, 8, little_endian);
	offset += 8;
	proto_tree_add_item(tree,
			    hf_openais_ckpt_checkpoint_creation_attributes_max_section_id_size,
			    tvb, offset, 8, little_endian);
	offset += 8;
	return (offset - original_offset);
}

static int
dissect_openais_ckpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
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
					  "UNKNOWN-ID"));

	if (check_col(pinfo->cinfo, COL_INFO))
	        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(ckpt");	
	fn_id = openais_a_get_fn_id(pinfo);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, 
				" :%s",
				val_to_str(fn_id, vals_openais_ckpt_fn_id,
					   "UNKNOWN-ID"));

	little_endian = openais_a_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_ckpt, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_ckpt);

	offset += 0;


	switch (fn_id) {
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN:
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTCLOSE:
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTUNLINK:
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONSET:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONCREATE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONDELETE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONEXPIRATIONTIMESET:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONWRITE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONOVERWRITE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONREAD:
	        offset += dissect_openais_a_mar_message_source(tvb, pinfo, 
							       tree, 
							       length, 
							       offset, 
							       little_endian);
	        offset += dissect_openais_a_mar_name(tvb, pinfo, 
						     tree, 
						     length, 
						     offset, 
						     little_endian,
						     NULL);
		break;
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONEXPIRE:
	        offset += dissect_openais_a_mar_name(tvb, pinfo, 
						     tree, 
						     length, 
						     offset, 
						     little_endian,
						     NULL);
		break;
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT:
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTSECTION:
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTREFCOUNT:
		offset += corosync_totemsrp_dissect_memb_ring_id(tvb, pinfo,
								 tree,
								 length,
								 offset);
		proto_tree_add_item(tree,
				    hf_openais_ckpt_ring_id_padding,
				    tvb, offset, 2, little_endian);
		offset += 2;
		
		offset += dissect_openais_a_mar_name(tvb, pinfo, 
						     tree, 
						     length, 
						     offset, 
						     little_endian,
						    NULL);
	        break;
	default:
		break;
	}

	switch (fn_id) {
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN:
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTCLOSE:
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONSET:
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTRETENTIONDURATIONEXPIRE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONCREATE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONDELETE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONEXPIRATIONTIMESET:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONWRITE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONOVERWRITE:
	case MESSAGE_REQ_EXEC_CKPT_SECTIONREAD:
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT:
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTSECTION:
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINTREFCOUNT:
		proto_tree_add_item(tree,
				    hf_openais_ckpt_ckpt_id,
				    tvb, offset, 4, little_endian);
		offset += 4;
		proto_tree_add_item(tree,
				    hf_openais_ckpt_ckpt_id_padding,
				    tvb, offset, 4, little_endian);
		offset += 4;
	}

	switch (fn_id) {
	case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN:
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT:
		offset += dissect_openais_ckpt_creation_attributes(tvb, pinfo, 
								   tree, 
								   length, 
								   offset, 
								   little_endian);
		proto_tree_add_item(tree,
				    hf_openais_ckpt_checkpoint_creation_attributes_set,
				    tvb, offset, 4, little_endian);
		offset += 4;
		proto_tree_add_item(tree,
				    hf_openais_ckpt_checkpoint_creation_attributes_set_padding,
				    tvb, offset, 4, little_endian);
		offset += 4;
		break;
	}
	switch (fn_id) {
		case MESSAGE_REQ_EXEC_CKPT_CHECKPOINTOPEN:
			proto_tree_add_bitmask(tree, tvb, offset, 
					       hf_openais_ckpt_checkpoint_open_flags,
					       ett_openais_ckpt_checkpoint_open_flags,
					       open_flags_fields,
					       little_endian);
			offset += 4;
			proto_tree_add_item(tree,
					    hf_openais_ckpt_checkpoint_open_flags_padding,
					    tvb, offset, 4, little_endian);
			offset += 4;
			proto_tree_add_item(tree,
					    hf_openais_ckpt_checkpoint_handle,
					    tvb, offset, 8, little_endian);
			offset += 8;
			proto_tree_add_item(tree,
					    hf_openais_ckpt_invocation,
					    tvb, offset, 8, little_endian);
			offset += 8;
			proto_tree_add_item(tree,
					    hf_openais_ckpt_async_call,
					    tvb, offset, 4, little_endian);
			offset += 4;
			proto_tree_add_item(tree,
					    hf_openais_ckpt_async_call_padding,
					    tvb, offset, 4, little_endian);
			offset += 4;
			proto_tree_add_item(tree,
					    hf_openais_ckpt_fail_with_error,
					    tvb, offset, 4, little_endian);
			offset += 4;
						proto_tree_add_item(tree,
					    hf_openais_ckpt_fail_with_error_padding,
					    tvb, offset, 4, little_endian);
			offset += 4;
			// mar_uint32_t async_call __attribute__((aligned(8)));
			// mar_uint32_t fail_with_error __attribute__((aligned(8)));
			break;
	case MESSAGE_REQ_EXEC_CKPT_SYNCCHECKPOINT:
		proto_tree_add_item(tree,
				    hf_openais_ckpt_active_replica_set,
				    tvb, offset, 4, little_endian);
		offset += 4;
		proto_tree_add_item(tree,
				    hf_openais_ckpt_active_replica_set_padding,
				    tvb, offset, 4, little_endian);
		offset += 4;
		proto_tree_add_item(tree,
				    hf_openais_ckpt_unlinked,
				    tvb, offset, 4, little_endian);
		offset += 4;
		proto_tree_add_item(tree,
				    hf_openais_ckpt_unlinked_padding,
				    tvb, offset, 4, little_endian);
		offset += 4;
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
		{ &hf_openais_ckpt_ckpt_id,
		  { "Id", "openais_ckpt.ckpt_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_ckpt_id_padding,
		  { "Padding", "openais_ckpt.ckpt_id_padding",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_ring_id_padding,
		  { "Padding", "openais_ckpt.ring_id_padding",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes,
		  { "Creation attributes", "openais_ckpt.checkpoint_creation_attributes",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags,
		  { "Creation attributes flags", "openais_ckpt.checkpoint_creation_attributes.creation_flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_all_replicas,
		  { "WR all replicas", "openais_ckpt.checkpoint_creation_attributes.creation_flags.wr_all_replicas",
		    FT_BOOLEAN, 32, NULL, SA_CKPT_WR_ALL_REPLICAS,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_active_replica,
		  { "Active replica", "openais_ckpt.checkpoint_creation_attributes.creation_flags.wr_active_replica",
		    FT_BOOLEAN, 32, NULL, SA_CKPT_WR_ACTIVE_REPLICA,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_wr_active_replica_weak,
		  { "Active replica weak", "openais_ckpt.checkpoint_creation_attributes.creation_flags.wr_active_replica_weak",
		    FT_BOOLEAN, 32, NULL, SA_CKPT_WR_ACTIVE_REPLICA_WEAK,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_checkpoint_collocated,
		  { "Checkpoint collocated", "openais_ckpt.checkpoint_creation_attributes.creation_flags.checkpoint_coollocated",
		    FT_BOOLEAN, 32, NULL, SA_CKPT_CHECKPOINT_COLLOCATED,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_creation_flags_padding,
		  { "Padding", "openais_ckpt.checkpoint_creation_attributes.creation_flags_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_checkpoint_size,
		  { "Checkpoint size", "openais_ckpt.checkpoint_creation_attributes.checkpoint_size",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_retention_duration,
		  { "Retention_duration", "openais_ckpt.checkpoint_creation_attributes.retention_duration",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_max_sections,
		  { "Max sections", "openais_ckpt.checkpoint_creation_attributes.max_sections",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_max_sections_padding,
		  { "Padding", "openais_ckpt.checkpoint_creation_attributes.max_sections_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_max_section_size,
		  { "Max section size", "openais_ckpt.checkpoint_creation_attributes.max_section_size",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_max_section_id_size,
		  { "Max section id size", "openais_ckpt.checkpoint_creation_attributes.max_section_id_size",
		    FT_UINT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_set,
		  { "Creation attributes set", "openais_ckpt.checkpoint_creation_attributes_set",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_creation_attributes_set_padding,
		  { "Padding", "openais_ckpt.checkpoint_creation_attributes_set_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_open_flags,
		  { "Open flags", "openais_ckpt.checkpoint_open_flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_open_flags_read,
		  { "Read", "openais_ckpt.checkpoint_open_flags.read",
		    FT_UINT32, BASE_HEX, NULL, MAR_CKPT_CHECKPOINT_READ,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_open_flags_write,
		  { "Write", "openais_ckpt.checkpoint_open_flags.write",
		    FT_UINT32, BASE_HEX, NULL, MAR_CKPT_CHECKPOINT_WRITE,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_open_flags_create,
		  { "Create", "openais_ckpt.checkpoint_open_flags.create",
		    FT_UINT32, BASE_HEX, NULL, MAR_CKPT_CHECKPOINT_CREATE,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_open_flags_padding,
		  { "Padding", "openais_ckpt.checkpoint_open_flags_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_checkpoint_handle,
		  { "Handle", "openais_ckpt.checkpoint_handle",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_invocation,
		  { "Invocation", "openais_ckpt.invocation",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_async_call,
		  { "Async call", "openais_ckpt.async_call",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_async_call_padding,
		  { "Padding", "openais_ckpt.async_call_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_fail_with_error,
		  { "Fail with error", "openais_ckpt.fail_with_error",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_fail_with_error_padding,
		  { "Padding", "openais_ckpt.fail_with_error_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_active_replica_set,
		  { "Active replica set", "openais_ckpt.active_replica_set",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_active_replica_set_padding,
		  { "Padding", "openais_ckpt.active_replica_set_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_unlinked,
		  { "Unlinked", "openais_ckpt.unlinked",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_ckpt_unlinked_padding,
		  { "Padding", "openais_ckpt.unlinked_padding",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_openais_ckpt,
		&ett_openais_ckpt_checkpoint_creation_attributes,
		&ett_openais_ckpt_checkpoint_creation_attributes_creation_flags,
		&ett_openais_ckpt_checkpoint_open_flags,
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
		dissector_delete_uint("openais_a.header.id.service", 
				      OPENAIS_CKPT_SERIVICE_TYPE, 
				      openais_ckpt_handle);
	} else {
		openais_ckpt_handle = new_create_dissector_handle(dissect_openais_ckpt,
								  proto_openais_ckpt);
		register_dissector = TRUE;
	}
	dissector_add_uint("openais_a.header.id.service", 
			   OPENAIS_CKPT_SERIVICE_TYPE,
			   openais_ckpt_handle);
}

/* packet-openais-ckpt.c ends here */
