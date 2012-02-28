/* packet-corosync-totempg.c
 * Dissctors for totem process groups header of corosync cluster engine
 * Copyright 2007, Masatake YAMATO <yamato@redhat.com>
 * Copyright 2009, Red Hat, Inc.
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
#include <epan/prefs.h>
#include <epan/reassemble.h>


#include "packet-corosync-totemsrp.h"
#include "packet-corosync-totempg.h"


/* Forward declaration we need below */
void proto_reg_handoff_corosync_totempg(void);

/* Initialize the protocol and registered fields */
static int proto_corosync_totempg = -1;

/* fields for struct corosync_totempg_mcast */
static int hf_corosync_totempg_fragmented           = -1;
static int hf_corosync_totempg_continuation         = -1;
static int hf_corosync_totempg_msg_count            = -1;
static int hf_corosync_totempg_msg_len              = -1;
static int hf_corosync_totempg_message              = -1;

static int hf_corosync_totempg_groups_count         = -1;
static int hf_corosync_totempg_group_len            = -1;
static int hf_corosync_totempg_group_name           = -1;

/* fields for struct corosync_totempg_mcast_header */
static int hf_corosync_totempg_mcast_header         = -1;
static int hf_corosync_totempg_mcast_header_version = -1;
static int hf_corosync_totempg_mcast_header_type    = -1;


static int hf_corosync_totempg_mcast_message      = -1;



static int hf_corosync_totempg_message_fragments = -1;
static int hf_corosync_totempg_message_fragment = -1;
static int hf_corosync_totempg_message_fragment_overlap = -1;
static int hf_corosync_totempg_message_fragment_overlap_conflicts = -1;
static int hf_corosync_totempg_message_fragment_multiple_tails = -1;
static int hf_corosync_totempg_message_fragment_too_long_fragment = -1;
static int hf_corosync_totempg_message_fragment_error = -1;
static int hf_corosync_totempg_message_reassembled_in = -1;


/* Initialize the subtree pointers */
static gint ett_corosync_totempg                    = -1;
static gint ett_corosync_totempg_mcast_header       = -1;
static gint ett_corosync_totempg_mcast_message      = -1;

static gint ett_corosync_totempg_message_fragment   = -1;
static gint ett_corosync_totempg_message_fragments  = -1;


/* desegmentation of message */
static gboolean    corosync_totempg_message_desegment = TRUE;

static GHashTable *corosync_totempg_message_segment_table = NULL;
static GHashTable *corosync_totempg_message_reassembled_table = NULL;

static const fragment_items corosync_totempg_message_frag_items = {
	/* Fragment subtrees */
	&ett_corosync_totempg_message_fragment,
	&ett_corosync_totempg_message_fragments,
	/* Fragment fields */
	&hf_corosync_totempg_message_fragments,
	&hf_corosync_totempg_message_fragment,
	&hf_corosync_totempg_message_fragment_overlap,
	&hf_corosync_totempg_message_fragment_overlap_conflicts,
	&hf_corosync_totempg_message_fragment_multiple_tails,
	&hf_corosync_totempg_message_fragment_too_long_fragment,
	&hf_corosync_totempg_message_fragment_error,
	/* Reassembled in field */
	&hf_corosync_totempg_message_reassembled_in,
	/* Tag */
	"MESSAGE fragments"
};




static dissector_table_t subdissector_table;
static dissector_handle_t data_handle;



static guint16 corosync_totempg_get_guint16(tvbuff_t* tvb, gint offset, gboolean little_endian);
static guint32 corosync_totempg_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
static gint32  corosync_totempg_get_gint32 (tvbuff_t* tvb, gint offset, gboolean little_endian);

static int
dissect_corosync_totempg_mcast_header(tvbuff_t *tvb,
				      packet_info *pinfo, proto_tree *parent_tree,
				      guint length, int offset,
				      gboolean little_endian)
{
  int original_offset;
  proto_tree *tree;
  proto_item *item;

#define corosync_totempg_mcast_header_length ( 2 + 2 )
  if ((length - offset) <  corosync_totempg_mcast_header_length)
    return 0;

  original_offset = offset;

  item = proto_tree_add_item(parent_tree, hf_corosync_totempg_mcast_header, 
                             tvb, offset, 2 + 2, little_endian);
  tree = proto_item_add_subtree(item, ett_corosync_totempg_mcast_header);


  offset += 0;
  proto_tree_add_item(tree,
                      hf_corosync_totempg_mcast_header_version,
                      tvb, offset, 2, little_endian);

  offset += 2;
  proto_tree_add_item(tree,
                      hf_corosync_totempg_mcast_header_type,
                      tvb, offset, 2, little_endian);
  offset += 2;
  return (offset - original_offset);
 
  pinfo = pinfo;
}

static guint16
dissect_corosync_totempg_message0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				 guint length, guint16 msg_len, int offset, gboolean little_endian)
{
  int j;
  guint16   *group_lens;
  guint16    groups_count;
  gint       group_lens_total;
  proto_item *sub_item;
  int        local_offset;

  gchar**    group_names;


  local_offset = offset;

  if ((length - local_offset) < 2)
    goto next;


  local_offset += 0;
  proto_tree_add_item(tree, hf_corosync_totempg_groups_count,
                      tvb, local_offset, 2, little_endian);
  groups_count = corosync_totempg_get_guint16(tvb, local_offset, little_endian);


  local_offset += 2;
  if (length < (guint)(local_offset + (2 * groups_count)))
    goto next;

  group_lens = ep_alloc(sizeof (guint16) * groups_count);
  group_lens_total = 0;
  for (j = 0; j < groups_count; j++) {
    sub_item = proto_tree_add_item(tree, hf_corosync_totempg_group_len,
                                   tvb, local_offset, 2, little_endian);
    group_lens[j] = corosync_totempg_get_guint16(tvb, local_offset, little_endian);
    group_lens_total += group_lens[j];
    proto_item_append_text(sub_item, " (group index: %u)", j);

    local_offset += 2;
  }
      

  local_offset += 0;
  if (length < (guint)(local_offset + (group_lens_total)))
    goto next;

  group_names = ep_alloc(sizeof (gchar*) * groups_count);
  for (j = 0; j < groups_count; j++) {
    sub_item = proto_tree_add_item(tree, hf_corosync_totempg_group_name,
                                   tvb, local_offset, group_lens[j], little_endian);
    proto_item_append_text(sub_item, " (group index: %u)", j);
    group_names[j] = tvb_get_ephemeral_string(tvb, local_offset, group_lens[j]);
        
    local_offset += group_lens[j];
  }

  if ((msg_len - (local_offset - offset)) < 0)
    goto next;

  {
    tvbuff_t *next_tvb;
    gint len, reported_len;


    len = (msg_len - (local_offset - offset));
    reported_len = tvb_reported_length_remaining(tvb, local_offset);

    if (len > reported_len)
      len = reported_len;
    next_tvb = tvb_new_subset(tvb, local_offset, len, reported_len);

    for (j = 0; j < groups_count; j++)
      dissector_try_string(subdissector_table, 
			   group_names[j], next_tvb, pinfo, 
			   tree);
  }
      
 next:
  return msg_len;
}

static int
dissect_corosync_totempg_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				 guint length, guint16* msg_lens, int offset, int msg_index, 
				 gboolean deal_as_data,
				 gboolean little_endian)
{
  proto_item *sub_item;
  proto_tree *sub_tree;
      

  sub_item = proto_tree_add_item(tree, hf_corosync_totempg_mcast_message, 
				 tvb, offset, msg_lens[msg_index], little_endian);
  proto_item_append_text(sub_item, " (msg index: %u)", msg_index);
  sub_tree = proto_item_add_subtree(sub_item, ett_corosync_totempg_mcast_message);
	
  if (deal_as_data)
    {
      tvbuff_t* next_tvb;

      next_tvb = tvb_new_subset(tvb, offset, msg_lens[msg_index], msg_lens[msg_index]);
      call_dissector(data_handle, next_tvb, pinfo, sub_tree);
      return msg_lens[msg_index];
    }
  else
    return dissect_corosync_totempg_message0(tvb, pinfo, sub_tree, 
					     length, msg_lens[msg_index], offset, little_endian);
}

static int
dissect_corosync_totempg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  guint    length;
  int      offset;

  gboolean little_endian;

  proto_tree *tree;
  proto_item *item;

  int        sub_length;

  guint16    msg_count;
  int        i;

  guint16   *msg_lens;
  guint      msg_lens_total;

  guint8     fragmented;
  guint8     continuation;


  length = tvb_length(tvb);
  if (length < (corosync_totempg_mcast_header_length + 1 + 1 + 2))
    return FALSE;


  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "COROSYNC/TOTEMPG");
  }
  
  /* if (check_col(pinfo->cinfo, COL_INFO))
     col_clear(pinfo->cinfo, COL_INFO); */

  if (parent_tree) {
    little_endian = corosync_totemsrp_is_little_endian(pinfo);
    offset = 0;

    item = proto_tree_add_item(parent_tree, proto_corosync_totempg, tvb, 
                               offset, -1, little_endian);
    tree = proto_item_add_subtree(item, ett_corosync_totempg);
    

    offset += 0;
    sub_length = dissect_corosync_totempg_mcast_header(tvb, 
						       pinfo, tree,
						       length, offset,
						       little_endian);
    if (sub_length == 0)
      goto out;

    offset += sub_length;
    proto_tree_add_item(tree,
                        hf_corosync_totempg_fragmented,
                        tvb, offset, 1, little_endian);
    fragmented = tvb_get_guint8(tvb, offset);

    offset += 1;
    proto_tree_add_item(tree,
                        hf_corosync_totempg_continuation,
                        tvb, offset, 1, little_endian);
    continuation = tvb_get_guint8(tvb, offset);


    offset += 1;
    proto_tree_add_item(tree,
                        hf_corosync_totempg_msg_count,
                        tvb, offset, 2, little_endian);
    msg_count = corosync_totempg_get_guint16(tvb, offset, little_endian);


    if (msg_count == 0)
      goto out;
    if ((length - offset) < (sizeof(guint16) * msg_count))
      goto out;
    
    msg_lens = ep_alloc(sizeof(guint16) * msg_count);
    msg_lens_total = 0;
    for (i = 0; i < msg_count; i++) {
      proto_item *sub_item;


      offset += 2;
      sub_item = proto_tree_add_item(tree,
                                     hf_corosync_totempg_msg_len,
                                     tvb, offset, 2, little_endian);
      msg_lens[i] = corosync_totempg_get_guint16(tvb, offset, little_endian);
      msg_lens_total += msg_lens[i];
      proto_item_append_text(sub_item, " (msg index: %u)", i);
    }


    offset += 2;
    if ((length - offset) < msg_lens_total)
      goto out;


    {
      int i0;


      i0 = 0;

      if (continuation > 0)
	{
	  if  (corosync_totempg_message_desegment)
	    {
	      fragment_data  *frag_msg;
	      tvbuff_t       *next_tvb;


	      frag_msg = fragment_add_seq_check(tvb, offset, pinfo, 
						corosync_totemsrp_nodeid(pinfo),
						corosync_totempg_message_segment_table,
						corosync_totempg_message_reassembled_table,
						continuation,
						msg_lens[0], 
						(fragmented > 0)? 1: 0);

	      next_tvb = process_reassembled_data (tvb, offset, pinfo, 
						   "Reassembled message",
						   frag_msg, 
						   &corosync_totempg_message_frag_items, 
						   NULL/*TODO*/, tree);

	      if (next_tvb)
		dissect_corosync_totempg_message(next_tvb, 
						 pinfo, 
						 tree, 
						 length,
						 msg_lens, 
						 offset, 
						 0, 
						 FALSE,
						 little_endian);
	    }
	  else 
	    dissect_corosync_totempg_message(tvb, 
					     pinfo, 
					     tree, 
					     length,
					     msg_lens, 
					     offset, 
					     0, 
					     TRUE,
					     little_endian);
	  offset += msg_lens[0];
	  i0 = 1;
	}
      
      for (i = i0; i < (msg_count - ((fragmented > 0)? 1: 0)); i++) 
	offset += dissect_corosync_totempg_message(tvb, 
						   pinfo, 
						   tree, 
						   length,
						   msg_lens, 
						   offset, 
						   i, 
						   FALSE,
						   little_endian);

      if (fragmented > 0)
	{
	  int z;
	  z = msg_count - 1;

	  /* If this message is already in reassemble process, 
	     do nothing. */
	  if (continuation && ((msg_count - 1) == 0))
	    goto out;


	  if (corosync_totempg_message_desegment)
	    {

	      fragment_data  *frag_msg;
	      tvbuff_t       *next_tvb;

	      frag_msg = fragment_add_seq_check(tvb, offset, pinfo, 
						corosync_totemsrp_nodeid(pinfo),
						corosync_totempg_message_segment_table,
						corosync_totempg_message_reassembled_table,
						continuation,
						msg_lens[z], 1);

	      next_tvb = process_reassembled_data (tvb, offset, pinfo, 
						   "Reassembled message",
						   frag_msg, 
						   &corosync_totempg_message_frag_items, 
						   NULL/*TODO*/, tree);

	      if (next_tvb)
		dissect_corosync_totempg_message(next_tvb, 
						 pinfo, 
						 tree, 
						 length,
						 msg_lens, 
						 offset, 
						 z, 
						 FALSE,
						 little_endian);
	      offset += msg_lens[z];
	    }
	  else
	    dissect_corosync_totempg_message(tvb, 
					     pinfo, 
					     tree, 
					     length,
					     msg_lens, 
					     offset, 
					     z, 
					     TRUE,
					     little_endian);
	}
    }
  }

 out:
  return length;
}

static gboolean
dissect_corosync_totempg_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int r;

  r = dissect_corosync_totempg(tvb, pinfo, tree);
  if (r > 0)
    return TRUE;
  else
    return FALSE;
}

static void corosync_totempg_message_reassemble_init (void)
{
  fragment_table_init    (&corosync_totempg_message_segment_table);
  reassembled_table_init (&corosync_totempg_message_reassembled_table);
}

/* Register the protocol with Wireshark */
void
proto_register_corosync_totempg(void)
{
  /* Setup list of fields */
  static hf_register_info hf[] = {
    { &hf_corosync_totempg_fragmented,
      { "Fragment flag", "corosync_totempg.fragmented",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_continuation,
      { "Continuation flag", "corosync_totempg.continuation",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_msg_count,
      { "Count of messages", "corosync_totempg.msg_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_msg_len,
      { "Length of message", "corosync_totempg.msg_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_message,
      { "Message", "corosync_totempg.message",
        FT_BYTES, BASE_NONE, NULL, 0x0, /* TODO: BASE_HEX is rejected by the latest wireshark. */
        NULL, HFILL }},
    { &hf_corosync_totempg_mcast_header,
      { "Multicast packet header", "corosync_totempg.mcast_header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_mcast_header_version,
      { "Version", "corosync_totempg.mcast_header.version",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_mcast_header_type,
      { "Type", "corosync_totempg.mcast_header.type",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_groups_count,
      {"Group count", "corosync_totempg.group_count",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totempg_group_len,
      {"Length of group name", "corosync_totempg.group_len",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL, HFILL}},
    { &hf_corosync_totempg_group_name,
      { "Group name", "corosync_totempg.group_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_mcast_message,
      { "Multicast packet message", "corosync_totempg.mcast_message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_corosync_totempg_message_fragments,
      { "Corosync totempg message fragments", "corosync_totempg.message_fragments", 
	FT_NONE, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_fragment,
      { "Corosync totempg message fragment",  "corosync_totempg.message_fragment", 
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_fragment_overlap,
      { "Corosync totempg message fragment overlap", "corosync_totempg.message_fragment.overlap",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_fragment_overlap_conflicts,
      { "Corosync totempg message fragment overlap conflicts", "corosync_totempg.message_fragment.overlap.conflict",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_fragment_multiple_tails,
      { "Corosync totempg message fragment multiple tails", "corosync_totempg.message_fragment.multiple_tails",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_fragment_too_long_fragment,
      { "Corosync totempg message fragment too long fragment", "corosync_totempg.message_fragment.too_long_fragment",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_fragment_error,
      { "Corosync totempg message fragment error", "corosync_totempg.message_fragment.error",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
    { &hf_corosync_totempg_message_reassembled_in,
      { "Corosync totempg message reassembled in", "corosync_totempg.message_reassembled_in",
	FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_corosync_totempg,
    &ett_corosync_totempg_mcast_header,
    &ett_corosync_totempg_mcast_message,
    &ett_corosync_totempg_message_fragment,
    &ett_corosync_totempg_message_fragments,
  };
 
  module_t *corosync_totempg_module;


  proto_corosync_totempg 
    = proto_register_protocol("Process Group Layer of Corosync Cluster Engine",
			      "COROSYNC/TOTEMPG", "corosync_totempg");
  proto_register_field_array(proto_corosync_totempg, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&corosync_totempg_message_reassemble_init);

  
  /* Preferences */
  corosync_totempg_module = prefs_register_protocol(proto_corosync_totempg, NULL);
  prefs_register_bool_preference(corosync_totempg_module, "desegment_message",
				 "Reassemble messages",
				 "Whether the COROSYNC/TOTEMPG dissector should reassemble fragmented messages.",
				 &corosync_totempg_message_desegment);  

  /* Subdissector Table */
  subdissector_table 
    = register_dissector_table("corosync_totempg.group_name",
			       "The name of process group",
			       FT_STRING,
			       FT_NONE);
}


void
proto_reg_handoff_corosync_totempg(void)
{
  static gboolean initialize = FALSE;

  if (!initialize) {
    heur_dissector_add("corosync_totemsrp.mcast", 
		       dissect_corosync_totempg_heur, 
		       proto_corosync_totempg);
    data_handle = find_dissector("data");
    initialize = TRUE;

  }
  
}

static guint16
corosync_totempg_get_guint16(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
  return (little_endian? tvb_get_letohs: tvb_get_ntohs)(tvb, offset);
}

gboolean
corosync_totempg_is_little_endian(packet_info *pinfo)
{
  return corosync_totemsrp_is_little_endian(pinfo);
}

gint
corosync_totempg_dissect_mar_req_header(tvbuff_t *tvb,
					packet_info *pinfo, 
					proto_tree *parent_tree,
					guint length, int offset,
					/*  */
					int hf_header, int ett_header,
					int hf_size, int hf_size_padding,   
					int hf_id,   int hf_id_padding,
					/*  */
					gboolean little_endian,
					gint32 *size,
					gint32 *id,
					gint (* id_callback)(proto_tree *,
							     tvbuff_t   *,
							     int    id_offset,
							     gboolean id_little_endian,
							     void        *),
					void* id_callback_data)

{
  int original_offset;

  proto_tree *tree;
  proto_item *item;

  if ((length - offset) < corosync_totempg_dissect_mar_req_header_length)
    return 0;

  original_offset = offset;

  item = proto_tree_add_item(parent_tree, hf_header,
                             tvb, offset, corosync_totempg_dissect_mar_req_header_length, little_endian);
  tree = proto_item_add_subtree(item, ett_header);

  offset += 0;
  proto_tree_add_item(tree,
                      hf_size,
                      tvb, offset, 4, little_endian);
  if (size)
    *size = corosync_totempg_get_gint32(tvb, offset, little_endian);


  offset += 4;
  proto_tree_add_item(tree,
                      hf_size_padding,
                      tvb, offset, 4, little_endian);

  /* --- ID --- */
  offset += 4;
  if (id)
    *id = corosync_totempg_get_gint32(tvb, offset, little_endian);
  
  if (id_callback)
    id_callback(tree, tvb, offset, little_endian, id_callback_data);
  else
    proto_tree_add_item(tree,
                        hf_id,
                        tvb, offset, 4, little_endian);  
  /* --- ID --- */

  offset += 4;
  proto_tree_add_item(tree,
                      hf_id_padding,
                      tvb, offset, 4, little_endian);
  
  offset += 4;
  return (offset - original_offset);
  
  /* Unsed */
  pinfo = pinfo;
}


static guint32
corosync_totempg_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
  return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}

static gint32
corosync_totempg_get_gint32 (tvbuff_t* tvb, gint offset, gboolean little_endian)
{       
  union {
    guint32 u;
    gint32  i;
  } v;

  v.u = corosync_totempg_get_guint32(tvb, offset, little_endian);
  return v.i;
}

/* packet-corosync-totempg.c ends here. */
