/* packet-dlm_controld.c
 * Routines for dissecting protocol used in dlm_controld
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
#include <stdio.h>
#include <string.h>

#include <epan/packet.h>

#define DLM_CONTROLD_DAEMON_NAME "dlm:controld"
#define DLM_CONTROLD_LS_PREFIX "dlm:ls:"

enum {
	DLM_MSG_PROTOCOL = 1,
	DLM_MSG_START,
	DLM_MSG_PLOCK,
	DLM_MSG_PLOCK_OWN,
	DLM_MSG_PLOCK_DROP,
	DLM_MSG_PLOCK_SYNC_LOCK,
	DLM_MSG_PLOCK_SYNC_WAITER,
	DLM_MSG_PLOCKS_STORED,
	DLM_MSG_DEADLK_CYCLE_START,
	DLM_MSG_DEADLK_CYCLE_END,
	DLM_MSG_DEADLK_CHECKPOINT_READY,
	DLM_MSG_DEADLK_CANCEL_LOCK
};

/* dlm_header flags */
#define DLM_MFLG_JOINING   1  /* accompanies start, we are joining */
#define DLM_MFLG_HAVEPLOCK 2  /* accompanies start, we have plock state */
#define DLM_MFLG_NACK      4  /* accompanies start, prevent wrong match when
				 two outstanding changes are the same */
/* Forward declaration we need below */
void proto_reg_handoff_dlm_controld(void);

/* Initialize the protocol and registered fields */
static int proto_dlm_controld = -1;

static int hf_dlm_controld_header = -1;
static int hf_dlm_controld_header_version = -1;
static int hf_dlm_controld_header_version_major = -1;
static int hf_dlm_controld_header_version_minor = -1;
static int hf_dlm_controld_header_version_patch = -1;
static int hf_dlm_controld_header_type = -1;
static int hf_dlm_controld_header_nodeid = -1;
static int hf_dlm_controld_header_to_nodeid = -1;
static int hf_dlm_controld_header_global_id = -1;
static int hf_dlm_controld_header_flags = -1;
static int hf_dlm_controld_header_flags_joining = -1;
static int hf_dlm_controld_header_flags_haveplock = -1;
static int hf_dlm_controld_header_flags_nack = -1;
static int hf_dlm_controld_header_msgdata = -1;
static int hf_dlm_controld_header_pad1 = -1;
static int hf_dlm_controld_header_pad2 = -1;

static int hf_dlm_controld_protocol = -1;
#define VAR_protocol(X) \
  static int hf_dlm_controld_protocol_##X##_ver = -1; \
  static int hf_dlm_controld_protocol_##X##_ver_major = -1; \
  static int hf_dlm_controld_protocol_##X##_ver_minor = -1; \
  static int hf_dlm_controld_protocol_##X##_ver_patch = -1; \
  static int hf_dlm_controld_protocol_##X##_ver_flags = -1; \
  \
  static int ett_dlm_controld_protocol_##X##_ver      = -1
VAR_protocol(dm);
VAR_protocol(km);
VAR_protocol(dr);
VAR_protocol(kr);


/* Initialize the subtree pointers */
static gint ett_dlm_controld        = -1;
static gint ett_dlm_controld_header = -1;
static gint ett_dlm_controld_header_version = -1;
static gint ett_dlm_controld_header_flags = -1;
static gint ett_dlm_controld_protocol = -1;

static const value_string vals_header_type[] = {
  { DLM_MSG_PROTOCOL,                "Protocol"                  },
  { DLM_MSG_START,                   "Start"                     },
  { DLM_MSG_PLOCK_OWN,               "Plock own"                 },
  { DLM_MSG_PLOCK_DROP,              "Plock drop"                },
  { DLM_MSG_PLOCK_SYNC_LOCK,         "Plock sync lock"           },
  { DLM_MSG_PLOCK_SYNC_WAITER,       "Plock sync waiter"         },
  { DLM_MSG_PLOCKS_STORED,           "Plock stored"              },
  { DLM_MSG_DEADLK_CYCLE_START,      "Deadlock cycle start"      },
  { DLM_MSG_DEADLK_CYCLE_END,        "Deadlock cycle end"        },
  { DLM_MSG_DEADLK_CHECKPOINT_READY, "Deadlock checkpoint ready" },
  { DLM_MSG_DEADLK_CANCEL_LOCK,      "Deadlock cancel lock"      },
  { 0,                               NULL                        },
};

static const int *header_flags_fields[] = {
  &hf_dlm_controld_header_flags_nack,
  &hf_dlm_controld_header_flags_haveplock,
  &hf_dlm_controld_header_flags_joining,
  NULL
};


static int
dissect_dlm_controld_protocol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			     int offset, guint length)
{
  int original_offset;
  proto_tree *tree, *dm_tree, *dr_tree;
  proto_item *item, *dm_item, *dr_item;


  original_offset = offset;
  if ( (length - offset) <  (( 2 * 4 ) * 4 ))
    return 0;

  offset += 0;
  item = proto_tree_add_item(parent_tree, hf_dlm_controld_protocol, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_dlm_controld_protocol);

  offset += 0;


#define LOAD_protocol(X) \
  item = proto_tree_add_item(tree, hf_dlm_controld_protocol_##X##_ver, tvb, \
			     offset, -1, TRUE);				\
  dm_tree = proto_item_add_subtree(item, ett_dlm_controld_protocol);	\
									\
  offset += 0;								\
  dm_item = proto_tree_add_item(dm_tree, hf_dlm_controld_protocol_##X##_ver_major, tvb, \
			     offset, 2, TRUE);				\
  offset += 2;								\
  dm_item = proto_tree_add_item(dm_tree, hf_dlm_controld_protocol_##X##_ver_minor, tvb, \
			     offset, 2, TRUE);				\
  offset += 2;								\
  dm_item = proto_tree_add_item(dm_tree, hf_dlm_controld_protocol_##X##_ver_patch, tvb, \
			     offset, 2, TRUE);				\
  offset += 2;								\
  dm_item = proto_tree_add_item(dm_tree, hf_dlm_controld_protocol_##X##_ver_flags, tvb, \
				offset, 2, TRUE);			\
  offset += 2
  
  LOAD_protocol(dm);
  LOAD_protocol(km);
  LOAD_protocol(dr);
  LOAD_protocol(kr);

  return length - original_offset;
}

static int
dissect_dlm_controld(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		     const gchar* col_str)
{
  guint length;
  int offset;

  proto_tree *dlm_controld_tree, *tree, *version_tree;
  proto_item *item, *version_item;
  guint32 type;

  length = tvb_length(tvb);
  if ( length < ( 2 * 3 ) + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 8)
    return 0;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", col_str);

  if (!parent_tree)
    goto out;

  offset = 0;
  item = proto_tree_add_item(parent_tree, proto_dlm_controld, tvb, 
			     offset, -1, TRUE);
  dlm_controld_tree = proto_item_add_subtree(item, ett_dlm_controld);

  offset += 0;
  item = proto_tree_add_item(dlm_controld_tree, hf_dlm_controld_header, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_dlm_controld_header);

  offset += 0;
  version_item = proto_tree_add_item(tree, 
				     hf_dlm_controld_header_version, 
				     tvb, offset, -1, TRUE);
  version_tree = proto_item_add_subtree(version_item, 
					ett_dlm_controld_header_version);

  offset += 0;
  proto_tree_add_item(version_tree, hf_dlm_controld_header_version_major, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(version_tree, hf_dlm_controld_header_version_minor, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(version_tree, hf_dlm_controld_header_version_patch, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  type = tvb_get_letohs(tvb, offset);
  proto_tree_add_item(tree, hf_dlm_controld_header_type, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(tree, hf_dlm_controld_header_nodeid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_dlm_controld_header_to_nodeid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_dlm_controld_header_global_id, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset, hf_dlm_controld_header_flags, 
			 ett_dlm_controld_header_flags, header_flags_fields,
			 TRUE);

  offset += 4;
  switch (type)
    {
    default:
      proto_tree_add_item(tree, hf_dlm_controld_header_msgdata, 
			  tvb, offset, 4, TRUE);
      break;
    }

  offset += 4;
  proto_tree_add_item(tree, hf_dlm_controld_header_pad1, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_dlm_controld_header_pad2, 
		      tvb, offset, 8, TRUE);

  offset += 8;
  switch (type)
    {
    case DLM_MSG_PROTOCOL:
      dissect_dlm_controld_protocol(tvb, pinfo, dlm_controld_tree, offset, length);
      break;
    default:
      break;
    }
 out:
  return length;
}

static int
dissect_dlm_controld_daemon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  return dissect_dlm_controld(tvb, pinfo, parent_tree, "dlm:controld");
}

static int
dissect_dlm_controld_ls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  if (pinfo->private_data &&
      strstr(pinfo->private_data, DLM_CONTROLD_LS_PREFIX))
    return dissect_dlm_controld(tvb, pinfo, parent_tree, pinfo->private_data);
  else
    return 0;
}

void
proto_register_dlm_controld(void)
{
  /* Setup list of fields */
  static hf_register_info hf[] = {
    { &hf_dlm_controld_header,
      { "dlm_controld header", "dlm_controld.dlm_header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_version,
      { "dlm_controld header version", "dlm_controld.dlm_header.version",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_version_major,
      { "dlm_controld header major version", "dlm_controld.dlm_header.version.major",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_version_minor,
      { "dlm_controld header minor version", "dlm_controld.dlm_header.version.minor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_version_patch,
      { "dlm_controld header patch level", "dlm_controld.dlm_header.version.patch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_type,
      { "dlm_controld header type", "dlm_controld.dlm_header.type",
        FT_UINT16, BASE_DEC, VALS(vals_header_type), 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_nodeid,
      { "Sender node", "dlm_controld.dlm_header.nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_to_nodeid,
      { "Recipient node", "dlm_controld.dlm_header.to_nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_global_id,
      { "Global unique id for this domain", "dlm_controld.dlm_header.global_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_flags,
      { "dlm_controld header flags", "dlm_controld.dlm_header.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_flags_joining,
      { "Joining", "dlm_controld.dlm_header.flags.joining",
	FT_BOOLEAN, 32, NULL, DLM_MFLG_JOINING,
	NULL, HFILL }},
    { &hf_dlm_controld_header_flags_haveplock,
      { "Haveplock", "dlm_controld.dlm_header.flags.haveplock",
	FT_BOOLEAN, 32, NULL, DLM_MFLG_HAVEPLOCK,
	NULL, HFILL }},
    { &hf_dlm_controld_header_flags_nack,
      { "Nack", "dlm_controld.dlm_header.flags.nack",
	FT_BOOLEAN, 32, NULL, DLM_MFLG_NACK,
	NULL, HFILL }},
    
    { &hf_dlm_controld_header_msgdata,
      { "dlm_controld header msgdata", "dlm_controld.dlm_header.msgdata",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_pad1,
      { "Padding", "dlm_controld.dlm_header.pad1",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm_controld_header_pad2,
      { "Padding", "dlm_controld.dlm_header.pad2",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dlm_controld_protocol,
      { "dlm_controld protocol", "dlm_controld.protocol",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
#define ATTACH_protocol(X,Y)		   \
    { &hf_dlm_controld_protocol_##X##_ver, \
      { "Protocol version of " Y, "dlm_controld.protocol." #X "_ver", \
        FT_NONE, BASE_NONE, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_dlm_controld_protocol_##X##_ver_major, \
      { "Major version of " Y, "dlm_controld.protocol." #X "_ver.major", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_dlm_controld_protocol_##X##_ver_minor, \
      { "Minor version of " Y, "dlm_controld.protocol." #X "_ver.minor", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_dlm_controld_protocol_##X##_ver_patch, \
      { "Patch level of " Y, "dlm_controld.protocol." #X "_ver.patch", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_dlm_controld_protocol_##X##_ver_flags, \
      { "Flags of " Y, "dlm_controld.protocol." #X "_ver.flags", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }} 

    ATTACH_protocol(dm, "daemon max"),
    ATTACH_protocol(km, "kernel max"),
    ATTACH_protocol(dr, "daemon running"),
    ATTACH_protocol(kr, "kernel running"),
  };

  static gint *ett[] = {
    &ett_dlm_controld,
    &ett_dlm_controld_header,
    &ett_dlm_controld_header_version,
    &ett_dlm_controld_header_flags,
    &ett_dlm_controld_protocol,
    &ett_dlm_controld_protocol_dm_ver,
    &ett_dlm_controld_protocol_km_ver,
    &ett_dlm_controld_protocol_dr_ver,
    &ett_dlm_controld_protocol_kr_ver,
  };
  
  proto_dlm_controld = proto_register_protocol("Protocol used in dlm_controld",
					      "dlm_controld", "dlm_controld");
  proto_register_field_array(proto_dlm_controld, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dlm_controld(void)
{
  static gboolean register_dissector = FALSE;
  static dissector_handle_t dlm_controld_daemon_handle;
  static dissector_handle_t dlm_controld_ls_handle;

  if (register_dissector) {
    dissector_delete_string("openais_cpg.mar_name.value", 
			    DLM_CONTROLD_DAEMON_NAME, 
			    dlm_controld_daemon_handle);
  } else {
    dlm_controld_daemon_handle = new_create_dissector_handle(dissect_dlm_controld_daemon,
							     proto_dlm_controld);
    register_dissector = TRUE;
  }

  dissector_add_string("openais_cpg.mar_name.value", 
		       DLM_CONTROLD_DAEMON_NAME,
		       dlm_controld_daemon_handle);
  heur_dissector_add("openais_cpg", 
		     dissect_dlm_controld_ls, 
		     proto_dlm_controld);
}
