/* packet-rhcs-fenced.c
 * Routines for dissecting protocol used in fenced of rhcs
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

#include <epan/packet.h>

#define RHCS_FENCED_DAEMON_NAME "fenced:daemon"
#define RHCS_FENCED_DEFAULT_NAME "fenced:default"
#define PV_STATEFUL 0x0001
#define IDI_NODEID_IS_MEMBER 0x00000001

/* Forward declaration we need below */
void proto_reg_handoff_rhcs_fenced(void);

/* Initialize the protocol and registered fields */
static int proto_rhcs_fenced = -1;

static int hf_rhcs_fenced_header = -1;
static int hf_rhcs_fenced_header_version = -1;
static int hf_rhcs_fenced_header_version_major = -1;
static int hf_rhcs_fenced_header_version_minor = -1;
static int hf_rhcs_fenced_header_version_patch = -1;
static int hf_rhcs_fenced_header_type = -1;
static int hf_rhcs_fenced_header_nodeid = -1;
static int hf_rhcs_fenced_header_to_nodeid = -1;
static int hf_rhcs_fenced_header_global_id = -1;
static int hf_rhcs_fenced_header_flags = -1;
static int hf_rhcs_fenced_header_msgdata = -1;
static int hf_rhcs_fenced_header_pad1 = -1;
static int hf_rhcs_fenced_header_pad2 = -1;

static int hf_rhcs_fenced_protocol = -1;
static int hf_rhcs_fenced_protocol_dm_ver = -1;
static int hf_rhcs_fenced_protocol_dr_ver = -1;
static int hf_rhcs_fenced_protocol_dm_ver_major = -1;
static int hf_rhcs_fenced_protocol_dm_ver_minor = -1;
static int hf_rhcs_fenced_protocol_dm_ver_patch = -1;
static int hf_rhcs_fenced_protocol_dm_ver_flags = -1;
static int hf_rhcs_fenced_protocol_dm_ver_flags_stateful = -1;
static int hf_rhcs_fenced_protocol_dr_ver_major = -1;
static int hf_rhcs_fenced_protocol_dr_ver_minor = -1;
static int hf_rhcs_fenced_protocol_dr_ver_patch = -1;
static int hf_rhcs_fenced_protocol_dr_ver_flags = -1;
static int hf_rhcs_fenced_protocol_dr_ver_flags_stateful = -1;

static int hf_rhcs_fenced_start = -1;

static int hf_rhcs_fenced_fd_info = -1;
static int hf_rhcs_fenced_fd_info_fd_info_size = -1;
static int hf_rhcs_fenced_fd_info_id_info_size = -1;
static int hf_rhcs_fenced_fd_info_id_info_count = -1;
static int hf_rhcs_fenced_fd_info_started_count = -1;
static int hf_rhcs_fenced_fd_info_member_count = -1;
static int hf_rhcs_fenced_fd_info_joined_count = -1;
static int hf_rhcs_fenced_fd_info_remove_count = -1;
static int hf_rhcs_fenced_fd_info_failed_count = -1;

static int hf_rhcs_fenced_id_info = -1;
static int hf_rhcs_fenced_id_info_nodeid = -1;
static int hf_rhcs_fenced_id_info_flags = -1;
static int hf_rhcs_fenced_id_info_flags_nodedid_is_member = -1;
static int hf_rhcs_fenced_id_info_fence_external_node = -1;
static int hf_rhcs_fenced_id_info_fence_master = -1;
static int hf_rhcs_fenced_id_info_fence_how = -1;
static int hf_rhcs_fenced_id_info_pad = -1;
static int hf_rhcs_fenced_id_info_fence_time = -1;
static int hf_rhcs_fenced_id_info_fence_external_time = -1;

static int hf_rhcs_fenced_complete = -1;

/* Initialize the subtree pointers */
static gint ett_rhcs_fenced        = -1;
static gint ett_rhcs_fenced_header = -1;
static gint ett_rhcs_fenced_header_version = -1;
static gint ett_rhcs_fenced_protocol = -1;
static gint ett_rhcs_fenced_protocol_dm_ver = -1;
static gint ett_rhcs_fenced_protocol_dr_ver = -1;
static gint ett_rhcs_fenced_protocol_dm_ver_flags = -1;
static gint ett_rhcs_fenced_protocol_dr_ver_flags = -1;
static gint ett_rhcs_fenced_start = -1;
static gint ett_rhcs_fenced_fd_info = -1;
static gint ett_rhcs_fenced_id_info = -1;
static gint ett_rhcs_fenced_id_info_flags = -1;
static gint ett_rhcs_fenced_complete = -1;

/* See cluster/fence/fenced/fd.h */
#define FD_MSG_PROTOCOL		1
#define FD_MSG_START		2
#define FD_MSG_VICTIM_DONE	3
#define FD_MSG_COMPLETE		4
#define FD_MSG_EXTERNAL		5

#define VIC_DONE_AGENT		1
#define VIC_DONE_MEMBER		2
#define VIC_DONE_OVERRIDE	3
#define VIC_DONE_EXTERNAL	4

static const value_string vals_header_type[] = {
  { FD_MSG_PROTOCOL,    "Protocol"    },
  { FD_MSG_START,       "Start"       },
  { FD_MSG_VICTIM_DONE, "Victim done" },
  { FD_MSG_COMPLETE,    "Complete"    },
  { FD_MSG_EXTERNAL,    "External"    },
  { 0,                  NULL          },
};

static const value_string vals_fence_how[] = {
  { VIC_DONE_AGENT,     "Agent"    },
  { VIC_DONE_MEMBER,    "Member"   },
  { VIC_DONE_OVERRIDE,  "Override" },
  { VIC_DONE_EXTERNAL,  "External" },
  { 0,                  NULL       },
};
  

static const int *protocol_dm_ver_flags_fields[] = {
  &hf_rhcs_fenced_protocol_dm_ver_flags_stateful,
  NULL
};

static const int *protocol_dr_ver_flags_fields[] = {
  &hf_rhcs_fenced_protocol_dr_ver_flags_stateful,
  NULL
};

static const int *id_info_flags_fields[] = {
  &hf_rhcs_fenced_id_info_flags_nodedid_is_member,
  NULL
};
static int
dissect_rhcs_fenced_protocol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			     int offset, guint length)
{
  int original_offset;
  proto_tree *tree, *dm_tree, *dr_tree;
  proto_item *item, *dm_item, *dr_item;


  original_offset = offset;
  if ( (length - offset) <  (( 2 * 4 ) * 2 ))
    return 0;

  offset += 0;
  item = proto_tree_add_item(parent_tree, hf_rhcs_fenced_protocol, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_rhcs_fenced_protocol);

  offset += 0;
  item = proto_tree_add_item(tree, hf_rhcs_fenced_protocol_dm_ver, tvb, 
			     offset, -1, TRUE);
  dm_tree = proto_item_add_subtree(item, ett_rhcs_fenced_protocol);

  offset += 0;
  dm_item = proto_tree_add_item(dm_tree, hf_rhcs_fenced_protocol_dm_ver_major, tvb, 
			     offset, 2, TRUE);
  offset += 2;
  dm_item = proto_tree_add_item(dm_tree, hf_rhcs_fenced_protocol_dm_ver_minor, tvb, 
			     offset, 2, TRUE);
  offset += 2;
  dm_item = proto_tree_add_item(dm_tree, hf_rhcs_fenced_protocol_dm_ver_patch, tvb, 
			     offset, 2, TRUE);
  offset += 2;
  dm_item = proto_tree_add_bitmask(dm_tree, tvb, offset, hf_rhcs_fenced_protocol_dm_ver_flags, 
				   ett_rhcs_fenced_protocol_dm_ver_flags, protocol_dm_ver_flags_fields, 
				   TRUE);
  
  offset += 2;
  item = proto_tree_add_item(tree, hf_rhcs_fenced_protocol_dr_ver, tvb, 
			     offset, -1, TRUE);
  dr_tree = proto_item_add_subtree(item, ett_rhcs_fenced_protocol);
  offset += 0;
  dr_item = proto_tree_add_item(dr_tree, hf_rhcs_fenced_protocol_dr_ver_major, tvb, 
			     offset, 2, TRUE);
  offset += 2;
  dr_item = proto_tree_add_item(dr_tree, hf_rhcs_fenced_protocol_dr_ver_minor, tvb, 
			     offset, 2, TRUE);
  offset += 2;
  dr_item = proto_tree_add_item(dr_tree, hf_rhcs_fenced_protocol_dr_ver_patch, tvb, 
			     offset, 2, TRUE);
  offset += 2;
  dr_item = proto_tree_add_bitmask(dr_tree, tvb, offset, hf_rhcs_fenced_protocol_dr_ver_flags, 
				   ett_rhcs_fenced_protocol_dr_ver_flags, protocol_dr_ver_flags_fields, 
				   TRUE);
  offset += 2;
  return length - original_offset;
}

static int
dissect_rhcs_fenced_fd_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			    int offset, guint length, guint32 *id_info_count)
{
  int original_offset;
  proto_tree *fd_info_tree;
  proto_item *fd_info_item;

  original_offset = offset;
  if ( (length - offset) <  ( 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 ) )
    return 0;

  offset += 0;
  fd_info_item = proto_tree_add_item(parent_tree, hf_rhcs_fenced_fd_info, tvb, 
				     offset, -1, TRUE);
  fd_info_tree = proto_item_add_subtree(fd_info_item, ett_rhcs_fenced_fd_info);

  offset += 0;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_fd_info_size, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  *id_info_count = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_id_info_size, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_id_info_count, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_started_count, tvb, 
		      offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_member_count, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_joined_count, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_remove_count, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(fd_info_tree, hf_rhcs_fenced_fd_info_failed_count, tvb, 
		      offset, 4, TRUE);

  offset += 4;

  return offset - original_offset;
}

static int
dissect_rhcs_fenced_id_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			    int offset, guint length)
{
  int original_offset;
  
  original_offset = offset;
  if ( (length - offset) < ( ( 4 * 6 ) + ( 8 * 2 )) )
    return 0;

  offset += 0;
  proto_tree *id_info_tree;
  proto_item *id_info_item;

  id_info_item = proto_tree_add_item(parent_tree, hf_rhcs_fenced_id_info, tvb, 
				     offset, -1, TRUE);
  id_info_tree = proto_item_add_subtree(id_info_item, ett_rhcs_fenced_id_info);

  offset += 0;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_nodeid, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_bitmask(id_info_tree, tvb, offset, hf_rhcs_fenced_id_info_flags, 
			 ett_rhcs_fenced_id_info_flags, id_info_flags_fields,
			 TRUE);
  offset += 4;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_fence_external_node, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_fence_master, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_fence_how, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_pad, tvb, 
		      offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_fence_time, tvb, 
		      offset, 8, TRUE);
  offset += 8;
  proto_tree_add_item(id_info_tree, hf_rhcs_fenced_id_info_fence_external_time, tvb, 
		      offset, 8, TRUE);
  offset += 8;
  return offset - original_offset;
}

static int
dissect_rhcs_fenced_start_or_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
				      int offset, guint length, int hf, gint ett)
{
  int original_offset;
  proto_tree *tree, *fd_info_tree;
  proto_item *item, *fd_info_item;
  guint32 i, id_info_count;
  int d;

  original_offset = offset;
  if ( (length - offset) <  ( 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 ) )
    return 0;

  offset += 0;
  item = proto_tree_add_item(parent_tree, hf, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett);

  offset += dissect_rhcs_fenced_fd_info(tvb, pinfo, tree, offset, length, &id_info_count);
  if (original_offset == offset)
    goto out;
 
  for (i = 0; i < id_info_count; i++)
    {
      d = dissect_rhcs_fenced_id_info(tvb, pinfo, tree, offset, length);
      if ( d == 0 )
	goto out;

      offset += d;
    }
 
 out:
  return length - original_offset;
}

static int
dissect_rhcs_fenced_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			  int offset, guint length)
{
  return dissect_rhcs_fenced_start_or_complete(tvb, pinfo, parent_tree, offset, length,
					       hf_rhcs_fenced_start,
					       ett_rhcs_fenced_start);
}

static int
dissect_rhcs_fenced_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			  int offset, guint length)
{
  return dissect_rhcs_fenced_start_or_complete(tvb, pinfo, parent_tree, offset, length,
					       hf_rhcs_fenced_complete,
					       ett_rhcs_fenced_complete);
}


static int
dissect_rhcs_fenced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		    gboolean daemon)
{
  guint length;
  int offset;

  proto_tree *fenced_tree, *tree, *version_tree;
  proto_item *item, *version_item;
  guint32 type;

  length = tvb_length(tvb);
  if ( length < ( 2 * 3 ) + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 8)
    return 0;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", daemon?"fenced:daemon": "fenced:default");

  if (!parent_tree)
    goto out;

  offset = 0;
  item = proto_tree_add_item(parent_tree, proto_rhcs_fenced, tvb, 
			     offset, -1, TRUE);
  fenced_tree = proto_item_add_subtree(item, ett_rhcs_fenced);

  offset += 0;
  item = proto_tree_add_item(fenced_tree, hf_rhcs_fenced_header, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_rhcs_fenced_header);

  offset += 0;
  version_item = proto_tree_add_item(tree, 
				     hf_rhcs_fenced_header_version, 
				     tvb, offset, -1, TRUE);
  version_tree = proto_item_add_subtree(version_item, 
					ett_rhcs_fenced_header_version);

  offset += 0;
  proto_tree_add_item(version_tree, hf_rhcs_fenced_header_version_major, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(version_tree, hf_rhcs_fenced_header_version_minor, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(version_tree, hf_rhcs_fenced_header_version_patch, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  type = tvb_get_letohs(tvb, offset);
  proto_tree_add_item(tree, hf_rhcs_fenced_header_type, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(tree, hf_rhcs_fenced_header_nodeid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_rhcs_fenced_header_to_nodeid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_rhcs_fenced_header_global_id, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_rhcs_fenced_header_flags, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  switch (type)
    {
    default:
      proto_tree_add_item(tree, hf_rhcs_fenced_header_msgdata, 
			  tvb, offset, 4, TRUE);
      break;
    }

  offset += 4;
  proto_tree_add_item(tree, hf_rhcs_fenced_header_pad1, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_rhcs_fenced_header_pad2, 
		      tvb, offset, 8, TRUE);

  offset += 8;
  switch (type)
    {
    case FD_MSG_START:
      dissect_rhcs_fenced_start(tvb, pinfo, fenced_tree, offset, length);
      break;
    case FD_MSG_COMPLETE:
      dissect_rhcs_fenced_complete(tvb, pinfo, fenced_tree, offset, length);
      break;
    case FD_MSG_PROTOCOL:
      dissect_rhcs_fenced_protocol(tvb, pinfo, fenced_tree, offset, length);
      break;
      /* TODO: FD_MSG_VICTIM_DONE,  FD_MSG_EXTERNAL */
    default:
      break;
    }
 out:
  return length;
}

static int
dissect_rhcs_fenced_daemon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  return dissect_rhcs_fenced(tvb, pinfo, parent_tree, TRUE);
}

static int
dissect_rhcs_fenced_default(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  return dissect_rhcs_fenced(tvb, pinfo, parent_tree, FALSE);
}



void
proto_register_rhcs_fenced(void)
{
  /* Setup list of fields */
  static hf_register_info hf[] = {
    { &hf_rhcs_fenced_header,
      { "Fenced header", "rhcs_fenced.fd_header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_version,
      { "Fenced header version", "rhcs_fenced.fd_header.version",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_version_major,
      { "Fenced header major version", "rhcs_fenced.fd_header.version.major",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_version_minor,
      { "Fenced header minor version", "rhcs_fenced.fd_header.version.minor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_version_patch,
      { "Fenced header patch level", "rhcs_fenced.fd_header.version.patch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_type,
      { "Fenced header type", "rhcs_fenced.fd_header.type",
        FT_UINT16, BASE_DEC, VALS(vals_header_type), 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_nodeid,
      { "Sender node", "rhcs_fenced.fd_header.nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_to_nodeid,
      { "Recipient node", "rhcs_fenced.fd_header.to_nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_global_id,
      { "Global unique id for this domain", "rhcs_fenced.fd_header.global_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_flags,
      { "Fenced header flags", "rhcs_fenced.fd_header.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_msgdata,
      { "Fenced header msgdata", "rhcs_fenced.fd_header.msgdata",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_pad1,
      { "Padding", "rhcs_fenced.fd_header.pad1",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_header_pad2,
      { "Padding", "rhcs_fenced.fd_header.pad2",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rhcs_fenced_protocol,
      { "Protocol", "rhcs_fenced.protocol",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rhcs_fenced_protocol_dm_ver,
      { "Max version of protocol", "rhcs_fenced.protocol.dm_ver",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dm_ver_major,
      { "Major version of dm_ver", "rhcs_fenced.protocol.dm_ver.major",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dm_ver_minor,
      { "Minor version of dm_ver", "rhcs_fenced.protocol.dm_ver.minor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dm_ver_patch,
      { "Patch version of dm_ver", "rhcs_fenced.protocol.dm_ver.patch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dm_ver_flags,
      { "Flags of dm_ver", "rhcs_fenced.protocol.dm_ver.flags",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dm_ver_flags_stateful,
      { "dm_ver stateful", "rhcs_fenced.protocol.dm_ver.flags.stateful",
	FT_BOOLEAN, 16, NULL, PV_STATEFUL,
	NULL, HFILL }},

    { &hf_rhcs_fenced_protocol_dr_ver,
      { "Running version of protocol", "rhcs_fenced.protocol.dr_ver",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dr_ver_major,
      { "Major version of dr_ver", "rhcs_fenced.protocol.dr_ver.major",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dr_ver_minor,
      { "Minor version of dr_ver", "rhcs_fenced.protocol.dr_ver.minor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dr_ver_patch,
      { "Patch version of dr_ver", "rhcs_fenced.protocol.dr_ver.patch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dr_ver_flags,
      { "Flags of dr_ver", "rhcs_fenced.protocol.dr_ver.flags",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_protocol_dr_ver_flags_stateful,
      { "dr_ver stateful", "rhcs_fenced.protocol.dr_ver.flags.stateful",
	FT_BOOLEAN, 16, NULL, PV_STATEFUL,
	NULL, HFILL }},

    { &hf_rhcs_fenced_start,
      { "Start", "rhcs_fenced.start",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info,
      { "Fence domain info", "rhcs_fenced.fd_info",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_fd_info_size,
      { "Size of fd info", "rhcs_fenced.fd_info.fd_info_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_id_info_size,
      { "Size of id info", "rhcs_fenced.fd_info.id_info_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_id_info_count,
      { "Count of id infos", "rhcs_fenced.fd_info.id_info_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_started_count,
      { "Count of started", "rhcs_fenced.fd_info.started_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_member_count,
      { "Count of members", "rhcs_fenced.fd_info.member_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_joined_count,
      { "Count of joined", "rhcs_fenced.fd_info.joined_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_remove_count,
      { "Count of remove", "rhcs_fenced.fd_info.remove_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_fd_info_failed_count,
      { "Count of failed", "rhcs_fenced.fd_info.failed_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rhcs_fenced_id_info,
      { "ID info", "rhcs_fenced.id_info",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_nodeid,
      { "Node id", "rhcs_fenced.id_info.nodeid",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_flags,
      { "Flags", "rhcs_fenced.id_info.flags",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_flags_nodedid_is_member,
      { "Member?", "rhcs_fenced.id_info.flags.nodedid_is_member",
        FT_BOOLEAN, 32, NULL, IDI_NODEID_IS_MEMBER,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_fence_external_node,
      { "Fence external node", "rhcs_fenced.id_info.fence_external_node",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_fence_master,
      { "Fence master", "rhcs_fenced.id_info.fence_master",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_fence_how,
      { "Fence how", "rhcs_fenced.id_info.fence_how",
        FT_INT32, BASE_DEC, VALS(vals_fence_how), 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_pad,
      { "Padding", "rhcs_fenced.id_info.pad",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_fence_time,
      { "Time", "rhcs_fenced.id_info.fence_time",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_rhcs_fenced_id_info_fence_external_time,
      { "External Time", "rhcs_fenced.id_info.fence_external_time",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_rhcs_fenced_complete,
      { "Complete", "rhcs_fenced.complete",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_rhcs_fenced,
    &ett_rhcs_fenced_header,
    &ett_rhcs_fenced_header_version,
    &ett_rhcs_fenced_protocol,
    &ett_rhcs_fenced_protocol_dm_ver,
    &ett_rhcs_fenced_protocol_dr_ver,
    &ett_rhcs_fenced_protocol_dm_ver_flags,
    &ett_rhcs_fenced_protocol_dr_ver_flags,
    &ett_rhcs_fenced_start,
    &ett_rhcs_fenced_fd_info,
    &ett_rhcs_fenced_id_info,
    &ett_rhcs_fenced_id_info_flags,
    &ett_rhcs_fenced_complete,
  };
  
  proto_rhcs_fenced = proto_register_protocol("Protocol used in fenced of rhcs",
					      "RHCS/fenced", "rhcs_fenced");
  proto_register_field_array(proto_rhcs_fenced, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rhcs_fenced(void)
{
  static gboolean register_dissector = FALSE;
  static dissector_handle_t rhcs_fenced_daemon_handle;
  static dissector_handle_t rhcs_fenced_default_handle;

  if (register_dissector) {
    dissector_delete_string("openais_cpg.mar_name.value", 
			    RHCS_FENCED_DAEMON_NAME, 
			    rhcs_fenced_daemon_handle);
    dissector_delete_string("openais_cpg.mar_name.value", 
			    RHCS_FENCED_DEFAULT_NAME, 
			    rhcs_fenced_default_handle);
  } else {
    rhcs_fenced_daemon_handle = new_create_dissector_handle(dissect_rhcs_fenced_daemon,
							    proto_rhcs_fenced);
    rhcs_fenced_default_handle = new_create_dissector_handle(dissect_rhcs_fenced_default,
							     proto_rhcs_fenced);
    register_dissector = TRUE;
  }
  dissector_add_string("openais_cpg.mar_name.value", 
		       RHCS_FENCED_DAEMON_NAME,
		       rhcs_fenced_daemon_handle);
  dissector_add_string("openais_cpg.mar_name.value", 
		       RHCS_FENCED_DEFAULT_NAME,
		       rhcs_fenced_default_handle);
}
