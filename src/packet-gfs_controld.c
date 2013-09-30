/* packet-gfs_controld.c
 * Routines for dissecting protocol used in gfs_controld
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
#include <string.h>

#include <epan/packet.h>

#define GFS_CONTROLD_DAEMON_NAME "gfs:controld"
#define GFS_CONTROLD_MOUNT_PREFIX "gfs:mount:"

/* Forward declaration we need below */
void proto_reg_handoff_gfs_controld(void);

/* Initialize the protocol and registered fields */
static int proto_gfs_controld = -1;

static int hf_gfs_controld_header = -1;
static int hf_gfs_controld_header_version = -1;
static int hf_gfs_controld_header_version_major = -1;
static int hf_gfs_controld_header_version_minor = -1;
static int hf_gfs_controld_header_version_patch = -1;
static int hf_gfs_controld_header_type = -1;
static int hf_gfs_controld_header_nodeid = -1;
static int hf_gfs_controld_header_to_nodeid = -1;
static int hf_gfs_controld_header_global_id = -1;
static int hf_gfs_controld_header_flags = -1;
static int hf_gfs_controld_header_msgdata = -1;
static int hf_gfs_controld_header_msgdata_seq = -1;
static int hf_gfs_controld_header_msgdata_error = -1;
static int hf_gfs_controld_header_msgdata_ro = -1;
static int hf_gfs_controld_header_pad1  = -1;
static int hf_gfs_controld_header_pad2  = -1;

static int hf_gfs_controld_protocol = -1;
#define VAR_protocol(X) \
  static int hf_gfs_controld_protocol_##X##_ver = -1; \
  static int hf_gfs_controld_protocol_##X##_ver_major = -1; \
  static int hf_gfs_controld_protocol_##X##_ver_minor = -1; \
  static int hf_gfs_controld_protocol_##X##_ver_patch = -1; \
  static int hf_gfs_controld_protocol_##X##_ver_flags = -1; \
  \
  static int ett_gfs_controld_protocol_##X##_ver      = -1
VAR_protocol(dm);
VAR_protocol(km);
VAR_protocol(dr);
VAR_protocol(kr);

static int hf_gfs_controld_recovery_result_jid = -1;
static int hf_gfs_controld_recovery_result_result = -1;

static int hf_gfs_controld_mg_info = -1;
static int hf_gfs_controld_mg_info_mg_info_size = -1;
static int hf_gfs_controld_mg_info_id_info_size = -1;
static int hf_gfs_controld_mg_info_id_info_count = -1;
static int hf_gfs_controld_mg_info_started_count = -1;
static int hf_gfs_controld_mg_info_member_count = -1;
static int hf_gfs_controld_mg_info_joined_count = -1;
static int hf_gfs_controld_mg_info_remove_count = -1;
static int hf_gfs_controld_mg_info_failed_count = -1;
static int hf_gfs_controld_mg_info_first_recovery_needed = -1;
static int hf_gfs_controld_mg_info_first_recovery_master = -1;

static int hf_gfs_controld_id_info = -1;
static int hf_gfs_controld_id_info_nodeid = -1;
static int hf_gfs_controld_id_info_jid = -1;
static int hf_gfs_controld_id_info_flags = -1;

/* gfs_header flags */
#define GFS_MFLG_JOINING   1  /* accompanies start, we are joining */

static int hf_gfs_controld_header_flags_joining   = -1;

static const int *header_flags_fields[] = {
  &hf_gfs_controld_header_flags_joining,
  NULL,
};

#define GFS_MSG_PROTOCOL		1
#define GFS_MSG_START			2
#define GFS_MSG_MOUNT_DONE		3
#define GFS_MSG_FIRST_RECOVERY_DONE	4
#define GFS_MSG_RECOVERY_RESULT		5
#define GFS_MSG_REMOUNT			6
#define GFS_MSG_WITHDRAW		7
#define GFS_MSG_WITHDRAW_ACK		8

static const value_string vals_header_type[] = {
  { GFS_MSG_PROTOCOL,                "protocol"              },
  { GFS_MSG_START,                   "start"                 },
  { GFS_MSG_MOUNT_DONE,              "mount-done"            },
  { GFS_MSG_FIRST_RECOVERY_DONE,     "first-recovery-done"   },
  { GFS_MSG_RECOVERY_RESULT,         "recovery-result"       },
  { GFS_MSG_REMOUNT,                 "remount"               },
  { GFS_MSG_WITHDRAW,                "withdraw"              },
  { GFS_MSG_WITHDRAW_ACK,            "withdraw-ack"          },
  { 0,                               NULL                    },
};

#define IDI_NODEID_IS_MEMBER	0x00000001
#define IDI_JID_NEEDS_RECOVERY	0x00000002
#define IDI_MOUNT_DONE		0x00000008
#define IDI_MOUNT_ERROR		0x00000010
#define IDI_MOUNT_RO		0x00000020
#define IDI_MOUNT_SPECTATOR	0x00000040

static int hf_gfs_controld_id_info_flags_nodeid_is_member = -1;
static int hf_gfs_controld_id_info_flags_jid_needs_recovery = -1;
static int hf_gfs_controld_id_info_flags_mount_done = -1;
static int hf_gfs_controld_id_info_flags_mount_error = -1;
static int hf_gfs_controld_id_info_flags_mount_ro = -1;
static int hf_gfs_controld_id_info_flags_mount_spectator = -1;

static const int *id_info_flags_fields[] = {
  &hf_gfs_controld_id_info_flags_nodeid_is_member,
  &hf_gfs_controld_id_info_flags_jid_needs_recovery,
  &hf_gfs_controld_id_info_flags_mount_done,
  &hf_gfs_controld_id_info_flags_mount_error,
  &hf_gfs_controld_id_info_flags_mount_ro,
  &hf_gfs_controld_id_info_flags_mount_spectator,
  NULL
};

#define LM_RD_GAVEUP 308
#define LM_RD_SUCCESS 309
static const value_string vals_recovery_result_result[] = {
  { LM_RD_GAVEUP,  "Give up" },
  { LM_RD_SUCCESS, "Successful" },
  { 0,             NULL },
};

/* Initialize the subtree pointers */
static gint ett_gfs_controld        = -1;
static gint ett_gfs_controld_header = -1;
static gint ett_gfs_controld_header_version = -1;
static gint ett_gfs_controld_header_flags = -1;
static gint ett_gfs_controld_mg_info = -1;
static gint ett_gfs_controld_id_info = -1;
static gint ett_gfs_controld_id_info_flags = -1;
static gint ett_gfs_controld_protocol = -1;


static int
dissect_gfs_controld_protocol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			     int offset, guint length)
{
  int original_offset;

  proto_tree *protocol_tree, *tree;
  proto_item *item;


  original_offset = offset;
  if ( (length - offset) <  (( 2 * 4 ) * 4 ))
    return 0;

  offset += 0;
  item = proto_tree_add_item(parent_tree, hf_gfs_controld_protocol, tvb, 
			     offset, -1, TRUE);
  protocol_tree = proto_item_add_subtree(item, ett_gfs_controld_protocol);


#define LOAD_protocol(X) \
  item = proto_tree_add_item(protocol_tree, hf_gfs_controld_protocol_##X##_ver, tvb, \
			     offset, -1, TRUE);				\
  tree = proto_item_add_subtree(item, ett_gfs_controld_protocol);	\
									\
  offset += 0;								\
  item = proto_tree_add_item(tree, hf_gfs_controld_protocol_##X##_ver_major, tvb, \
			     offset, 2, TRUE);				\
  offset += 2;								\
  item = proto_tree_add_item(tree, hf_gfs_controld_protocol_##X##_ver_minor, tvb, \
			     offset, 2, TRUE);				\
  offset += 2;								\
  item = proto_tree_add_item(tree, hf_gfs_controld_protocol_##X##_ver_patch, tvb, \
			     offset, 2, TRUE);				\
  offset += 2;								\
  item = proto_tree_add_item(tree, hf_gfs_controld_protocol_##X##_ver_flags, tvb, \
				offset, 2, TRUE);			\
  offset += 2

  offset += 0;  
  LOAD_protocol(dm);
  LOAD_protocol(km);
  LOAD_protocol(dr);
  LOAD_protocol(kr);

  return length - original_offset;
}

static int
dissect_gfs_controld_mg_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			     int offset, guint length, guint32 *id_info_count)
{
  int original_offset;
  
  proto_tree *tree;
  proto_item *item;

  original_offset = offset;
  if ( (length - offset) <  ( 4 * 10 ) )
    return 0;

  offset += 0;
  item = proto_tree_add_item(parent_tree, hf_gfs_controld_mg_info, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_gfs_controld_mg_info);

  offset += 0;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_mg_info_size, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_id_info_size, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  *id_info_count = tvb_get_letohl(tvb, offset);
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_id_info_count, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_started_count, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_member_count, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_joined_count, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_remove_count, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_failed_count, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_first_recovery_needed, 
		      tvb, offset, 4, TRUE);
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_mg_info_first_recovery_master, 
		      tvb, offset, 4, TRUE);
  offset += 4;

  return offset - original_offset;
}

static int
dissect_gfs_controld_id_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			     int offset, guint length)
{
  int original_offset;
  
  proto_tree *tree;
  proto_item *item;


  original_offset = offset;
  if ( (length - offset) <  ( 4  * 3 ) )
    return 0;

  offset += 0;
  item = proto_tree_add_item(parent_tree, hf_gfs_controld_id_info, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_gfs_controld_id_info);

  offset += 0;
  proto_tree_add_item(tree, hf_gfs_controld_id_info_nodeid, 
		      tvb, offset, 4, TRUE);
  
  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_id_info_jid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset, hf_gfs_controld_id_info_flags, 
			 ett_gfs_controld_id_info_flags, id_info_flags_fields,
			 TRUE); 
  offset += 4;

  return offset - original_offset;
}


static int
dissect_gfs_controld_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			   int offset, guint length)
{
  int original_offset;
  guint32 i, id_info_count;
  int d;


  original_offset = offset;
  offset += dissect_gfs_controld_mg_info(tvb, pinfo, parent_tree, offset, length, &id_info_count);
  if (original_offset == offset)
    goto out;

  for (i = 0; i < id_info_count; i++)
    {
      d = dissect_gfs_controld_id_info(tvb, pinfo, parent_tree, offset, length);
      if ( d == 0 )
	goto out;

      offset += d;
    }

 out:  
  return offset - original_offset;
}

static int
dissect_gfs_controld_recovery_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
				     int offset, guint length)
{
    int original_offset;
    proto_tree *tree = parent_tree;
    
    original_offset = offset;
    if ( (length - offset) <  ( 4  * 2 ) )
      return 0;

    offset += 0;
    proto_tree_add_item(tree, hf_gfs_controld_recovery_result_jid, 
			tvb, offset, 4, TRUE);
    offset += 4;
    proto_tree_add_item(tree, hf_gfs_controld_recovery_result_result, 
			tvb, offset, 4, TRUE);
    offset += 4;
  
    return offset - original_offset;
    
}

static int
dissect_gfs_controld(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		       const gchar* col_str)
{
  guint length;
  int offset;
  int d;

  proto_tree *gfs_controld_tree, *tree, *version_tree;
  proto_item *item, *version_item;
  guint32 type;

  guint32 msgdata;


  length = tvb_length(tvb);

  if ( length < ( 2 * 3 ) + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 8 )
    return 0;

  type = tvb_get_letohs(tvb, ( 2 * 3 ));
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s :%s)", 
			  col_str, val_to_str(type, vals_header_type, "UNKNOWN-TYPE"));

  if (!parent_tree)
    goto out;

  offset = 0;
  item = proto_tree_add_item(parent_tree, proto_gfs_controld, tvb, 
			     offset, -1, TRUE);
  gfs_controld_tree = proto_item_add_subtree(item, ett_gfs_controld);

  offset += 0;
  item = proto_tree_add_item(gfs_controld_tree, hf_gfs_controld_header, tvb, 
			     offset, -1, TRUE);
  tree = proto_item_add_subtree(item, ett_gfs_controld_header);

  offset += 0;
  version_item = proto_tree_add_item(tree, 
				     hf_gfs_controld_header_version, 
				     tvb, offset, -1, TRUE);
  version_tree = proto_item_add_subtree(version_item, 
					ett_gfs_controld_header_version);

  offset += 0;
  proto_tree_add_item(version_tree, hf_gfs_controld_header_version_major, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(version_tree, hf_gfs_controld_header_version_minor, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(version_tree, hf_gfs_controld_header_version_patch, 
		      tvb, offset, 2, TRUE);

  offset += 2;
  proto_tree_add_item(tree, hf_gfs_controld_header_type, 
		      tvb, offset, 2, TRUE);
	

  offset += 2;
  proto_tree_add_item(tree, hf_gfs_controld_header_nodeid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_header_to_nodeid, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_header_global_id, 
		      tvb, offset, 4, TRUE);
  
  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset, hf_gfs_controld_header_flags, 
			 ett_gfs_controld_header_flags, header_flags_fields,
			 TRUE); 

  offset += 4;
  msgdata = tvb_get_letohl(tvb, offset);
  switch (type)
    {
    case GFS_MSG_START:
      proto_tree_add_item(tree, hf_gfs_controld_header_msgdata_seq, 
			  tvb, offset, 4, TRUE);
      break;
    case GFS_MSG_MOUNT_DONE:
      proto_tree_add_item(tree, hf_gfs_controld_header_msgdata_error, 
			  tvb, offset, 4, TRUE);
      break;
    case GFS_MSG_REMOUNT:
      proto_tree_add_item(tree, hf_gfs_controld_header_msgdata_ro, 
			  tvb, offset, 4, TRUE);
      break;
    default:
      proto_tree_add_item(tree, hf_gfs_controld_header_msgdata, 
			  tvb, offset, 4, TRUE);
      break;
    }

  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_header_pad1, 
		      tvb, offset, 4, TRUE);

  offset += 4;
  proto_tree_add_item(tree, hf_gfs_controld_header_pad2, 
		      tvb, offset, 8, TRUE);

  offset += 8;
  switch (type)
    {
    case GFS_MSG_PROTOCOL:
      offset += dissect_gfs_controld_protocol(tvb, pinfo, gfs_controld_tree, offset, length);
      break;      
    case GFS_MSG_START:
      offset += dissect_gfs_controld_start(tvb, pinfo, gfs_controld_tree, offset, length);
      break;
    case GFS_MSG_RECOVERY_RESULT:
      offset += dissect_gfs_controld_recovery_result(tvb, pinfo, gfs_controld_tree, offset, length);
      break;
    }

 out:
  return length;
}

static int
dissect_gfs_controld_daemon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
  return dissect_gfs_controld(tvb, pinfo, parent_tree, "gfs:controld");
}

void
proto_register_gfs_controld(void)
{
  /* Setup list of fields */
  static hf_register_info hf[] = {
    { &hf_gfs_controld_header,
      { "header", "gfs_controld.gfs_header",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_version,
      { "header version", "gfs_controld.gfs_header.version",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_version_major,
      { "header major version", "gfs_controld.gfs_header.version.major",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_version_minor,
      { "header minor version", "gfs_controld.gfs_header.version.minor",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_version_patch,
      { "header patch level", "gfs_controld.gfs_header.version.patch",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_type,
      { "header type", "gfs_controld.gfs_header.type",
        FT_UINT16, BASE_DEC, VALS(vals_header_type), 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_nodeid,
      { "Sender node", "gfs_controld.gfs_header.nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_to_nodeid,
      { "Recipient node", "gfs_controld.gfs_header.to_nodeid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_global_id,
      { "Global unique id for this lockspace", "gfs_controld.gfs_header.global_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_flags,
      { "header flags", "gfs_controld.gfs_header.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_flags_joining,
      { "Joining", "gfs_controld.gfs_header.flags.joining",
	FT_BOOLEAN, 32, NULL, GFS_MFLG_JOINING,
	NULL, HFILL }},

    { &hf_gfs_controld_header_msgdata,
      { "msgdata", "gfs_controld.gfs_header.msgdata",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_msgdata_seq,
      { "sequnce number", "gfs_controld.gfs_header.msgdata_seq",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_msgdata_error,
      { "error", "gfs_controld.gfs_header.msgdata_error",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_msgdata_ro,
	  { "read only", "gfs_controld.gfs_header.msgdata_ro",
	    FT_UINT32, BASE_DEC, NULL, 0x0,
	    NULL, HFILL }},
    { &hf_gfs_controld_header_pad1,
      { "Padding", "gfs_controld.gfs_header.pad1",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_header_pad2,
      { "Padding", "gfs_controld.gfs_header.pad2",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_gfs_controld_recovery_result_jid,
      { "Jid in recovery result command", "gfs_controld.recovery_result_jid",
	FT_INT32, BASE_DEC, NULL, 0x0, 
	NULL, HFILL }},
    { &hf_gfs_controld_recovery_result_result,
      { "recovery result", "gfs_controld.recovery_result_result",
	FT_INT32, BASE_DEC, VALS(vals_recovery_result_result), 0x0, 
	NULL, HFILL }},
    
    { &hf_gfs_controld_mg_info,
      { "mg_info", "gfs_controld.mg_info",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_mg_info_size,
      { "Size of mg_info", "gfs_controld.mg_info.mg_info_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_id_info_size,
      { "Size of id_info", "gfs_controld.mg_info.id_info_size",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_id_info_count,
      { "Count of id_infos", "gfs_controld.mg_info.id_info_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_started_count,
      { "Count of started", "gfs_controld.mg_info.started_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_member_count,
      { "Count of members", "gfs_controld.mg_info.member_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_joined_count,
      { "Count of joined", "gfs_controld.mg_info.joined_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_remove_count,
      { "Count of remove", "gfs_controld.mg_info.remove_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_failed_count,
      { "Count of failed", "gfs_controld.mg_info.failed_count",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_first_recovery_needed,
      { "First recovery needed", "gfs_controld.mg_info.first_recovery_needed",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_mg_info_first_recovery_master,
      { "First recovery master", "gfs_controld.mg_info.first_recovery_master",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_id_info,
      { "id_info", "gfs_controld.id_info",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_id_info_nodeid,
      { "Node id", "gfs_controld.id_info.nodeid",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_id_info_jid,
      { "Journal id", "gfs_controld.id_info.jid",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags,
      { "Flags in id_info", "gfs_controld.id_info.flags",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags_nodeid_is_member,
      { "nodeid is member?", "gfs_controld.id_info.flags.nodeid_is_member",
	FT_BOOLEAN, 32, NULL, IDI_NODEID_IS_MEMBER,
	NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags_jid_needs_recovery,
      { "jid needs recovery?", "gfs_controld.id_info.flags.jid_needs_recovery",
	FT_BOOLEAN, 32, NULL, IDI_JID_NEEDS_RECOVERY,
	NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags_mount_done,
      { "mount done", "gfs_controld.id_info.flags.mount_done",
	FT_BOOLEAN, 32, NULL, IDI_MOUNT_DONE,
	NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags_mount_error,
      { "mount error", "gfs_controld.id_info.flags.mount_error",
	FT_BOOLEAN, 32, NULL, IDI_MOUNT_ERROR,
	NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags_mount_ro,
      { "read only", "gfs_controld.id_info.flags.mount_ro",
	FT_BOOLEAN, 32, NULL, IDI_MOUNT_RO,
	NULL, HFILL }},
    { &hf_gfs_controld_id_info_flags_mount_spectator,
      { "spectator", "gfs_controld.id_info.flags.mount_spectator",
	FT_BOOLEAN, 32, NULL, IDI_MOUNT_SPECTATOR,
	NULL, HFILL }},

    { &hf_gfs_controld_protocol,
      { "protocol", "gfs_controld.protocol",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
#define ATTACH_protocol(X,Y)		   \
    { &hf_gfs_controld_protocol_##X##_ver, \
      { "Protocol version of " Y, "gfs_controld.protocol." #X "_ver", \
        FT_NONE, BASE_NONE, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_gfs_controld_protocol_##X##_ver_major, \
      { "Major version of " Y, "gfs_controld.protocol." #X "_ver.major", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_gfs_controld_protocol_##X##_ver_minor, \
      { "Minor version of " Y, "gfs_controld.protocol." #X "_ver.minor", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_gfs_controld_protocol_##X##_ver_patch, \
      { "Patch level of " Y, "gfs_controld.protocol." #X "_ver.patch", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }}, \
    { &hf_gfs_controld_protocol_##X##_ver_flags, \
      { "Flags of " Y, "gfs_controld.protocol." #X "_ver.flags", \
        FT_UINT16, BASE_DEC, NULL, 0x0, \
        NULL, HFILL }} 

    ATTACH_protocol(dm, "daemon max"),
    ATTACH_protocol(km, "kernel max"),
    ATTACH_protocol(dr, "daemon running"),
    ATTACH_protocol(kr, "kernel running"),

  };

  static gint *ett[] = {
    &ett_gfs_controld,
    &ett_gfs_controld_header,
    &ett_gfs_controld_header_version,
    &ett_gfs_controld_header_flags,
    &ett_gfs_controld_mg_info,
    &ett_gfs_controld_id_info,
    &ett_gfs_controld_id_info_flags,
    &ett_gfs_controld_protocol,
    &ett_gfs_controld_protocol_dm_ver,
    &ett_gfs_controld_protocol_km_ver,
    &ett_gfs_controld_protocol_dr_ver,
    &ett_gfs_controld_protocol_kr_ver,
  };
  
  proto_gfs_controld = proto_register_protocol("Protocol used in gfs_controld",
					      "gfs_controld", "gfs_controld");
  proto_register_field_array(proto_gfs_controld, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

static int
dissect_gfs_controld_mount(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
  if (pinfo->private_data &&
      strstr(pinfo->private_data, GFS_CONTROLD_MOUNT_PREFIX))
    return dissect_gfs_controld(tvb, pinfo, parent_tree, pinfo->private_data);
  else
    return 0;
}

void
proto_reg_handoff_gfs_controld(void)
{
  static gboolean register_dissector = FALSE;
  static dissector_handle_t gfs_controld_daemon_handle;
  static dissector_handle_t gfs_controld_mg_handle;

  if (register_dissector) {
    dissector_delete_string("openais_cpg.mar_name.value", 
			    GFS_CONTROLD_DAEMON_NAME, 
			    gfs_controld_daemon_handle);
  } else {
    gfs_controld_daemon_handle = new_create_dissector_handle(dissect_gfs_controld_daemon,
							     proto_gfs_controld);
    register_dissector = TRUE;
  }

  dissector_add_string("openais_cpg.mar_name.value", 
		       GFS_CONTROLD_DAEMON_NAME,
		       gfs_controld_daemon_handle);
  heur_dissector_add("openais_cpg", 
		     dissect_gfs_controld_mount, 
		     proto_gfs_controld);
}
