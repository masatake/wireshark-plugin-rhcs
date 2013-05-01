/* packet-clvmd.c
 * Routines for dissecting protocol used in cluster LVM daemon
 * Copyright 2009, Masatake YAMATO <yamato@redhat.com>
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

#define CLVMD_CMAN_TGTPORT 11

/* 
 * Taken from LVM2.2.02.33/daemons/clvmd/clvm.h 
 */

/* Commands */
#define CLVMD_CMD_REPLY    1
#define CLVMD_CMD_VERSION  2	/* Send version around cluster when we start */
#define CLVMD_CMD_GOAWAY   3	/* Die if received this - we are running 
				   an incompatible version */
#define CLVMD_CMD_TEST     4	/* Just for mucking about */

#define CLVMD_CMD_LOCK              30
#define CLVMD_CMD_UNLOCK            31

/* Lock/Unlock commands */
#define CLVMD_CMD_LOCK_LV           50
#define CLVMD_CMD_LOCK_VG           51

/* Misc functions */
#define CLVMD_CMD_REFRESH	    40
#define CLVMD_CMD_GET_CLUSTERNAME   41
#define CLVMD_CMD_SET_DEBUG	    42
#define CLVMD_CMD_VG_BACKUP	    43
#define CLVMD_CMD_RESTART	    44
#define CLVMD_CMD_SYNC_NAMES	    45



/* Flags */
#define CLVMD_FLAG_LOCAL        1	/* Only do this on the local node */
#define CLVMD_FLAG_SYSTEMLV     2	/* Data in system LV under my node name */
#define CLVMD_FLAG_NODEERRS     4       /* Reply has errors in node-specific portion */

/* /usr/include/asm-generic/errno-base.h */
#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	EIO		 5	/* I/O error */
#define	ENOMEM		12	/* Out of memory */
#define	ENOSPC		28	/* No space left on device */
#define	ENAMETOOLONG	36      /* File name too long */
#define	EXFULL		54	/* Exchange full */
#define	ETIME		62	/* Timer expired */
#define	EOPNOTSUPP	95	/* Operation not supported on transport endpoint */

/* lib/locking/locking.h */
#define LCK_TYPE_MASK	0x00000007U

#define LCK_NULL	0x00000000U	/* LCK$_NLMODE */
#define LCK_READ	0x00000001U	/* LCK$_CRMODE */
					/* LCK$_CWMODE */
#define LCK_PREAD       0x00000003U	/* LCK$_PRMODE */
#define LCK_WRITE	0x00000004U	/* LCK$_PWMODE */
#define LCK_EXCL	0x00000005U	/* LCK$_EXMODE */
#define LCK_UNLOCK      0x00000006U	/* This is ours */

#define LCK_SCOPE_MASK	0x00000008U
#define LCK_VG		0x00000000U
#define LCK_LV		0x00000008U

#define LCK_NONBLOCK	0x00000010U	/* Don't block waiting for lock? */
#define LCK_HOLD	0x00000020U	/* Hold lock when lock_vol returns? */
#define LCK_LOCAL	0x00000040U	/* Don't propagate to other nodes */


#define LCK_CLUSTER_VG	0x00000080U	/* VG is clustered */


/* Common combinations */
#define LCK_NONE		(LCK_VG | LCK_NULL)

#define LCK_VG_READ		(LCK_VG | LCK_READ | LCK_HOLD)
#define LCK_VG_WRITE		(LCK_VG | LCK_WRITE | LCK_HOLD)
#define LCK_VG_UNLOCK		(LCK_VG | LCK_UNLOCK)

#define LCK_LV_EXCLUSIVE	(LCK_LV | LCK_EXCL | LCK_NONBLOCK)
#define LCK_LV_SUSPEND		(LCK_LV | LCK_WRITE | LCK_NONBLOCK)
#define LCK_LV_RESUME		(LCK_LV | LCK_UNLOCK | LCK_NONBLOCK)
#define LCK_LV_ACTIVATE		(LCK_LV | LCK_READ | LCK_NONBLOCK)
#define LCK_LV_DEACTIVATE	(LCK_LV | LCK_NULL | LCK_NONBLOCK)


/*
 * Additional lock bits for cluster communication
 */
#define LCK_PARTIAL_MODE	0x00000001U	/* Running in partial mode */
#define LCK_MIRROR_NOSYNC_MODE	0x00000002U	/* Mirrors don't require sync */
#define LCK_DMEVENTD_MONITOR_MODE	0x00000004U	/* Register with dmeventd */

/* Forward declaration we need below */
void proto_reg_handoff_clvmd(void);


/* Initialize the protocol and registered fields */
static int proto_clvmd = -1;


/* Fields for struct cl_protheader */
static int hf_clvmd_header_cmd   = -1;


static int hf_clvmd_header_flags = -1;
static int hf_clvmd_header_flags_local    = -1;
static int hf_clvmd_header_flags_systemlv = -1;
static int hf_clvmd_header_flags_nodeerrs = -1;

static int hf_clvmd_header_xid      = -1;
static int hf_clvmd_header_clientid = -1;
static int hf_clvmd_header_status   = -1;
static int hf_clvmd_header_arglen   = -1;

static int hf_clvmd_header_node     = -1;


static int hf_clvmd_args            = -1;

static int hf_clvmd_major   = -1;
static int hf_clvmd_minor   = -1;
static int hf_clvmd_patch   = -1;
static int hf_clvmd_garbage = -1;

static int hf_clvmd_resource = -1;


static int hf_clvmd_lock_cmd          = -1;
static int hf_clvmd_lock_cmd_type     = -1;
static int hf_clvmd_lock_cmd_scope    = -1;

static int hf_clvmd_lock_cmd_nonblock = -1;
static int hf_clvmd_lock_cmd_hold     = -1;
static int hf_clvmd_lock_cmd_local    = -1;


static int hf_clvmd_lock_flags              = -1;
static int hf_clvmd_lock_flags_cluster_vg   = -1;
static int hf_clvmd_lock_flags_partial_mode = -1;
static int hf_clvmd_lock_flags_mirror_nosync_mode  = -1;
static int hf_clvmd_lock_flags_dmeventd_monitor_mode = -1;


/* Value strings */
static const value_string vals_header_cmd[] = {
  	{ 0,                         "Successful"      },
	{ CLVMD_CMD_REPLY,           "Reply"           },
	{ CLVMD_CMD_VERSION,         "Version"         },
	{ CLVMD_CMD_GOAWAY,          "Goaway"          },
	{ CLVMD_CMD_TEST,            "Test"            },
	{ CLVMD_CMD_LOCK,            "Lock"            },
	{ CLVMD_CMD_UNLOCK,          "Unlock"          },
	{ CLVMD_CMD_LOCK_LV,         "Lock LV"         },
	{ CLVMD_CMD_LOCK_VG,         "Lock VG"         },
	{ CLVMD_CMD_REFRESH,	     "Refresh"         },
	{ CLVMD_CMD_GET_CLUSTERNAME, "Get cluster name"}, 
	{ CLVMD_CMD_SET_DEBUG,	     "Set debug"       },
	{ CLVMD_CMD_VG_BACKUP,       "Backup"          },
	{ CLVMD_CMD_RESTART,         "Restart"         },
	{ CLVMD_CMD_SYNC_NAMES,      "Sync names"      },
	{ 0,                            NULL           },
		
};

static const value_string vals_header_status[] = {
	{ 0,            "Successful"                                    },
  	{ EPERM,        "Operation not permitted"                       },
	{ ENOENT,       "No such file or directory"                     },
	{ EIO,          "I/O error"                                     },
	{ ENOMEM,       "Out of memory"                                 },
	{ ENOSPC,       "No space left on device"                       },
	{ ENAMETOOLONG, "File name too long"                            },
	{ EXFULL,       "Exchange full"                                 },	
	{ ETIME,        "Timer expired"                                 },
	{ EOPNOTSUPP,   "Operation not supported on transport endpoint" },
	{ 0, NULL },
};

#define  vals_lock_cmd_common_type		\
	{ LCK_NULL,      "NULL"   },		\
	{ LCK_READ,      "READ"   },		\
	{ LCK_PREAD,     "PREAD"  },		\
	{ LCK_WRITE,     "WRITE"  },		\
	{ LCK_EXCL,      "EXCL"   },		\
	{ LCK_UNLOCK,    "UNLOCK" }		\

#define vals_lock_cmd_common_scope              \
	{ LCK_VG,        "Volume group"   },    \
	{ LCK_LV,        "Logical volume" }

static const value_string vals_lock_cmd_common_combinations [] = {
	{ LCK_NONE,          "NONE"          },
	{ LCK_VG_READ,       "VG READ"       },
	{ LCK_VG_WRITE,      "VG WRITE"      },
	{ LCK_VG_UNLOCK,     "VG UNLOCK"     },
	{ LCK_LV_EXCLUSIVE,  "LV EXCLUSIVE"  },
	{ LCK_LV_SUSPEND,    "LV SUSPEND"    },
	{ LCK_LV_RESUME,     "LV RESUME"     },
	{ LCK_LV_ACTIVATE,   "LV ACTIVATE"   },
	{ LCK_LV_DEACTIVATE, "LV DEACTIVATE" },
	vals_lock_cmd_common_type,
	vals_lock_cmd_common_scope,
	{ 0, NULL }
};
static const value_string vals_lock_cmd_type[] = {
	vals_lock_cmd_common_type,
	{ 0, NULL                 }

};

static const value_string vals_lock_cmd_scope[] = {
	vals_lock_cmd_common_scope,
	{ 0, NULL                 }
};

/* Initialize the subtree pointers */
static gint ett_clvmd                      = -1;

static gint ett_clvmd_header_flags         = -1;

static gint ett_clvmd_lock_cmd   = -1;
static gint ett_clvmd_lock_flags   = -1;


static const int *header_flags_fields[] = {
	&hf_clvmd_header_flags_local,
	&hf_clvmd_header_flags_systemlv,
	&hf_clvmd_header_flags_nodeerrs,
	NULL
};

static const int *lock_cmd [] = {
	&hf_clvmd_lock_cmd_type,
	&hf_clvmd_lock_cmd_scope,
	&hf_clvmd_lock_cmd_nonblock,
	&hf_clvmd_lock_cmd_hold,
	&hf_clvmd_lock_cmd_local,
	NULL
};

static const int *lock_flags [] = {
	&hf_clvmd_lock_flags_cluster_vg,
	
	&hf_clvmd_lock_cmd_local,

	&hf_clvmd_lock_flags_partial_mode,
	&hf_clvmd_lock_flags_mirror_nosync_mode,
	&hf_clvmd_lock_flags_dmeventd_monitor_mode,
	NULL
};

#if 0
struct clvm_header {
	uint8_t  cmd;	        /* See below */
	uint8_t  flags;	        /* See below */
	uint16_t xid;	        /* Transaction ID, ntohs */
	uint32_t clientid;	/* Only used in Daemon->Daemon comms, ??? */
	int32_t  status;	/* For replies, whether request succeeded, ntohl*/
	uint32_t arglen;	/* Length of argument below. 
				   If >1500 then it will be passed 
				   around the cluster in the system LV, ntohl */
	char node[1];		/* Actually a NUL-terminated string, node name.
				   If this is empty then the command is 
				   forwarded to all cluster nodes unless 
				   FLAG_LOCAL is also set. */
	char args[1];		/* Arguments for the command follow the 
				   node name, This member is only
				   valid if the node name is empty */
} __attribute__ ((packed));
#endif

static int
dissect_clvmd_reply_args(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			   int offset, guint length, guint32 arglen)
{
	int original_offset;
	gint nodelen;
	guint8 *node;
	guint8 *args;

	
	original_offset = offset;
	nodelen = tvb_strnlen(tvb, offset, length - offset - arglen);
	if (nodelen == -1)
		return 0;

	node = tvb_get_ephemeral_string(tvb, offset, nodelen);
	proto_tree_add_string(parent_tree,
			      hf_clvmd_header_node,
			      tvb,
			      offset,
			      nodelen + 1,
			      node);

	offset += (nodelen + 1);
	if ( (length - offset) < arglen )
		return (offset - original_offset);

	args = tvb_get_ephemeral_string(tvb, offset, arglen);
	proto_tree_add_bytes(parent_tree,
			     hf_clvmd_args,
			     tvb,
			     offset,
			     arglen,
			     node);
	offset += arglen;

	if (arglen == 0 && (length - offset) > 0)
	{
		proto_tree_add_item(parent_tree,
				    hf_clvmd_garbage,
				    tvb,
				    offset,
				    1,
				    FALSE);
		offset += 1;
	}
	
	return (offset - original_offset);

	pinfo = pinfo;
}

static int
dissect_clvmd_version_args(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			   int offset, guint length, guint32 arglen)
{
	int original_offset;
	guint8 *node;

	
	original_offset = offset;
	if ( (length - offset) < 1 + 4 + 4 + 4 )
		return 0;

	node = tvb_get_ephemeral_string(tvb, offset, 1);
	proto_tree_add_string(parent_tree,
			      hf_clvmd_header_node,
			      tvb,
			      offset,
			      1,
			      node);
	
	offset += 1;
	proto_tree_add_item(parent_tree,
			    hf_clvmd_major,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	proto_tree_add_item(parent_tree,
			    hf_clvmd_minor,
			    tvb,
			    offset,
			    4,
			    FALSE);
	offset += 4;
	proto_tree_add_item(parent_tree,
			    hf_clvmd_patch,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	if ( (length - offset) > 0 ) {
		proto_tree_add_item(parent_tree,
				    hf_clvmd_garbage,
				    tvb,
				    offset,
				    1,
				    FALSE);
		offset += 1;
	}

	return (offset - original_offset);

	pinfo = pinfo;
	arglen = arglen;
}


static int
dissect_clvmd__cmd_flags_resource(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		      int offset, guint length, guint32 arglen)
{
	int original_offset;
	guint8 *node;
	guint8* resource;

	
	original_offset = offset;
	if ( (length - offset) < 1 + arglen )
		return 0;

	node = tvb_get_ephemeral_string(tvb, offset, 1);
	proto_tree_add_string(parent_tree,
			      hf_clvmd_header_node,
			      tvb,
			      offset,
			      1,
			      node);
	offset += 1;
	proto_tree_add_bitmask(parent_tree, tvb, offset,
			       hf_clvmd_lock_cmd,
			       ett_clvmd_lock_cmd,
			       lock_cmd,
			       FALSE);
			       
	offset += 1;
	proto_tree_add_bitmask(parent_tree, tvb, offset,
			       hf_clvmd_lock_flags,
			       ett_clvmd_lock_flags,
			       lock_flags,
			       FALSE);

	offset += 1;
	resource = tvb_get_ephemeral_string(tvb, offset, arglen - 2);
	proto_tree_add_string(parent_tree,
			      hf_clvmd_resource,
			      tvb,
			      offset,
			      arglen - 2,
			      resource);

	offset += (arglen - 2);

	if ( (offset - original_offset) > 0 )
	{
		proto_tree_add_item(parent_tree,
				    hf_clvmd_garbage,
				    tvb,
				    offset,
				    1,
				    FALSE);
		offset += 1;
	}

	
	return (offset - original_offset);

	pinfo = pinfo;
}

static int
dissect_clvmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint    length;
	int      offset;

	proto_tree *tree;
	proto_item *item;

	guint8   cmd;
	guint32  arglen;

	length = tvb_length(tvb);
	if ( length < 1 + 1 + 2 + 4 + 4 + 4 )
		return 0;

	/* ??? */
	/* if (check_col(pinfo->cinfo, COL_PROTOCOL))
	   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLVMD"); */
	
	cmd = tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(clvmd %s)",
				    val_to_str(cmd, vals_header_cmd, "Unknown cmd"));
	
	if (!parent_tree)
		goto out;

	offset = 0;
	item = proto_tree_add_item(parent_tree, proto_clvmd, tvb, 
 				   offset, -1, FALSE);
	tree = proto_item_add_subtree(item, ett_clvmd);
	

	offset += 0;
	proto_tree_add_item(tree, hf_clvmd_header_cmd, tvb, offset, 1, FALSE);

	offset += 1;
	proto_tree_add_bitmask(tree, tvb, offset, hf_clvmd_header_flags,
			       ett_clvmd_header_flags, header_flags_fields, FALSE);

	offset += 1;
	proto_tree_add_item(tree, hf_clvmd_header_xid, tvb, offset, 2, FALSE);
	/* TODO: conversation */
	
	offset += 2;
	proto_tree_add_item(tree, hf_clvmd_header_clientid, tvb, offset, 4, FALSE);
	
	offset += 4;
	proto_tree_add_item(tree, hf_clvmd_header_status, tvb, offset, 4, FALSE);

	offset += 4;
	proto_tree_add_item(tree, hf_clvmd_header_arglen, tvb, offset, 4, FALSE);
	arglen = tvb_get_ntohl(tvb, offset);
	
	offset += 4;
	switch (cmd)
	{
		/* clvmd-command.c::do_command() */
	case CLVMD_CMD_REPLY:
		offset += dissect_clvmd_reply_args(tvb,
						   pinfo,
						   tree,
						   offset,
						   length,
						   arglen);
		break;
	case CLVMD_CMD_VERSION:
		offset += dissect_clvmd_version_args(tvb,
						     pinfo,
						     tree,
						     offset,
						     length,
						     arglen);
		break;
	case CLVMD_CMD_GOAWAY:
		/* TODO: garbage */
		/* Do nothing */
		break;
		
	case CLVMD_CMD_TEST:
		/* TODO: strlen is needed. */
		break;

	case CLVMD_CMD_LOCK:
	case CLVMD_CMD_UNLOCK:
		/* Maybe obsolete commands. */
		break;

	case CLVMD_CMD_LOCK_LV:
		offset += dissect_clvmd__cmd_flags_resource(tvb,
							    pinfo,
							    tree,
							    offset,
							    length,
							    arglen);
		break;
		
	case CLVMD_CMD_LOCK_VG:
		offset += dissect_clvmd__cmd_flags_resource(tvb,
							    pinfo,
							    tree,
							    offset,
							    length,
							    arglen);
		break;
		
	case CLVMD_CMD_REFRESH:
		/* TODO: strlen is needed, may be empty, no payload,
		 * see _cluster_request(). */
		break;
		
	case CLVMD_CMD_GET_CLUSTERNAME:
		/* Do nothing */
		break;
		
	case CLVMD_CMD_SET_DEBUG:
		/* TODO: strlen is needed, may be 1 byte(level), 1 byte payload
		 * ------------------------------------------------------------
		 * clvmd.h:
		 * typedef enum {DEBUG_OFF, DEBUG_STDERR, DEBUG_SYSLOG} debug_t;*/
		break;
		
	case CLVMD_CMD_VG_BACKUP:
		offset += dissect_clvmd__cmd_flags_resource(tvb,
							    pinfo,
							    tree,
							    offset,
							    length,
							    arglen);
		break;
	case CLVMD_CMD_RESTART:
		g_warning("TODO: clvmd:cmd: %d\n", cmd);
		break;
	case CLVMD_CMD_SYNC_NAMES:
		offset += dissect_clvmd__cmd_flags_resource(tvb,
							    pinfo,
							    tree,
							    offset,
							    length,
							    arglen);
		break;

	default:
		break;
	}
out:
	return length;
}

void
proto_register_clvmd(void)
{
	static hf_register_info hf[] = {
		{ &hf_clvmd_header_cmd,
		  { "Command", "clvmd.header.cmd",
		    FT_UINT8, BASE_DEC, VALS(vals_header_cmd), 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_header_flags,
		  { "Flags", "clvmd.header.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_header_flags_local,
		  { "Only do this on the local node", "clvmd.header.flags.local",
		    FT_BOOLEAN, 8, NULL, CLVMD_FLAG_LOCAL,
		    NULL, HFILL }},
		{ &hf_clvmd_header_flags_systemlv,
		  { "Data in system LV under my node name", "clvmd.header.flags.systemlv",
		    FT_BOOLEAN, 8, NULL, CLVMD_FLAG_SYSTEMLV,
		    NULL, HFILL }},
		{ &hf_clvmd_header_flags_nodeerrs,
		  { "Reply has errors in node-specific portion", "clvmd.header.flags.nodderrs",
		    FT_BOOLEAN, 8, NULL, CLVMD_FLAG_NODEERRS,
		    NULL, HFILL }},
		{ &hf_clvmd_header_xid,
		  { "Transaction id", "clvmd.header.xid",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_header_clientid,
		  { "Client id", "clvmd.header.client",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_header_status,
		  { "Status", "clvmd.header.status",
		    FT_INT32, BASE_DEC, VALS(vals_header_status), 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_header_arglen,
		  { "Lenght of the arguments", "clvmd.header.arglen",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_header_node,
		  { "Node", "clvmd.header.node",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_args,
		  { "Arguments", "clvmd.args",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_major,
		  { "Major version", "clvmd.major",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_minor,
		  { "Minor version", "clvmd.minor",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_patch,
		  { "Patch version", "clvmd.patch",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_garbage,
		  { "Garbage", "clvmd.garbage",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_clvmd_resource,
		  { "Resource", "clvmd.resource",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_clvmd_lock_cmd,
		  { "Lock command", "clvmd.lock_cmd",
		    FT_UINT8, BASE_HEX, VALS(vals_lock_cmd_common_combinations), 0xFF, /* <= TODO: 0x0? */
		    NULL, HFILL }},
		{ &hf_clvmd_lock_cmd_type,
		  { "Type", "clvmd.lock_cmd.type",
		    FT_UINT8, BASE_HEX, VALS(vals_lock_cmd_type), LCK_TYPE_MASK,
		    NULL, HFILL }},
		{ &hf_clvmd_lock_cmd_scope,
		  { "Scope", "clvmd.lock_cmd.scope",
		    FT_UINT8, BASE_HEX, VALS(vals_lock_cmd_scope), LCK_SCOPE_MASK,
		    NULL, HFILL }},
		{ &hf_clvmd_lock_cmd_nonblock,
		  { "Don't block waiting for lock?", "clvmd.header.lock_cmd.nonblock",
		    FT_BOOLEAN, 8, NULL, LCK_NONBLOCK,
		    NULL, HFILL }},
		{ &hf_clvmd_lock_cmd_hold,
		  { "Hold lock when lock_vol returns?", "clvmd.header.lock_cmd.hold",
		    FT_BOOLEAN, 8, NULL, LCK_HOLD,
		    NULL, HFILL }},
		{ &hf_clvmd_lock_cmd_local,
		  { "Don't propagate to other nodes?", "clvmd.header.lock_cmd.local",
		    FT_BOOLEAN, 8, NULL, LCK_LOCAL,
		    NULL, HFILL }},
		{ &hf_clvmd_lock_flags,
		  { "Cluster lock flags", "clvmd.lock_flags",
		    FT_UINT8, BASE_HEX,
		    NULL, 0xFF, NULL, HFILL }},
		{ &hf_clvmd_lock_flags_cluster_vg,
		  { "Cluster lock flags", "clvmd.lock_flags.cluster_vg",
		    FT_BOOLEAN, 8,
		    NULL, LCK_CLUSTER_VG, NULL, HFILL }},
		{ &hf_clvmd_lock_flags_partial_mode,
		  { "Running in partial mode", "clvmd.lock_flags.partial_mode",
		    FT_BOOLEAN, 8,
		    NULL, LCK_PARTIAL_MODE, NULL, HFILL }},
		{ &hf_clvmd_lock_flags_mirror_nosync_mode,
		  { "Mirrors don't require sync", "clvmd.lock_flags.mirror_nosync_mode",
		    FT_BOOLEAN, 8,
		    NULL, LCK_MIRROR_NOSYNC_MODE, NULL, HFILL }},
		{ &hf_clvmd_lock_flags_dmeventd_monitor_mode,
		  { "Register with dmeventd", "clvmd.lock_flags.dmeventd_monitor_mode",
		    FT_BOOLEAN, 8,
		    NULL, LCK_DMEVENTD_MONITOR_MODE, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_clvmd,
		&ett_clvmd_header_flags,
		&ett_clvmd_lock_cmd,
		&ett_clvmd_lock_flags
	};

	proto_clvmd 
		= proto_register_protocol("Cluster LVM daemon",
					  "CLVMD", "clvmd");
	
	proto_register_field_array(proto_clvmd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_clvmd(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t clvmd_handle;

	if (register_dissector) {
		dissector_delete("openais_cman.tgtport", CLVMD_CMAN_TGTPORT, clvmd_handle);
	} else {
		clvmd_handle = new_create_dissector_handle(dissect_clvmd, proto_clvmd);
		register_dissector = TRUE;
	}
	dissector_add("openais_cman.tgtport", CLVMD_CMAN_TGTPORT, clvmd_handle);
}

