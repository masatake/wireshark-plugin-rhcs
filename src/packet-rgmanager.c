/* packet-rgmanager.c
 * Routines for dissecting protocol used in resource groupd manager
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
#include <time.h>
#include <string.h>


#define RGMANAGER_CMAN_TGTPORT 177


/* rgmanager-2.0.38/include/message.h */

enum {
	M_NONE = 0,
	M_OPEN = 1,
	M_OPEN_ACK = 2,
	M_CLOSE = 3,
	M_DATA = 4,
	M_STATECHANGE = 5,		/* Node transition */
	M_PORTOPENED = 6,		/* Port opened */
	M_PORTCLOSED = 7,		/* Port closed */
	M_TRY_SHUTDOWN = 8		/* Local node shutdown */
};

#define GENERIC_HDR_MAGIC   0x123abc00
#define GENERIC_HDR_MAGICV2 0x123abc02


#define RG_ACTION_REQUEST	/* Message header */ 0x138582
#define RG_EVENT		0x138583

/* Requests */
#define RG_SUCCESS	  0
#define RG_FAIL		  1
#define RG_START	  2
#define RG_STOP		  3
#define RG_STATUS	  4
#define RG_DISABLE	  5
#define RG_STOP_RECOVER	  6
#define RG_START_RECOVER  7
#define RG_RESTART	  8
#define RG_EXITING	  9 
#define RG_INIT		  10
#define RG_ENABLE	  11
#define RG_STATUS_NODE	  12
#define RG_RELOCATE	  13
#define RG_CONDSTOP	  14
#define RG_CONDSTART	  15
#define RG_START_REMOTE   16	/* Part of a relocate */
#define RG_STOP_USER	  17	/* User-stop request */
#define RG_STOP_EXITING	  18	/* Exiting. */
#define RG_LOCK		  19
#define RG_UNLOCK	  20
#define RG_QUERY_LOCK	  21
#define RG_MIGRATE	  22
#define RG_FREEZE	  23
#define RG_UNFREEZE	  24
#define RG_STATUS_INQUIRY 25
#define RG_NONE		  999

/* Resource group states (for now) */
#define RG_STATE_BASE			110
#define RG_STATE_STOPPED		110	/** Resource group is stopped */
#define RG_STATE_STARTING		111	/** Resource is starting */
#define RG_STATE_STARTED		112	/** Resource is started */
#define RG_STATE_STOPPING		113	/** Resource is stopping */
#define RG_STATE_FAILED			114	/** Resource has failed */
#define RG_STATE_UNINITIALIZED		115	/** Thread not running yet */
#define RG_STATE_CHECK			116	/** Checking status */
#define RG_STATE_ERROR			117	/** Recoverable error */
#define RG_STATE_RECOVER		118	/** Pending recovery */
#define RG_STATE_DISABLED		119	/** Resource not allowd to run */
#define RG_STATE_MIGRATE		120	/** Resource migrating */

#define VF_MESSAGE		0x3000

#define VF_COMMAND_MASK         0x0000ffff
#define VF_JOIN_VIEW		0x3001
#define VF_VOTE			0x3002
#define VF_ABORT		0x3004
#define VF_VIEW_FORMED		0x3005
#define VF_CURRENT		0x3006
#define VF_ACK			0x3007
#define VF_NACK			0x3008

/* TODO */
#define VF_FLAGS_MASK           0xffff0000
#define VF_FLAGS_SHIFT          16
#define VFMF_AFFIRM	        (0x00010000 >> VF_FLAGS_SHIFT)


/* Forward declaration we need below */
void proto_reg_handoff_rgmanager(void);


/* Initialize the protocol and registered fields */
static int proto_rgmanager = -1;


/* Fields for struct cl_protheader */
static int hf_rgmanager_cluster_msg_header_src_ctx     = -1;
static int hf_rgmanager_cluster_msg_header_src_nodeid  = -1;
static int hf_rgmanager_cluster_msg_header_dest_ctx    = -1;
static int hf_rgmanager_cluster_msg_header_dest_nodeid = -1;

static int hf_rgmanager_cluster_msg_header_msg_control = -1;
static int hf_rgmanager_cluster_msg_header_msg_port    = -1;
static int hf_rgmanager_cluster_msg_header_pad         = -1;
static int hf_rgmanager_cluster_msg_header_reserved    = -1;

static int hf_rgmanager_generic_msg_hdr_magic          = -1;
static int hf_rgmanager_generic_msg_hdr_length         = -1;
static int hf_rgmanager_generic_msg_hdr_command        = -1;
static int hf_rgmanager_generic_msg_hdr_arg1           = -1;
static int hf_rgmanager_generic_msg_hdr_arg2           = -1;
static int hf_rgmanager_generic_msg_hdr_arg3           = -1;

static int hf_rgmanager_generic_msg_hdr_status_fast     = -1;
static int hf_rgmanager_generic_msg_hdr_exiting_node_id = -1;
static int hf_rgmanager_generic_msg_hdr_vf_command      = -1;
static int hf_rgmanager_generic_msg_hdr_owner           = -1;
static int hf_rgmanager_generic_msg_hdr_last            = -1;
static int hf_rgmanager_vf_command                      = -1;
static int hf_rgmanager_vf_flags                        = -1;
static int hf_rgmanager_generic_msg_hdr_vf_trans        = -1;

static int hf_rgmanager_vf_msg_info                     = -1;
static int hf_rgmanager_vf_msg_info_vf_command          = -1;
static int hf_rgmanager_vf_msg_info_vf_transaction      = -1;
static int hf_rgmanager_vf_msg_info_vf_keyid            = -1;
static int hf_rgmanager_vf_msg_info_vf_coordinator      = -1;
static int hf_rgmanager_vf_msg_info_vf_datalen          = -1;
static int hf_rgmanager_vf_msg_info_vf_view             = -1;
static int hf_rgmanager_vf_msg_info_vf_data             = -1;

static int hf_rgmanager_sm_data                         = -1;
static int hf_rgmanager_sm_data_svcName                 = -1;
static int hf_rgmanager_sm_data_action                  = -1;
static int hf_rgmanager_sm_data_svcState                = -1;
static int hf_rgmanager_sm_data_svcOwner                = -1;
static int hf_rgmanager_sm_data_ret                     = -1;

static int hf_rgmanager_rg_state_rs_name                = -1;
static int hf_rgmanager_rg_state_rs_flags                  = -1;
static int hf_rgmanager_rg_state_rs_magic               = -1;
static int hf_rgmanager_rg_state_rs_owner               = -1;
static int hf_rgmanager_rg_state_rs_last_owner          = -1;
static int hf_rgmanager_rg_state_rs_state               = -1;
static int hf_rgmanager_rg_state_rs_restarts            = -1;
static int hf_rgmanager_rg_state_rs_transition          = -1;


/* Value string */
static const value_string vals_cluster_msg_header_msg_control[] = {
	{ M_NONE,         "none"                },
	{ M_OPEN,         "open"                },
	{ M_OPEN_ACK,     "open_ack"            },
	{ M_CLOSE,        "close"               },
	{ M_DATA,         "data"                },
	{ M_STATECHANGE,  "node transition"     },
	{ M_PORTOPENED,   "port opened"         },
	{ M_PORTCLOSED,   "port closed"         },
	{ M_TRY_SHUTDOWN, "local node shutdown" },
	{ 0, NULL }
};

static const value_string vals_generic_msg_hdr_magic[] = {
	{ GENERIC_HDR_MAGIC,   "version 0" },
	{ GENERIC_HDR_MAGICV2, "version 2 (cannot handle in this dissector)" },
	{ 0, NULL },
};

static const value_string vals_generic_msg_hdr_command[] = {
        { RG_STATUS,         "status"                 },
	{ RG_STATUS_NODE,    "node status"            },
	{ RG_LOCK,           "lock"                   },
	{ RG_UNLOCK,         "unlock"                 },
	{ RG_QUERY_LOCK,     "query lock"             },
	{ RG_ACTION_REQUEST, "action request"         },
	{ RG_EVENT,          "event"                  },
	{ RG_EXITING,        "exiting"                },
	{ VF_MESSAGE,        "view formation message" },
	{ 0, NULL },
};

static const value_string vals_generic_msg_hdr_status_fast[] = {
        { 0, "no"  },
	{ 1, "yes" },
	{ 0, NULL  },
};

static const value_string vals_vf_msg_info_command[] = {
	{ VF_JOIN_VIEW,   "join view"   },
	{ VF_VOTE,        "vote"        },
	{ VF_ABORT,       "abort"       },
	{ VF_VIEW_FORMED, "view formed" },
	{ VF_CURRENT,     "current"     },
	{ VF_ACK,         "ack"         },
	{ VF_NACK,        "nack"        },
	{ 0, NULL },
};

static const value_string vals_vf_msg_info_flags[] = {
	{ VFMF_AFFIRM, "affirm" },
	{ 0, NULL },
};

#define RG_ACTION_MASTER	0xfe0db143
#define RG_ACTION_USER		0x3f173bfd

static const value_string vals_sm_service_owner[] = {
	{ RG_ACTION_MASTER, "master" },
	{ RG_ACTION_USER,   "user"   },
	{ 0, NULL }
};



/* Return codes */
#define RG_EEXCL	-16		/* Service not runnable due to
					   the fact that it is tagged 
					   exclusive and there are no
					   empty nodes. */
#define RG_EDOMAIN	-15		/* Service not runnable given the
					   set of nodes and its failover
					   domain */
#define RG_ESCRIPT	-14		/* S/Lang script failed */
#define RG_EFENCE	-13		/* Fencing operation pending */
#define RG_ENODE	-12		/* Node is dead/nonexistent */
//#define RG_EFROZEN    -11		/* Forward compat. with -HEAD */
#define RG_ERUN		-10		/* Service is already running */
#define RG_EQUORUM	-9		/* Operation requires quorum */
#define RG_EINVAL	-8		/* Invalid operation for resource */
#define RG_EDEPEND 	-7		/* Operation violates dependency */
#define RG_EAGAIN	-6		/* Try again */
#define RG_EDEADLCK	-5		/* Aborted - would deadlock */
#define RG_ENOSERVICE	-4		/* Service does not exist */
#define RG_EFORWARD	-3		/* Service not mastered locally */
#define RG_EABORT	-2		/* Abort; service unrecoverable */
#define RG_EFAIL	-1		/* Generic failure */
#define RG_ESUCCESS	0
#define RG_YES		1
#define RG_NO		2

static const value_string vals_sm_ret[] = {
	{ RG_EEXCL,	"EEXCL" }, 
	{ RG_EDOMAIN,	"EDOMAIN" }, 
	{ RG_ESCRIPT,	"ESCRIPT" }, 
	{ RG_EFENCE,	"EFENCE" }, 
	{ RG_ENODE,	"ENODE" }, 
/*	{ RG_EFROZEN,   "EFROZEN" },  */
	{ RG_ERUN,      "ERUN" },
	{ RG_EQUORUM,	"EQUORUM" }, 
	{ RG_EINVAL,	"EINVAL" }, 
	{ RG_EDEPEND, 	"EDEPEND" }, 
	{ RG_EAGAIN,	"EAGAIN" }, 
	{ RG_EDEADLCK,	"EDEADLCK"}, 
	{ RG_ENOSERVICE, "ENOSERVICE"}, 
	{ RG_EFORWARD,	"EFORWARD" }, 
	{ RG_EABORT,	"EABORT" }, 
	{ RG_EFAIL,     "EFAIL" }, 
	{ RG_ESUCCESS,	"ESUCCESS"  },
	{ RG_YES,       "YES"  },
	{ RG_NO,        "NO"  },
	{ 0, NULL }
};

static const value_string vals_rg_state[] = {
        { RG_STATE_STOPPED,       "stopped" },
	{ RG_STATE_STARTING,      "starting" },
	{ RG_STATE_STARTED,       "started" },
	{ RG_STATE_STOPPING,      "stopping" },
	{ RG_STATE_FAILED,        "failed" },
	{ RG_STATE_UNINITIALIZED, "uninitialized" },
	{ RG_STATE_CHECK,         "check" },
	{ RG_STATE_ERROR,         "error" },
	{ RG_STATE_RECOVER,       "recover" },
	{ RG_STATE_DISABLED,      "disabled" },
	{ RG_STATE_MIGRATE,       "migrate" },
	{ 0, NULL },
};


#define RG_FLAG_FROZEN			(1<<0)	/** Resource frozen */
#define RG_FLAG_PARTIAL			(1<<1)	/** One or more non-critical
						    resources offline */

static const value_string vals_rg_flags[] = {
  { RG_FLAG_FROZEN, "frozen" },
  { 0,              NULL     },
};

/* Bit fields */
static const int* b_vf_commands[] = {
	&hf_rgmanager_vf_command,
	&hf_rgmanager_vf_flags,
	NULL
};

/* Initialize the subtree pointers */
static gint ett_rgmanager                            = -1;
static gint ett_rgmanager_generic_msg_hdr_vf_command = -1;
static gint ett_rgmanager_vf_msg_info                = -1;
static gint ett_rgmanager_sm_data                    = -1;
static gint ett_rgmanager_rg_state                   = -1;

static int
dissect_rgmanager_generic_args(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			       guint length, int offset, 
			       int hf_arg1, int hf_arg2)
{
	int original_offset;
	proto_item *arg1_item, *arg2_item, *arg3_item;



	if ((length - offset) < 4 + 4 + 4)
		return 0;

	original_offset = offset;


	offset += 0;
	if (hf_arg1 == 0)
		hf_arg1 = hf_rgmanager_generic_msg_hdr_arg1;
	arg1_item = proto_tree_add_item(tree,
					hf_arg1,
					tvb,
					offset,
					4,
					FALSE);
	
	offset += 4;
	if (hf_arg2 == 0)
		hf_arg2 = hf_rgmanager_generic_msg_hdr_arg2;
	arg2_item = proto_tree_add_item(tree,
					hf_rgmanager_generic_msg_hdr_arg2,
					tvb,
					offset,
					4,
					FALSE);

	offset += 4;
	arg3_item = proto_tree_add_item(tree,
					hf_rgmanager_generic_msg_hdr_arg3,
					tvb,
					offset,
					4,
					FALSE);

	offset += 4;


	if (hf_arg1 == hf_rgmanager_generic_msg_hdr_arg1)
		proto_item_append_text(arg1_item, " (unused)");
	if (hf_arg2 == hf_rgmanager_generic_msg_hdr_arg2)
		proto_item_append_text(arg2_item, " (unused)");
	proto_item_append_text(arg3_item, " (unused)");


	return (offset - original_offset);
	
	pinfo = pinfo;
}

static int
dissect_rgmanager_rg_state(tvbuff_t *tvb, packet_info *pinfo, 
			   proto_tree *tree,
			   guint length, int offset)
{
  int original_offset;
  proto_item *item;
  time_t t;
  char *ct;


  if (length - offset < 96)
    return 0;
  original_offset = offset;


  item = proto_tree_add_item(tree, hf_rgmanager_vf_msg_info_vf_data,
			     tvb, offset, length - offset, FALSE);
  tree = proto_item_add_subtree(item, ett_rgmanager_rg_state);
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_name,
		      tvb,
		      offset,
		      64,
		      FALSE);
  offset += 64;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_flags,
		      tvb,
		      offset,
		      4,
		      TRUE);
  offset += 4;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_magic,
		      tvb,
		      offset,
		      4,
		      TRUE);
  offset += 4;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_owner,
		      tvb,
		      offset,
		      4,
		      TRUE);
  offset += 4;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_last_owner,
		      tvb,
		      offset,
		      4,
		      TRUE);
  offset += 4;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_state,
		      tvb,
		      offset,
		      4,
		      TRUE);
  offset += 4;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_restarts,
		      tvb,
		      offset,
		      4,
		      TRUE);
  offset += 4;
  proto_tree_add_item(tree,
		      hf_rgmanager_rg_state_rs_transition,
		      tvb,
		      offset,
		      8,
		      TRUE);
  t = (time_t)tvb_get_letoh64(tvb, offset);
  ct = ctime(&t);
  ct[strlen(ct)-1] = '\0';
  proto_tree_add_text(tree, tvb, offset, 8, "%s", ct);
  offset += 8;
  return offset - original_offset;  
}

static int
dissect_rgmanager_vf_msg_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			      guint length, int offset)
{
	int original_offset;
	guint32 datalen;



	if ((length - offset) < 4 + 4 + 64 + 4 + 4 + 8) 
		return 0;

	original_offset = offset;


	proto_tree_add_item(tree,
			    hf_rgmanager_vf_msg_info_vf_command,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_vf_msg_info_vf_transaction,
			    tvb,
			    offset,
			    4,
			    FALSE);
		
	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_vf_msg_info_vf_keyid,
			    tvb,
			    offset,
			    64,
			    FALSE);

	offset += 64;
	proto_tree_add_item(tree,
			    hf_rgmanager_vf_msg_info_vf_coordinator,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_vf_msg_info_vf_datalen,
			    tvb,
			    offset,
			    4,
			    FALSE);
	datalen = tvb_get_ntohl(tvb, offset);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_vf_msg_info_vf_view,
			    tvb,
			    offset,
			    8,
			    FALSE);

	offset += 8;
	if ((length - offset) < datalen)
		goto out;
	
	switch (datalen)
	  {
	    /* case 1: */
	    /* "Transition-Master" */
	  case 96:
	    /* resgroup.h:rg_state_t 
	       "rg="*" */
	    offset += dissect_rgmanager_rg_state(tvb, pinfo, tree, length, offset);
	    break;
	  default:
	    proto_tree_add_item(tree,
				hf_rgmanager_vf_msg_info_vf_data,
				tvb,
				offset,
				datalen,
				FALSE);
	  }
	offset += datalen;

out:
	return offset - original_offset;

	pinfo = pinfo;
}
		
static int
dissect_rgmanager_vf_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			     guint length, int offset)
{

	int original_offset;
	guint32 vf_command;

	proto_item *sub_item;
	proto_item *arg2_item, *arg3_item;


	if ((length - offset) < 4 + 4 + 4)
		return 0;

	original_offset = offset;

	proto_tree_add_bitmask(tree, tvb, offset,
			       hf_rgmanager_generic_msg_hdr_vf_command,
			       ett_rgmanager_generic_msg_hdr_vf_command,
			       b_vf_commands,
			       FALSE);
	vf_command = (tvb_get_ntohl(tvb, offset) & VF_COMMAND_MASK);
	
	
	offset += 4;
	
	switch (vf_command)
	{
		proto_tree *sub_tree;

		
	case VF_CURRENT:
		arg2_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg2,
						tvb,
						offset,
						4,
						FALSE);

		offset += 4;
		
		arg3_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg3,
						tvb,
						offset,
						4,
						FALSE);
		offset += 4;
		proto_item_append_text(arg2_item, " (unused)");
		proto_item_append_text(arg3_item, " (unused)");


		sub_item = proto_tree_add_item(tree, hf_rgmanager_vf_msg_info,
					       tvb, offset, length - offset, FALSE);
		sub_tree = proto_item_add_subtree(sub_item, ett_rgmanager_vf_msg_info);
		offset += dissect_rgmanager_vf_msg_info(tvb, pinfo, sub_tree, length, offset);
		break;

	case VF_JOIN_VIEW:
		arg2_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg2,
						tvb,
						offset,
						4,
						FALSE);

		offset += 4;
		
		arg3_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg3,
						tvb,
						offset,
						4,
						FALSE);
		offset += 4;
		proto_item_append_text(arg2_item, " (unused)");
		proto_item_append_text(arg3_item, " (unused)");

		sub_item = proto_tree_add_item(tree, hf_rgmanager_vf_msg_info,
					       tvb, offset, length - offset, FALSE);
		sub_tree = proto_item_add_subtree(sub_item, ett_rgmanager_vf_msg_info);
		offset += dissect_rgmanager_vf_msg_info(tvb, pinfo, sub_tree, length, offset);

		break;

	case VF_VOTE:
	case VF_ABORT:
	case VF_VIEW_FORMED:
		arg2_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_vf_trans,
						tvb,
						offset,
						4,
						FALSE);

		offset += 4;
		
		arg3_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg3,
						tvb,
						offset,
						4,
						FALSE);
		offset += 4;


		proto_item_append_text(arg3_item, " (unused)");
		break;
		
	case VF_ACK:
		/* fprintf(stderr, "todo: VF_ACK"); */
		arg2_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg2,
						tvb,
						offset,
						4,
						FALSE);

		offset += 4;
		
		arg3_item = proto_tree_add_item(tree,
						hf_rgmanager_generic_msg_hdr_arg3,
						tvb,
						offset,
						4,
						FALSE);
		offset += 4;
		proto_item_append_text(arg2_item, " (unused)");
		proto_item_append_text(arg3_item, " (unused)");


		sub_item = proto_tree_add_item(tree, hf_rgmanager_vf_msg_info,
					       tvb, offset, length - offset, FALSE);
		sub_tree = proto_item_add_subtree(sub_item, ett_rgmanager_vf_msg_info);
		offset += dissect_rgmanager_vf_msg_info(tvb, pinfo, sub_tree, length, offset);
		break;
	};

out:
	return (offset - original_offset);

	pinfo = pinfo;
	goto out;
	
}

static int
dissect_rgmanager_sm_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			  guint length, int offset, guint command)
{
	int original_offset;
	proto_item* sub_item;
	proto_item* tmp_item;
	proto_tree* sub_tree;

	if ((length - offset) < 64 + 4 + 4 + 4 + 4)
		return 0;
	original_offset = offset;



	sub_item = proto_tree_add_item(tree, hf_rgmanager_sm_data,
				       tvb, offset, length - offset, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_rgmanager_sm_data);

	proto_tree_add_item(sub_tree,
			    hf_rgmanager_sm_data_svcName,
			    tvb,
			    offset,
			    64,
			    FALSE);

	offset += 64;
	proto_tree_add_item(sub_tree,
			    hf_rgmanager_sm_data_action,
			    tvb,
			    offset,
			    4,
			    FALSE);
	
	offset += 4;
	tmp_item = proto_tree_add_item(sub_tree,
				       hf_rgmanager_sm_data_svcState,
				       tvb,
				       offset,
				       4,
				       FALSE);
	if (command == RG_EVENT 
	    || command == RG_ACTION_REQUEST)
		proto_item_append_text(tmp_item, " (unused)");
	

	offset += 4;
	tmp_item = proto_tree_add_item(sub_tree,
				       hf_rgmanager_sm_data_svcOwner,
				       tvb,
				       offset,
				       4,
				       FALSE);
	if (command == RG_EVENT)
		proto_item_append_text(tmp_item, " (unused)");

	offset += 4;
	tmp_item = proto_tree_add_item(sub_tree,
				       hf_rgmanager_sm_data_ret,
				       tvb,
				       offset,
				       4,
				       FALSE);
	if (command == RG_EVENT)
		proto_item_append_text(tmp_item, " (unused)");
	

out:
	return (offset - original_offset);

	pinfo = pinfo;
	goto out;
}

static int
dissect_rgmanager(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	guint    length;
	int      offset;

	proto_tree *tree;
	proto_item *item;
	

	guint32  dest_ctx;
	guint8   msg_control;
	proto_item *dest_ctx_item;



	length = tvb_length(tvb);
	if ( length < 4 + 4 + 4 + 4 + 1 + 1 + 2 + 12 ) {
		goto out;
	}

	/* TODO */
	/* 
	   if (check_col(pinfo->cinfo, COL_PROTOCOL))
	   col_set_str(pinfo->cinfo, COL_PROTOCOL, "RGMANAGER"); */
	
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "rgmanager");

	if (!parent_tree)
		goto out;

	offset = 0;
	item = proto_tree_add_item(parent_tree, proto_rgmanager, tvb, 
 				   offset, -1, FALSE);
	tree = proto_item_add_subtree(item, ett_rgmanager);

	offset += 0;
	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_src_ctx,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_src_nodeid,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	dest_ctx_item = proto_tree_add_item(tree,
					    hf_rgmanager_cluster_msg_header_dest_ctx,
					    tvb,
					    offset,
					    4,
					    FALSE);
	dest_ctx = tvb_get_ntohl(tvb, offset);

		

	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_dest_nodeid,
			    tvb,
			    offset,
			    4,
			    FALSE);

	offset += 4;
	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_msg_control,
			    tvb,
			    offset,
			    1,
			    FALSE);
	msg_control = tvb_get_guint8(tvb, offset);
	if (dest_ctx == 0 && msg_control == M_DATA) {
		proto_item_append_text(dest_ctx_item, " (%s)", "broadcast");
	}
		
	offset += 1;
	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_msg_port,
			    tvb,
			    offset,
			    1,
			    FALSE);

	offset += 1;
	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_pad,
			    tvb,
			    offset,
			    2,
			    FALSE);
	offset += 2;

	proto_tree_add_item(tree,
			    hf_rgmanager_cluster_msg_header_reserved,
			    tvb,
			    offset,
			    12,
			    FALSE);
	offset += 12;
	/* ???
	   M_OPEN
	   See _cluster_msg_receive.
	 */
	if ( msg_control == M_DATA ) {
		guint32 magic;
		guint32 command;

		
		if ( (length - offset) < 4 + 4 + 4 )
			goto out;
		
		proto_tree_add_item(tree,
				    hf_rgmanager_generic_msg_hdr_magic,
				    tvb,
				    offset,
				    4,
				    FALSE);
		magic = tvb_get_ntohl(tvb, offset);
		
		offset += 4;
		if (GENERIC_HDR_MAGIC != magic) goto out;
		proto_tree_add_item(tree,
				    hf_rgmanager_generic_msg_hdr_length,
				    tvb,
				    offset,
				    4,
				    FALSE);
		
		offset += 4;
		proto_tree_add_item(tree,
				    hf_rgmanager_generic_msg_hdr_command,
				    tvb,
				    offset,
				    4,
				    FALSE);
		command = tvb_get_ntohl(tvb, offset);
		
		offset += 4;
		switch (command)
		{
		case RG_STATUS:
			offset += dissect_rgmanager_generic_args(tvb, pinfo, tree, 
								 length, offset,
								 hf_rgmanager_generic_msg_hdr_status_fast,
								 0);
			break;
		case RG_STATUS_NODE:
			offset += dissect_rgmanager_generic_args(tvb, pinfo, tree, 
								 length, offset,
								 0,
								 0);
			break;
		case RG_LOCK:
		case RG_UNLOCK:
		case RG_QUERY_LOCK:
			offset += dissect_rgmanager_generic_args(tvb, pinfo, tree, 
								 length, offset,
								 0,
								 0);
			break;
		case RG_ACTION_REQUEST:
			offset += dissect_rgmanager_generic_args(tvb, pinfo, tree, 
								 length, offset,
								 hf_rgmanager_generic_msg_hdr_owner,
								 hf_rgmanager_generic_msg_hdr_last);
			offset += dissect_rgmanager_sm_data(tvb, pinfo, tree,
							    length, offset,
							    command);
			break;
		case RG_EVENT:
			offset += dissect_rgmanager_generic_args(tvb, pinfo, tree, 
								 length, offset,
								 hf_rgmanager_generic_msg_hdr_owner,
								 hf_rgmanager_generic_msg_hdr_last);
			offset += dissect_rgmanager_sm_data(tvb, pinfo, tree,
							    length, offset,
							    command);
			break;
		case RG_EXITING:
			offset += dissect_rgmanager_generic_args(tvb, pinfo, tree, 
								 length, offset,
								 hf_rgmanager_generic_msg_hdr_exiting_node_id,
								 0);
			/* ??? */
			offset += dissect_rgmanager_sm_data     (tvb, pinfo, tree,
								 length, offset, command);
			break;
		case VF_MESSAGE:
			/* TODO
			   rgmanager/2.0.38-2.el5/pre-build/rgmanager-2.0.38/src/clulib/vft.c
			*/
			offset += dissect_rgmanager_vf_message(tvb, pinfo, tree, 
							       length, offset);
			break;
		default:
			break;
		}
	}
out:
	return length;
}

void
proto_register_rgmanager(void)
{
	static hf_register_info hf[] = {
		{ &hf_rgmanager_cluster_msg_header_src_ctx,
		  { "Source context",   "rgmanager.cluster_msg_header.src_ctx",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_src_nodeid,
		  { "Source node id",   "rgmanager.cluster_msg_header.src_nodeid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_dest_ctx,
		  { "Destination context",   "rgmanager.cluster_msg_header.dest_ctx",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_dest_nodeid,
		  { "Destination node id",   "rgmanager.cluster_msg_header.dest_nodeid",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_msg_control,
		  { "Message contorol", "rgmanager.cluster_msg_header.msg_contorol",
		    FT_UINT8, BASE_DEC, VALS(vals_cluster_msg_header_msg_control), 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_msg_port,
		  { "Message port", "rgmanager.cluster_msg_header.msg_port",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_pad,
		  { "Padding", "rgmanager.cluster_msg_header.pad",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_cluster_msg_header_reserved,
		  { "Reserved", "rgmanager.cluster_msg_header.reserved",
		    FT_BYTES, BASE_NONE, NULL, 0x0, /* BASE_HEX is Rejected.  */
		    NULL, HFILL }},

		{ &hf_rgmanager_generic_msg_hdr_magic,
		  { "Magic", "rgmanager.generic_msg_hdr.magic",
		    FT_UINT32, BASE_HEX, VALS(vals_generic_msg_hdr_magic), 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_length,
		  { "Length", "rgmanager.generic_msg_hdr.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_command,
		  { "Command", "rgmanager.generic_msg_hdr.command",
		    FT_UINT32, BASE_HEX, VALS(vals_generic_msg_hdr_command), 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_arg1,
		  { "Arguement 1", "rgmanager.generic_msg_hdr.arg1",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_arg2,
		  { "Arguement 2", "rgmanager.generic_msg_hdr.arg2",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_arg3,
		  { "Arguement 3", "rgmanager.generic_msg_hdr.arg3",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_status_fast,
		  { "Fast", "rgmanager.generic_msg_hdr.status_fast",
		    FT_UINT32, BASE_DEC, VALS(vals_generic_msg_hdr_status_fast), 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_exiting_node_id,
		  { "Exiting node id", "rgmanager.generic_msg_hdr.exiting_node_id",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_vf_command,
		  { "View formation command holder", "rgmanager.generic_msg_hdr.vf_command",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_command,
		  { "VF command", "rgmanager.vf_command",
		    FT_UINT32, BASE_HEX, VALS(vals_vf_msg_info_command), VF_COMMAND_MASK,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_flags,
		  { "VF flags", "rgmanager.vf_flags",
		    FT_UINT32, BASE_HEX, VALS(vals_vf_msg_info_flags), VF_FLAGS_MASK,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_owner,
		  { "Node id of owner", "rgmanager.generic_msg_hdr.owner",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_last,
		  { "Node id of the last owner", "rgmanager.generic_msg_hdr.last",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_generic_msg_hdr_vf_trans,
		  { "View formed transaction", "rgmanager.generic_msg_hdr.vf_trans",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_rgmanager_vf_msg_info,
		  { "View formation message", "rgmanager.vf_msg_info",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		
		{ &hf_rgmanager_vf_msg_info_vf_command,
		  { "Command (unused)", "rgmanager.vf_msg_info.vf_command",
		    FT_UINT32, BASE_HEX, VALS(vals_vf_msg_info_command), VF_COMMAND_MASK,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_msg_info_vf_transaction,
		  { "Transaction", "rgmanager.vf_msg_info.vf_transaction",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_msg_info_vf_keyid,
		  { "Key id", "rgmanager.vf_msg_info.vf_keyid",
		    FT_STRING, BASE_NONE, NULL, 0, /* BASE_HEX is rejected. */
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_msg_info_vf_coordinator,
		  { "Coordinator", "rgmanager.vf_msg_info.vf_coordinator",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_msg_info_vf_datalen,
		  { "Data length", "rgmanager.vf_msg_info.vf_datalen",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_msg_info_vf_view,
		  { "View", "rgmanager.vf_msg_info.vf_view",
		    FT_UINT64, BASE_HEX, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_vf_msg_info_vf_data,
		  { "Data", "rgmanager.vf_msg_info.vf_data",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},

		{ &hf_rgmanager_sm_data,
		  { "Service management data", "rgmanager.sm_data",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_rgmanager_sm_data_svcName,
		  { "Service name", "rgmanager.sm_data.svcName",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_sm_data_action,
		  { "Action", "rgmanager.sm_data.action",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_sm_data_svcState,
		  { "Service state(unused)", "rgmanager.sm_data.svcState",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_sm_data_svcOwner,
		  { "Node id of service owner", "rgmanager.sm_data.svcOwner",
		    FT_UINT32, BASE_DEC, VALS(vals_sm_service_owner), 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_sm_data_ret,
		  { "Return value", "rgmanager.sm_data.ret",
		    FT_INT32, BASE_DEC, VALS(vals_sm_ret), 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_name,
		  { "Name of resource group", "rgmanager.rg_state.rs_name",
		    FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_flags,
		  { "Flags of resource group ", "rgmanager.rg_state.rs_flags",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_magic,
		  { "Magic ", "rgmanager.rg_state.rs_magic",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_owner,
		  { "Owner of resource group ", "rgmanager.rg_state.rs_owner",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_last_owner,
		  { "The last owner of resource group ", "rgmanager.rg_state.rs_last_owner",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_state,
		  { "The state of resource group", "rgmanager.rg_state.rs_state",
		    FT_UINT32, BASE_DEC, VALS(vals_rg_state), 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_restarts,
		  { "The number of restarts", "rgmanager.rg_state.rs_restarts",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_rgmanager_rg_state_rs_transition,
		  { "The last service transaction time", "rgmanager.rg_state.rs_transition",
		    FT_UINT64, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
	};
	
	static gint *ett[] = {
		&ett_rgmanager,
		&ett_rgmanager_generic_msg_hdr_vf_command,
		&ett_rgmanager_vf_msg_info,
		&ett_rgmanager_sm_data,
		&ett_rgmanager_rg_state,
	};

	proto_rgmanager 
		= proto_register_protocol("Resource group manager",
					  "RGMANAGER", "rgmanager");
	
	proto_register_field_array(proto_rgmanager, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rgmanager(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t rgmanager_handle;

	if (register_dissector) {
		dissector_delete_uint("openais_cman.tgtport", RGMANAGER_CMAN_TGTPORT, rgmanager_handle);
	} else {
		rgmanager_handle = new_create_dissector_handle(dissect_rgmanager, proto_rgmanager);
		register_dissector = TRUE;
	}
	dissector_add_uint("openais_cman.tgtport", RGMANAGER_CMAN_TGTPORT, rgmanager_handle);
}



#if 0
-*- mode: grep; default-directory: "/var/lib/lcopy/sources/r/rgmanager/trunk/rgmanager/" -*-
Grep started at Wed Feb 11 03:31:12

find . -type f -print0 | xargs -0 -e grep -nH -e '\<msg_receive\>'
./src/daemons/service_op.c:168:		msg_ret = msg_receive(&ctx, &msg,
./src/daemons/rg_forward.c:106:		ret = msg_receive(ctx, &msg, sizeof(msg), 10);
./src/daemons/rg_forward.c:209:		ret = msg_receive(ctx, &msg, sizeof(msg), 10);
./src/daemons/groups.c:1201:	msg_receive(ctx, &hdr, sizeof(hdr), 10);
./src/daemons/main.c:101:	msg_receive(ctx, &hdr, sizeof(hdr), 10);
./src/daemons/main.c:421:	sz = msg_receive(ctx, msg_hdr, sizeof(msgbuf), 1);
./src/daemons/main.c:610:		msg_receive(ctx, NULL, 0, 0);
./src/daemons/main.c:616:		msg_receive(ctx, NULL, 0, 0);
./src/daemons/main.c:621:		msg_receive(ctx, NULL, 0, 0);
./src/daemons/main.c:647:		msg_receive(ctx, NULL, 0, 0);
./src/daemons/main.c:655:		msg_receive(ctx, NULL, 0, 0);
./src/daemons/main.c:666:		msg_receive(ctx, NULL, 0, 0);
./src/daemons/rg_state.c:1045:		if (msg_receive(&ctx, &response, sizeof (response), 5) != sizeof(response))
./src/daemons/rg_state.c:1624:		msg_ret = msg_receive(&ctx, &msg_relo,
./src/clulib/vft.c:307:		x = msg_receive(mcast_ctx, &response, sizeof(response), 1);
./src/clulib/msgsimple.c:73:	ret = msg_receive(ctx, peek_msg, sizeof(msgbuf), timeout);

Grep finished (matches found) at Wed Feb 11 03:31:12

#endif /* 0 */

#if 0
SmMessageSt => generic_msg_hdr...too deep
#endif /* 0 */
