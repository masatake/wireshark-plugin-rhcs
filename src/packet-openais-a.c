/* packet-openais-a.c
 * Routines for dissecting protocol used in "a" group running on OpenAIS
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

#include "packet-corosync-totemsrp.h"
#include "packet-corosync-totempg.h"
#include "packet-openais-a.h"


/* Forward declaration we need below */
void proto_reg_handoff_openais_a(void);

static guint16 openais_a_get_guint16(tvbuff_t* tvb, gint offset, gboolean little_endian);
#if 0
static guint32 openais_a_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
#endif 

/* Initialize the protocol and registered fields */
static int proto_openais_a = -1;

/* fields for struct cl_protheader */
static int hf_openais_a_header                 = -1;
static int hf_openais_a_header_size            = -1;
static int hf_openais_a_header_size_padding    = -1;
static int hf_openais_a_header_id              = -1;
static int hf_openais_a_header_id_padding      = -1;
static int hf_openais_a_header_id_service      = -1;
static int hf_openais_a_header_id_fn_id        = -1;

/* Initialize the subtree pointers */
static gint ett_openais_a                      = -1;
static gint ett_openais_a_header               = -1;
static gint ett_openais_a_header_id            = -1;

/* openais-0.80.3/include/ipc_gen.h */
enum service_types {
	EVS_SERVICE = 0,
	CLM_SERVICE = 1,
	AMF_SERVICE = 2,
	CKPT_SERVICE = 3,
	EVT_SERVICE = 4,
	LCK_SERVICE = 5,
	MSG_SERVICE = 6,
	CFG_SERVICE = 7,
	CPG_SERVICE = 8
};
const value_string vals_openais_a_service[] = {
	{ EVS_SERVICE,  "EVS" },
	{ CLM_SERVICE,  "CLM" },
	{ AMF_SERVICE,  "AMF" },
	{ CKPT_SERVICE, "CKPT" },
	{ EVT_SERVICE,  "EVT" },
	{ LCK_SERVICE,  "LCK" },
	{ MSG_SERVICE,  "MSG" },
	{ CFG_SERVICE,  "CFG" },
	{ CPG_SERVICE,  "CPG" },
	{ 0, NULL }
};

static dissector_table_t subdissector_table;

struct openais_a_info {
	void*       original_private_date;
	proto_item* service_item;

        guint16     fn_id;
	proto_item* fn_id_item;
        gint32      size;
};

static gint
dissect_openais_a_id(proto_tree *parent_tree,
		     tvbuff_t   *tvb,
		     int         id_offset,
		     gboolean    id_little_endian,
		     void       *data)
{
	int original_offset;
	proto_tree *tree;
	proto_item *item;

	struct openais_a_info* info;


	info = data;


	original_offset = id_offset;
	item = proto_tree_add_item(parent_tree, hf_openais_a_header_id, 
				   tvb, id_offset, -1, id_little_endian);
	tree = proto_item_add_subtree(item, ett_openais_a_header_id);


	id_offset += 0;
	if (id_little_endian) {
		info->fn_id_item 
			= proto_tree_add_item(tree,
					      hf_openais_a_header_id_fn_id,
					      tvb, id_offset, 2, id_little_endian);
		info->fn_id = openais_a_get_guint16(tvb, id_offset, id_little_endian);
	}
	else
		info->service_item 
			= proto_tree_add_item(tree,
					      hf_openais_a_header_id_service,
					      tvb, id_offset, 2, id_little_endian);

	id_offset += 2;
	if (id_little_endian)
		info->service_item 
			= proto_tree_add_item(tree,
					      hf_openais_a_header_id_service,
					      tvb, id_offset, 2, id_little_endian);
	else {
		info->fn_id_item 
			= proto_tree_add_item(tree,
					      hf_openais_a_header_id_fn_id,
					      tvb, id_offset, 2, id_little_endian);
		info->fn_id = openais_a_get_guint16(tvb, id_offset, id_little_endian);
	}

	id_offset += 2;

	return (id_offset - original_offset);
  
	data = data;
}

static int
dissect_openais_a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	guint    length;
	int      offset;
	int      sub_length;

	gboolean little_endian;

	proto_tree *tree;
	proto_item *item;

	gint32 a_size;
	gint32 a_id;


	length = tvb_length(tvb);
	if (length < (corosync_totempg_dissect_mar_req_header_length))
	  return 0;

	/* if (check_col(pinfo->cinfo, COL_PROTOCOL))
	   col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPENAIS/a"); */
	  
	/* if (check_col(pinfo->cinfo, COL_INFO))
	   col_clear(pinfo->cinfo, COL_INFO); */

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(a");
	  
	if (!parent_tree)
		goto out;


	little_endian = corosync_totempg_is_little_endian(pinfo);
	offset = 0;

	item = proto_tree_add_item(parent_tree, proto_openais_a, tvb, 
 				   offset, -1, little_endian);
	tree = proto_item_add_subtree(item, ett_openais_a);

	offset += 0;
	{
		struct openais_a_info info;

		
		info.original_private_date = pinfo->private_data;
		pinfo->private_data        = &info;
		sub_length
			= corosync_totempg_dissect_mar_req_header(tvb,
							 pinfo,
							 tree,
							 length, 
							 offset,
							 hf_openais_a_header, ett_openais_a_header,
							 hf_openais_a_header_size, hf_openais_a_header_size_padding,
							 hf_openais_a_header_id, hf_openais_a_header_id_padding,
							 little_endian,
							 &a_size, &a_id,
							 dissect_openais_a_id, pinfo->private_data);
		if (sub_length != corosync_totempg_dissect_mar_req_header_length)
			goto restore_pdata;
		info.size = a_size;


		offset += sub_length;
		{
			tvbuff_t *sub_tvb;
			sub_tvb = tvb_new_subset(tvb, offset, 
						 length - offset,
						 length - offset);
			dissector_try_port(subdissector_table, a_id >> 16, sub_tvb, pinfo, tree);
		}

	restore_pdata:
		pinfo->private_data = info.original_private_date;
		
	}
out:
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_str(pinfo->cinfo, COL_INFO, ")");
	return tvb_length(tvb);
}


void
proto_register_openais_a(void)
{
	/* Setup list of fields */
	static hf_register_info hf[] = {
		{ &hf_openais_a_header,
		  { "Header", "openais_a.header",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_a_header_size,
		  { "Size", "openais_a.header.size",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_a_header_size_padding,
		  { "Padding", "openais_a.header.size_padding",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_a_header_id,
		  { "Id", "openais_a.header.id",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_openais_a_header_id_service,
		  { "Service", "openais_a.header.id.service",
		    FT_INT16, BASE_DEC, VALS(vals_openais_a_service), 0x0,
		    NULL, HFILL }},
		{ &hf_openais_a_header_id_fn_id,
		  { "Function index", "openais_a.header.id.fn_id",
		    FT_INT16, BASE_DEC, NULL, 0x0, 
		    NULL, HFILL }},
		{ &hf_openais_a_header_id_padding,
		  { "Padding", "openais_a.header.id_padding",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_openais_a,
		&ett_openais_a_header,
		&ett_openais_a_header_id,
	};
  
	proto_openais_a 
		= proto_register_protocol("Protocol used in \"a\" group running on OpenAIS",
					  "OPENAIS/A", "openais_a");

	proto_register_field_array(proto_openais_a, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


	subdissector_table = register_dissector_table("openais_a.header.id.service",
						      "The service id",
						      FT_UINT16, BASE_DEC);
}

/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_openais_a(void)
{
	static gboolean register_dissector = FALSE;
	static dissector_handle_t openais_a_handle;

	if (register_dissector) {
		dissector_delete_string("corosync_totempg.group_name", "a", openais_a_handle);
	} else {
		openais_a_handle = new_create_dissector_handle(dissect_openais_a,
								  proto_openais_a);
		register_dissector = TRUE;
	}
	dissector_add_string("corosync_totempg.group_name", "a", openais_a_handle);
}

gboolean openais_a_is_little_endian(packet_info *pinfo)
{
	struct openais_a_info* info;
	gboolean r;


	info = pinfo->private_data;
	{
		pinfo->private_data = info->original_private_date;
		r = corosync_totempg_is_little_endian(pinfo);
	}
	pinfo->private_data = info;

	return r;
}

proto_item* 
openais_a_get_service_item(packet_info *pinfo)
{
  struct openais_a_info* info;

  info = pinfo->private_data;
  return info->service_item;
}

proto_item* 
openais_a_get_fn_id_item  (packet_info *pinfo)
{
  struct openais_a_info* info;

  info = pinfo->private_data;
  return info->fn_id_item;
}

guint16
openais_a_get_fn_id       (packet_info *pinfo)
{
  struct openais_a_info* info;

  info = pinfo->private_data;
  return info->fn_id;
}

gint32
openais_a_get_size        (packet_info *pinfo)
{
  struct openais_a_info* info;

  info = pinfo->private_data;
  return info->size;
}


static guint16
openais_a_get_guint16(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
  return (little_endian? tvb_get_letohs: tvb_get_ntohs)(tvb, offset);
}


/* Taken from `SaAisErrorT'
   of openais-0.80.3/include/saAis.h 

    Prefixes are rearranged. */
#define  OPENAIS_ERROR_OK                    1
#define  OPENAIS_ERROR_LIBRARY               2
#define  OPENAIS_ERROR_VERSION               3
#define  OPENAIS_ERROR_INIT                  4
#define  OPENAIS_ERROR_TIMEOUT               5
#define  OPENAIS_ERROR_TRY_AGAIN             6
#define  OPENAIS_ERROR_INVALID_PARAM         7
#define  OPENAIS_ERROR_NO_MEMORY             8
#define  OPENAIS_ERROR_BAD_HANDLE            9
#define  OPENAIS_ERROR_BUSY                  10
#define  OPENAIS_ERROR_ACCESS                11
#define  OPENAIS_ERROR_NOT_EXIST             12
#define  OPENAIS_ERROR_NAME_TOO_LONG         13
#define  OPENAIS_ERROR_EXIST                 14
#define  OPENAIS_ERROR_NO_SPACE              15
#define  OPENAIS_ERROR_INTERRUPT             16
#define  OPENAIS_ERROR_NAME_NOT_FOUND        17
#define  OPENAIS_ERROR_NO_RESOURCES          18
#define  OPENAIS_ERROR_NOT_SUPPORTED         19
#define  OPENAIS_ERROR_BAD_OPERATION         20
#define  OPENAIS_ERROR_FAILED_OPERATION      21
#define  OPENAIS_ERROR_MESSAGE_ERROR         22
#define  OPENAIS_ERROR_QUEUE_FULL            23
#define  OPENAIS_ERROR_QUEUE_NOT_AVAILABLE   24
#define  OPENAIS_ERROR_BAD_FLAGS             25
#define  OPENAIS_ERROR_TOO_BIG               26
#define  OPENAIS_ERROR_NO_SECTIONS           27

const value_string vals_openais_a_error[] = {
	{ OPENAIS_ERROR_OK,                   "OK"                  },
	{ OPENAIS_ERROR_LIBRARY,              "LIBRARY"             },
	{ OPENAIS_ERROR_VERSION,              "VERSION"             },
	{ OPENAIS_ERROR_INIT,                 "INIT"                },
	{ OPENAIS_ERROR_TIMEOUT,              "TIMEOUT"             },
	{ OPENAIS_ERROR_TRY_AGAIN,            "TRY AGAIN"           },
	{ OPENAIS_ERROR_INVALID_PARAM,        "INVALID PARAM"       },
	{ OPENAIS_ERROR_NO_MEMORY,            "NO MEMORY"           },
	{ OPENAIS_ERROR_BAD_HANDLE,           "BAD HANDLE"          },
	{ OPENAIS_ERROR_BUSY,                 "BUSY"                },
	{ OPENAIS_ERROR_ACCESS,               "ACCESS"              },
	{ OPENAIS_ERROR_NOT_EXIST,            "NOT EXIST"           },
	{ OPENAIS_ERROR_NAME_TOO_LONG,        "TOO LONG"            },
	{ OPENAIS_ERROR_EXIST,                "EXIST"               },
	{ OPENAIS_ERROR_NO_SPACE,             "NO SPACE"            },
	{ OPENAIS_ERROR_INTERRUPT,            "INTERRUPT"           },
	{ OPENAIS_ERROR_NAME_NOT_FOUND,       "NOT FOUND"           },
	{ OPENAIS_ERROR_NO_RESOURCES,         "NO RESOURCES"        },
	{ OPENAIS_ERROR_NOT_SUPPORTED,        "NOT SUPPORTED"       },
	{ OPENAIS_ERROR_BAD_OPERATION,        "BAD OPERATION"       },
	{ OPENAIS_ERROR_FAILED_OPERATION,     "FAILED OPERATION"    },
	{ OPENAIS_ERROR_MESSAGE_ERROR,        "MESSAGE ERROR"       },
	{ OPENAIS_ERROR_QUEUE_FULL,           "QUEUE FULL"          },
	{ OPENAIS_ERROR_QUEUE_NOT_AVAILABLE,  "QUEUE NOT AVAILABLE" },
	{ OPENAIS_ERROR_BAD_FLAGS,            "BAD FLAGS"           },
	{ OPENAIS_ERROR_TOO_BIG,              "TOO BIG"             },
	{ OPENAIS_ERROR_NO_SECTIONS,          "NO SECTIONS"         },

	{ 0,                                  NULL                  },
			
};

/* packet-openais-a.c ends here */
