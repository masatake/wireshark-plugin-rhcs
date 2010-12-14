/* packet-clumond.c
 *
 * Routines for clumond dissection
 * Copyright 2009, Red Hat, Inc.
 * Copyright 2009, Masatake YAMATO <yamato@redhat.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <epan/packet.h>

static int proto_clumond = -1;
static int hf_clumond_xml = -1;

static gint ett_clumond = -1;

#define CLUMOND_PORT 16851
static guint clumond_port  = CLUMOND_PORT;

dissector_handle_t xml_handle;

static int
dissect_clumond(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  guint length;
  proto_item *item;
  proto_tree *tree;

  length = tvb_length(tvb);
  

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLUMOND");

  if (parent_tree)
    {
      item = proto_tree_add_item(parent_tree, proto_clumond, tvb, 0,
				 length, TRUE);
      tree = proto_item_add_subtree(item, ett_clumond);

      {
	tvbuff_t* new_tvb;

	new_tvb = tvb_new_subset(tvb,0,-1,-1);
	call_dissector(xml_handle, new_tvb, pinfo, tree);
      }
    }

  return length;
}

void
proto_register_clumond (void)
{
  static hf_register_info hf[] = {
    { &hf_clumond_xml,
      { "XML", "clumond.xml", FT_STRING, FT_NONE, NULL, 0x0,
	NULL, HFILL }},
  };
  
  static gint *ett[] = {
    &ett_clumond,
  };

  proto_clumond = proto_register_protocol ("Clumond",
					   "clumond", "clumond");
  proto_register_field_array (proto_clumond, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_clumond (void)
{
  static gboolean dissector_registered = FALSE;

  static guint port;

  static dissector_handle_t clumond_handle;

  if (!dissector_registered) {
    clumond_handle = new_create_dissector_handle(dissect_clumond, proto_clumond);
    xml_handle = find_dissector("xml");
    dissector_registered = TRUE;
  } else {
    dissector_delete("tcp.port",  port,  clumond_handle);
  }

  port  = clumond_port;
  dissector_add("tcp.port",  port,  clumond_handle);
}
