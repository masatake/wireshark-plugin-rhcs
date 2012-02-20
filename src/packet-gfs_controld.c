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
#include <stdio.h>
#include <string.h>

#include <epan/packet.h>

#define GFS_CONTROLD_DAEMON_NAME "gfs:controld"

/* Forward declaration we need below */
void proto_reg_handoff_gfs_controld(void);

/* Initialize the protocol and registered fields */
static int proto_gfs_controld = -1;

/* Initialize the subtree pointers */
static gint ett_gfs_controld        = -1;

static int
dissect_gfs_controld(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
		     const gchar* col_str)
{
  guint length;
  int offset;

  proto_tree *gfs_controld_tree, *tree, *version_tree;
  proto_item *item, *version_item;
  guint32 type;

  length = tvb_length(tvb);
#if 0
  if ( length < ( 2 * 3 ) + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 8)
    return 0;
#endif

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_sep_str(pinfo->cinfo, COL_INFO, " ", col_str);

  if (!parent_tree)
    goto out;

  offset = 0;
  item = proto_tree_add_item(parent_tree, proto_gfs_controld, tvb, 
			     offset, -1, TRUE);
  gfs_controld_tree = proto_item_add_subtree(item, ett_gfs_controld);

 out:
  return length;
}

static int
dissect_gfs_controld_daemon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  return dissect_gfs_controld(tvb, pinfo, parent_tree, "gfs:controld");
}

void
proto_register_gfs_controld(void)
{
  /* Setup list of fields */
  static hf_register_info hf[] = {
  };

  static gint *ett[] = {
    &ett_gfs_controld,
  };
  
  proto_gfs_controld = proto_register_protocol("Protocol used in gfs_controld",
					      "gfs_controld", "gfs_controld");
  proto_register_field_array(proto_gfs_controld, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gfs_controld(void)
{
  static gboolean register_dissector = FALSE;
  static dissector_handle_t gfs_controld_daemon_handle;
  static dissector_handle_t gfs_controld_ls_handle;

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
}
