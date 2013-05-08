/* packet-openais-a.h
 * Routines for totem process groups header dissection
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

#ifndef __PACKET_OPENAIS_A_H__
#define __PACKET_OPENAIS_A_H__

/* subdissectors for openais-a can know the endian information
   embedded in totemsrp packet header. */
extern gboolean    openais_a_is_little_endian(packet_info *pinfo);

extern proto_item* openais_a_get_service_item(packet_info *pinfo);
extern proto_item* openais_a_get_fn_id_item  (packet_info *pinfo);
extern guint16     openais_a_get_fn_id       (packet_info *pinfo);
extern gint32      openais_a_get_size        (packet_info *pinfo);

extern const value_string vals_openais_a_error[];
extern const value_string vals_openais_a_service[];

guint32 openais_a_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);

#define openais_a_mar_source_length ( 8 + 8 )
extern int   dissect_openais_a_mar_message_source(tvbuff_t    *tvb,
						  packet_info *pinfo, 
						  proto_tree  *parent_tree,
						  guint length, int offset,
						  gboolean little_endian);

extern int   dissect_openais_a_mar_name(tvbuff_t *tvb,
					packet_info *pinfo, 
					proto_tree *parent_tree,
					guint length, int offset,
					gboolean little_endian,
					gchar** group_name);

#endif /* packet-openais-a.h */
