/* packet-corosync-totempg.h
 * Dissctors for totem process groups header of corosync cluster engine
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

#ifndef __PACKET_COROSYNC_TOTEMPG_H__
#define __PACKET_COROSYNC_TOTEMPG_H__

/* subdissectors for corosync_totempg can know the endian information
   embedded in totemsrp packet header. */
extern gboolean corosync_totempg_is_little_endian(packet_info *pinfo);


#define corosync_totempg_dissect_mar_req_header_length (8 + 8)
extern gint corosync_totempg_dissect_mar_req_header(tvbuff_t *tvb,
						    packet_info *pinfo, 
						    proto_tree *parent_tree,
						    guint length, int offset,
						    /*  */
						    int hf_header, int ett_header,
						    int hf_size, int hf_size_padding,   
						    int hf_id,   int hf_id_padding,
						    /*  */
						    gboolean little_endian,
						    /* NULL is acceptbale. */
						    gint32 *size, gint32 *id,
						    gint (* id_callback)(proto_tree *,
									 tvbuff_t   *,
									 int    id_offset,
									 gboolean id_little_endian,
									 void        *),
						    void* data);

#endif /* packet-corosync_totempg.h */
