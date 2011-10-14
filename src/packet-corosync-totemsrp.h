/* packet-corosync-totemsrp.h
 * Dissectors for totem single ring protocol implemented in corosync cluster engine
 * Copyright 2007 2009 2010 Masatake YAMATO <yamato@redhat.com>
 * Copyright (c) 2010 Red Hat, Inc.
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

#ifndef __PACKET_COROSYNC_TOTEMSRP_H__
#define __PACKET_COROSYNC_TOTEMSRP_H__

#include <netinet/in.h>

extern  int dissect_corosync_totemsrp     (tvbuff_t    *tvb,
                                           packet_info *pinfo, 
                                           proto_tree  *parent_tree);


/* subdissectors for corosync_totemsrp can know the endian information
   embedded in totemsrp packet header. */
extern gboolean corosync_totemsrp_is_little_endian(packet_info *pinfo);
extern guint corosync_totemsrp_nodeid             (packet_info *pinfo);

#define COROSYNC_TOTEMSRP_IP_ADDRLEN           (sizeof(struct in6_addr))
#define corosync_totemsrp_ip_address_length    ( 4 + 2 + COROSYNC_TOTEMSRP_IP_ADDRLEN )
#define corosync_totemsrp_memb_ring_id_length  ( 8 + corosync_totemsrp_ip_address_length )

extern  int corosync_totemsrp_dissect_memb_ring_id(tvbuff_t    *tvb,
                                                   packet_info *pinfo, 
                                                   proto_tree  *parent_tree,
                                                   guint        length, 
                                                   int          offset);


#endif /* packet-totemsrp.h */
