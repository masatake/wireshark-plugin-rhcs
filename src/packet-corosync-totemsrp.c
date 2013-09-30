/* packet-corosync-totemsrp.c
 * Dissectors for totem single ring protocol implementated in corosync cluster engine
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

/* Fields description are taken from
   
   1. "The Totem Single-Ring Ordering and Membership Protocol"
   Y.AMIR, L.E.MOSER, P.M.MELLIAR-SMITH, D.A.AGARWAL, P.CIARFELLA */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#include "packet-corosync-totemsrp.h"


/* Forward declaration we need below */
void proto_reg_handoff_corosync_totemsrp(void);

/* Initialize the protocol and registered fields */
static int proto_corosync_totemsrp = -1;

static heur_dissector_list_t heur_subdissector_list;

/* fields for struct message_header */
static int hf_corosync_totemsrp_message_header_type            = -1;
static int hf_corosync_totemsrp_message_header_encapsulated    = -1;
static int hf_corosync_totemsrp_message_header_endian_detector = -1;
static int hf_corosync_totemsrp_message_header_nodeid          = -1;

/* fields for struct orf_token */
static int hf_corosync_totemsrp_orf_token                      = -1;
static int hf_corosync_totemsrp_orf_token_seq                  = -1;
static int hf_corosync_totemsrp_orf_token_token_seq            = -1;
static int hf_corosync_totemsrp_orf_token_aru                  = -1;
static int hf_corosync_totemsrp_orf_token_aru_addr             = -1;
static int hf_corosync_totemsrp_orf_token_backlog              = -1;
static int hf_corosync_totemsrp_orf_token_fcc                  = -1;
static int hf_corosync_totemsrp_orf_token_retrnas_flg          = -1;
static int hf_corosync_totemsrp_orf_token_rtr_list_entries     = -1;

/* field for struct memb_ring_id */
static int hf_corosync_totemsrp_memb_ring_id                   = -1;
static int hf_corosync_totemsrp_memb_ring_id_seq               = -1;

/* field for struct totem_ip_address */
static int hf_corosync_totemsrp_ip_address                     = -1;
static int hf_corosync_totemsrp_ip_address_nodeid              = -1;
static int hf_corosync_totemsrp_ip_address_family              = -1;
static int hf_corosync_totemsrp_ip_address_addr                = -1;
static int hf_corosync_totemsrp_ip_address_addr4               = -1;
static int hf_corosync_totemsrp_ip_address_addr4_padding       = -1;
static int hf_corosync_totemsrp_ip_address_addr6               = -1;

/* field of struct mcast */
static int hf_corosync_totemsrp_mcast                          = -1;
static int hf_corosync_totemsrp_mcast_seq                      = -1;
static int hf_corosync_totemsrp_mcast_this_seqno               = -1;
static int hf_corosync_totemsrp_mcast_node_id                  = -1;
static int hf_corosync_totemsrp_mcast_system_from              = -1;
static int hf_corosync_totemsrp_mcast_guarantee                = -1;

/* field of struct memb_merge_detect */
static int hf_corosync_totemsrp_memb_merge_detect              = -1;

/* field of struct struct srp_addr */
static int hf_corosync_totemsrp_srp_addr                       = -1;

/* field of struct rtr_item */
static int hf_corosync_totemsrp_rtr_item                       = -1;
static int hf_corosync_totemsrp_rtr_item_seq                   = -1;

/* field of struct memb_join */
static int hf_corosync_totemsrp_memb_join                      = -1;
static int hf_corosync_totemsrp_memb_join_proc_list_entries    = -1;
static int hf_corosync_totemsrp_memb_join_failed_list_entries  = -1;
static int hf_corosync_totemsrp_memb_join_ring_seq             = -1;

/* field of struct memb_commit_token  */
static int hf_corosync_totemsrp_memb_commit_token              = -1;
static int hf_corosync_totemsrp_memb_commit_token_token_seq    = -1;
static int hf_corosync_totemsrp_memb_commit_token_retrans_flg  = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_index   = -1;
static int hf_corosync_totemsrp_memb_commit_token_addr_entries = -1;

/* field of struct memb_commit_token_memb_entry  */
static int hf_corosync_totemsrp_memb_commit_token_memb_entry                = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_entry_aru            = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_entry_high_delivered = -1;
static int hf_corosync_totemsrp_memb_commit_token_memb_entry_received_flg   = -1;

/* field of struct token_hold_cancel */
static int hf_corosync_totemsrp_token_hold_cancel              = -1;

/* Initialize the subtree pointers */
static gint ett_corosync_totemsrp                              = -1;
static gint ett_corosync_totemsrp_orf_token                    = -1;
static gint ett_corosync_totemsrp_memb_ring_id                 = -1;
static gint ett_corosync_totemsrp_ip_address                   = -1;
static gint ett_corosync_totemsrp_mcast                        = -1;
static gint ett_corosync_totemsrp_memb_merge_detect            = -1;
static gint ett_corosync_totemsrp_srp_addr                     = -1;
static gint ett_corosync_totemsrp_rtr_item                     = -1;
static gint ett_corosync_totemsrp_memb_join                    = -1;
static gint ett_corosync_totemsrp_memb_commit_token            = -1;
static gint ett_corosync_totemsrp_memb_commit_token_memb_entry = -1;
static gint ett_corosync_totemsrp_token_hold_cancel            = -1;
static gint ett_corosync_totemsrp_memb_join_proc_list          = -1;
static gint ett_corosync_totemsrp_memb_join_failed_list        = -1;


/* 
 * Value strings
 */
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_ORF_TOKEN         0
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST             1
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_MERGE_DETECT 2
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_JOIN         3
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_COMMIT_TOKEN 4
#define COROSYNC_TOTEMSRP_MESSAGE_TYPE_TOKEN_HOLD_CANCEL 5
          
static const value_string corosync_totemsrp_message_header_type[] = {
        { COROSYNC_TOTEMSRP_MESSAGE_TYPE_ORF_TOKEN,         "orf"               },
        /* { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST,             "multicast message" }, */
	{ COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST,             "mcast" },
        { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_MERGE_DETECT, "merge rings"       },
        { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_JOIN,         "join message"      },
        { COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_COMMIT_TOKEN, "commit token"      },
        { COROSYNC_TOTEMSRP_MESSAGE_TYPE_TOKEN_HOLD_CANCEL, "cancel"            },
        { 0, NULL                                                               }
};

#define COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED     1
#define COROSYNC_TOTEMSRP_MESSAGE_NOT_ENCAPSULATED 2

static const value_string corosync_totemsrp_message_header_encapsulated[] = {
        { 0,                                              "not mcast message" },
        { COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED,         "encapsulated"      },
        { COROSYNC_TOTEMSRP_MESSAGE_NOT_ENCAPSULATED,     "not encapsulated"  },
        { 0, NULL                                                             }
};


static const value_string corosync_totemsrp_ip_address_family[] = {
        { AF_INET,  "AF_INET"  },
        { AF_INET6, "AF_INET6" },
        { 0, NULL              }
};

static guint16  corosync_totemsrp_get_guint16(tvbuff_t* tvb, gint offset, gboolean little_endian);

static guint32  corosync_totemsrp_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian);
static gint32   corosync_totemsrp_get_gint32 (tvbuff_t* tvb, gint offset, gboolean little_endian);


#define COROSYNC_TOTEMSRP_ENDIAN_LOCAL   {0xff, 0x22}


#define COROSYNC_TOTEMSRP_SRP_ADDR_INTERFACE_MAX 2

struct corosync_totemsrp_info {
        void*       original_private_data;
        gboolean    little_endian;
        guint       nodeid;
        proto_tree* master_tree; 
};

static int dissect_corosync_totemsrp0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean encapsulated);


static int
dissect_corosync_totemsrp_ip_address(tvbuff_t *tvb,
                            packet_info *pinfo, proto_tree *parent_tree,
                            guint length, int offset,
                            gboolean little_endian,
                            gboolean print_interface,
                            guint    interface,
                            guint   *nodeid)
{
        int original_offset;
        proto_tree *tree;
        proto_item *item;

        guint16 family;
        gint hf;
        gint len;
  
        if ((length - offset) < corosync_totemsrp_ip_address_length)
                return 0;
        original_offset = offset;

  
        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_ip_address, tvb, offset,
                                   corosync_totemsrp_ip_address_length, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_ip_address);

        proto_item_append_text(item, " (");
        if (print_interface)
                proto_item_append_text(item, "interface: %u; ", interface);


        offset += 0;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_ip_address_nodeid,
                            tvb, offset, 4, little_endian);
        {
                guint nid;
    
                nid = corosync_totemsrp_get_guint32(tvb, offset, little_endian);
                proto_item_append_text(item, "node: %u", nid);
                if (nodeid)
                        *nodeid = nid;
        }
        proto_item_append_text(item, ")");

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_ip_address_family,
                            tvb, offset, 2, little_endian);
        family = corosync_totemsrp_get_guint16(tvb, offset, little_endian);

        offset += 2;
        switch (family)
        {
        case AF_INET:
                hf  = hf_corosync_totemsrp_ip_address_addr4;
                len = 4;
                break;
        case AF_INET6:
                hf  = hf_corosync_totemsrp_ip_address_addr6;
                len = COROSYNC_TOTEMSRP_IP_ADDRLEN;
                break;
        default:
                hf  = hf_corosync_totemsrp_ip_address_addr;
                len = COROSYNC_TOTEMSRP_IP_ADDRLEN;
                break;
        }
        proto_tree_add_item(tree,
                            hf,
                            tvb, offset, len, FALSE);
        offset += len;

        if (len != COROSYNC_TOTEMSRP_IP_ADDRLEN) {
          gint padding_len;

          padding_len = (COROSYNC_TOTEMSRP_IP_ADDRLEN - len);
          proto_tree_add_item (tree,
                               hf_corosync_totemsrp_ip_address_addr4_padding,
                               tvb, offset, padding_len, FALSE);
          offset += padding_len;
        }
          

        return offset - original_offset;

        pinfo = pinfo;
}

static int
dissect_corosync_totemsrp_memb_ring_id(tvbuff_t *tvb,
                              packet_info *pinfo, proto_tree *parent_tree,
                              guint length, int offset,
                              gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;
        guint nodeid;

        if ((length - offset) < corosync_totemsrp_memb_ring_id_length) {
                fprintf(stderr, "We have: %d, expected: %lu\n",
                        (length - offset),
                        corosync_totemsrp_memb_ring_id_length);
                return 0;
        }
        original_offset = offset;
  
        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_ring_id, tvb, offset,
                                   corosync_totemsrp_memb_ring_id_length, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_ring_id);

        offset += 0;
        sub_length = dissect_corosync_totemsrp_ip_address(tvb, pinfo, tree,
                                                 length, offset,
                                                 little_endian,
                                                 FALSE, -1,
                                                 &nodeid);
  
        if (sub_length == 0)
                goto out;
        proto_item_append_text(item, " (node: %u)", nodeid);


        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_ring_id_seq,
                            tvb, offset, 8, little_endian);

        offset += 8;
out:
        return offset - original_offset;
}

static int
dissect_corosync_totemsrp_rtr_list(tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *parent_tree,
                          guint length, int offset,
                          gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

#define corosync_totemsrp_rtr_list_length (corosync_totemsrp_memb_ring_id_length + 4)
        if ((length - offset) < corosync_totemsrp_rtr_list_length)
                return 0;
        original_offset = offset;

        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_rtr_item, tvb, offset,
                                   corosync_totemsrp_rtr_list_length, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_rtr_item);

        offset += 0;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_rtr_item_seq,
                            tvb, offset, 4, little_endian);

        offset += 4;
out:
        return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_orf_token(tvbuff_t *tvb,
                           packet_info *pinfo, proto_tree *parent_tree,
                           guint length, int offset,
                           gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

        gint32 rtr_list_entries;
        gint32 i;

#define corosync_totemsrp_orf_token_length ( 4                          \
					     + 4			\
					     + 4			\
					     + 4			\
					     + corosync_totemsrp_memb_ring_id_length \
					     + 4			\
					     + 4			\
					     + 4			\
					     + 4)
        if ((length - offset) < corosync_totemsrp_orf_token_length)
                return 0;
        original_offset = offset;

  
        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_orf_token, tvb, offset,
                                   -1, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_orf_token);

        offset += 0;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_seq,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_token_seq,
                            tvb, offset, 4, little_endian);
        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_aru,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_aru_addr,
                            tvb, offset, 4, little_endian);

        offset += 4;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_backlog,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_fcc,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_retrnas_flg,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_orf_token_rtr_list_entries,
                            tvb, offset, 4, little_endian);
  

  
        rtr_list_entries = corosync_totemsrp_get_gint32(tvb, offset, little_endian);
        if ((length - offset) < (rtr_list_entries * corosync_totemsrp_rtr_list_length) )
                goto out;

        offset += 4;
        for (i = 0; i < rtr_list_entries; i++) {
                sub_length = dissect_corosync_totemsrp_rtr_list(tvb, pinfo, tree,
                                                       length, offset,
                                                       little_endian);
                if (sub_length == 0)
                        goto out;
                offset += sub_length;
        }
out:
        return offset - original_offset;

        pinfo = pinfo;
}

static int
dissect_corosync_totemsrp_srp_addr(tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *parent_tree,
                          guint length, int offset,
                          int   hf,
                          gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

#define corosync_totemsrp_srp_addr_length  (corosync_totemsrp_ip_address_length * COROSYNC_TOTEMSRP_SRP_ADDR_INTERFACE_MAX)
        if ((length - offset) < corosync_totemsrp_srp_addr_length)
                return 0;
        original_offset = offset;

        item = proto_tree_add_item(parent_tree, hf? hf: hf_corosync_totemsrp_srp_addr, tvb, offset,
                                   corosync_totemsrp_srp_addr_length, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_srp_addr);

        offset += 0;
        sub_length = dissect_corosync_totemsrp_ip_address(tvb, pinfo, tree,
                                                 length, offset,
                                                 little_endian,
                                                 TRUE, 0,
                                                 NULL);
        if (sub_length == 0)
                goto out;


        offset += sub_length;
        sub_length = dissect_corosync_totemsrp_ip_address(tvb, pinfo, tree,
                                                 length, offset,
                                                 little_endian,
                                                 TRUE, 1,
                                                 NULL);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
out:
        return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_mcast  (tvbuff_t *tvb,
				  packet_info *pinfo, proto_tree *parent_tree,
				  guint length, int offset,
				  guint8      message_header__encapsulated,
				  gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;


#define corosync_totemsrp_mcast_length (corosync_totemsrp_srp_addr_length \
					+ 4				\
					+ 4				\
					+ corosync_totemsrp_memb_ring_id_length	\
					+ 4				\
					+ 4)
        if ((length - offset) < corosync_totemsrp_mcast_length) {
                return 0;
        }
        original_offset = offset;


        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_mcast, tvb, offset,
                                   -1, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_mcast);

        offset += 0;
        sub_length = dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree,
                                               length, offset,
                                               hf_corosync_totemsrp_mcast_system_from,
                                               little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_mcast_seq,
                            tvb, offset, 4, little_endian);
  
        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_mcast_this_seqno,
                            tvb, offset, 4, little_endian);

        offset += 4;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;
  
        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_mcast_node_id,
                            tvb, offset, 4, little_endian);
  
        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_mcast_guarantee,
                            tvb, offset, 4, little_endian);
  
        offset += 4;

        {
                gint len, reported_len;
                tvbuff_t *next_tvb;
                struct corosync_totemsrp_info* info;

                len = tvb_length_remaining(tvb, offset);
                reported_len = tvb_reported_length_remaining(tvb, offset);

                next_tvb = tvb_new_subset(tvb, offset, len, reported_len);

		if (message_header__encapsulated == COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED)
			offset += dissect_corosync_totemsrp0(next_tvb, pinfo, tree, TRUE);
		else
		{
			info = (struct corosync_totemsrp_info*)pinfo->private_data;
			if (dissector_try_heuristic(heur_subdissector_list,
						    next_tvb,
						    pinfo,
						    info->master_tree,
						    NULL))
				offset = length ;
		}
        }
  
out:
        return (offset - original_offset);
}


static int
dissect_corosync_totemsrp_memb_merge_detect(tvbuff_t *tvb,
                                   packet_info *pinfo, proto_tree *parent_tree,
                                   guint length, int offset,
                                   gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

#define corosync_totemsrp_memb_merge_detect_length (corosync_totemsrp_srp_addr_length + corosync_totemsrp_memb_ring_id_length)
        if ((length - offset) < corosync_totemsrp_memb_merge_detect_length) {
                return 0;
        }
        original_offset = offset;

  
        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_merge_detect, tvb, offset,
                                   -1, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_merge_detect);

        offset += 0;
        sub_length = dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree,
                                               length, offset,
                                               0,
                                               little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
out:  
        return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_memb_join(tvbuff_t *tvb,
                           packet_info *pinfo, proto_tree *parent_tree,
                           guint length, int offset,
                           gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

        guint32 proc_list_entries;
        proto_tree *proc_tree;
        proto_item *proc_item;
  
        guint32 failed_list_entries;
        proto_tree *failed_tree;
        proto_item *failed_item;

        guint i;

  
#define corosync_totemsrp_memb_join_length ( corosync_totemsrp_srp_addr_length \
					     + 4			\
					     + 4			\
					     + 8)
        if ((length - offset) <  corosync_totemsrp_memb_join_length)
                return 0;

        original_offset = offset;


        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_join, tvb, offset,
                                   -1, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_join);


        offset += 0;
        sub_length = dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree,
                                               length, offset,
                                               0,
                                               little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
        proc_item = proto_tree_add_item(tree,
                                        hf_corosync_totemsrp_memb_join_proc_list_entries,
                                        tvb, offset, 4, little_endian);
        proc_list_entries = corosync_totemsrp_get_guint32(tvb, offset, little_endian);

        offset += 4;
        failed_item = proto_tree_add_item(tree,
                                          hf_corosync_totemsrp_memb_join_failed_list_entries,
                                          tvb, offset, 4, little_endian);
        failed_list_entries = corosync_totemsrp_get_guint32(tvb, offset, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_join_ring_seq,
                            tvb, offset, 8, little_endian);

        offset += 8;
        proc_tree = proto_item_add_subtree(proc_item, ett_corosync_totemsrp_memb_join_proc_list);
        for (i = 0; i < proc_list_entries; i++) {
                sub_length = dissect_corosync_totemsrp_srp_addr(tvb, pinfo, proc_tree,
                                                       length, offset,
                                                       0,
                                                       little_endian);
                if (sub_length == 0)
                        goto out;
                offset += sub_length;
        }
  
        failed_tree = proto_item_add_subtree(failed_item, ett_corosync_totemsrp_memb_join_failed_list);
        for (i = 0; i < failed_list_entries; i++) {
                sub_length = dissect_corosync_totemsrp_srp_addr(tvb, pinfo, failed_tree,
                                                       length, offset,
                                                       0,
                                                       little_endian);
                if (sub_length == 0)
                        goto out;
                offset += sub_length;
        }
  
out:
        return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_memb_commit_token_memb_entry(tvbuff_t *tvb,
                                              packet_info *pinfo, proto_tree *parent_tree,
                                              guint length, int offset,
                                              gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

  
#define corosync_totemsrp_memb_commit_token_memb_entry_length ( corosync_totemsrp_memb_ring_id_length \
								+ 4	\
								+ 4	\
								+ 4 )
        if ((length - offset) < corosync_totemsrp_memb_commit_token_memb_entry_length)
                return 0;
        original_offset = offset;

        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_commit_token_memb_entry,
                                   tvb, offset,
                                   corosync_totemsrp_memb_commit_token_memb_entry_length, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_commit_token_memb_entry);
  
  
        offset += 0;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;
  
        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_memb_entry_aru,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_memb_entry_high_delivered,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_memb_entry_received_flg,
                            tvb, offset, 4, little_endian);


        offset += 4;
out:
        return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_memb_commit_token(tvbuff_t *tvb,
                                   packet_info *pinfo, proto_tree *parent_tree,
                                   guint length, int offset,
                                   gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

        gint32 addr_entries;
        gint   i;

#define corosync_totemsrp_memb_commit_token_length  ( 4                 \
						      + corosync_totemsrp_memb_ring_id_length \
						      + 4		\
						      + 4		\
						      + 4)
        if ((length - offset) < corosync_totemsrp_memb_commit_token_length)
                return 0;
  
        original_offset = offset;

  
        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_memb_commit_token,
                                   tvb, offset, -1, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_memb_commit_token);

  
        offset += 0;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_token_seq,
                            tvb, offset, 4, little_endian);

        offset += 4;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;

        offset += sub_length;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_retrans_flg,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_memb_index,
                            tvb, offset, 4, little_endian);

        offset += 4;
        proto_tree_add_item(tree,
                            hf_corosync_totemsrp_memb_commit_token_addr_entries,
                            tvb, offset, 4, little_endian);
        addr_entries = corosync_totemsrp_get_gint32(tvb, offset, little_endian);
  
  
        offset += 4;
        if ((length - offset) < ((corosync_totemsrp_srp_addr_length 
                                  * addr_entries)
                                 + (corosync_totemsrp_memb_commit_token_memb_entry_length 
                                    * addr_entries)))
                goto out;

        for (i = 0; i < addr_entries; i++) {
                sub_length = dissect_corosync_totemsrp_srp_addr(tvb, pinfo, tree, 
                                                       length, offset,
                                                       0,
                                                       little_endian);
                if (sub_length == 0)
                        goto out;
                offset += sub_length;
        }

        for (i = 0; i < addr_entries; i++) {
                sub_length = dissect_corosync_totemsrp_memb_commit_token_memb_entry(tvb, pinfo, tree, 
                                                                           length, offset,
                                                                           little_endian);
                if (sub_length == 0)
                        goto out;
                offset += sub_length;
        }

out:
        return (offset - original_offset);
}

static int
dissect_corosync_totemsrp_token_hold_cancel(tvbuff_t *tvb,
                                   packet_info *pinfo, proto_tree *parent_tree,
                                   guint length, int offset,
                                   gboolean little_endian)
{
        int original_offset;
        int sub_length;
        proto_tree *tree;
        proto_item *item;

#define corosync_totemsrp_token_hold_cancel_length ( corosync_totemsrp_memb_ring_id_length )
        if ((length - offset) <  corosync_totemsrp_token_hold_cancel_length)
                return 0;

        original_offset = offset;


        item = proto_tree_add_item(parent_tree, hf_corosync_totemsrp_token_hold_cancel, tvb, offset,
                                   -1, little_endian);
        tree = proto_item_add_subtree(item, ett_corosync_totemsrp_token_hold_cancel);


        offset += 0;
        sub_length = dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, tree,
                                                   length, offset,
                                                   little_endian);
        if (sub_length == 0)
                goto out;
  
        offset += sub_length;
out:
        return (offset - original_offset);
}

int
dissect_corosync_totemsrp(tvbuff_t *tvb,
			   packet_info *pinfo, proto_tree *parent_tree)
{
	return dissect_corosync_totemsrp0(tvb, pinfo, parent_tree, FALSE);
}

static int
dissect_corosync_totemsrp0(tvbuff_t *tvb,
			   packet_info *pinfo, proto_tree *parent_tree,
			   gboolean encapsulated)
{
        proto_item *item;
        proto_tree *tree;
        guint       length;
        int         offset;

  
        guint8      message_header__type;
        guint8      message_header__encapsulated;

        union EndianDetector {
                guint16 f;
                guint8  b[2];
        } message_header__endian_detector;
        guint8    endian_expect[2] = COROSYNC_TOTEMSRP_ENDIAN_LOCAL;

        gboolean little_endian;

        struct corosync_totemsrp_info info;



        /* Check that there's enough data */
        length = tvb_length(tvb);
        if (length < 1 + 1 + 2 + 4)
                return 0;

        /* message header */
        message_header__type = tvb_get_guint8(tvb, 0);
        if (message_header__type > 5)
                return 0;

        message_header__encapsulated = tvb_get_guint8(tvb, 1);

        /* message_header -- byte order checking */
        tvb_memcpy(tvb, &message_header__endian_detector.f, 2, 2);

        if ((message_header__endian_detector.b[0] == endian_expect[1])
            && (message_header__endian_detector.b[1] == endian_expect[0]))
                little_endian = TRUE;
        else if ((message_header__endian_detector.b[0] == endian_expect[0])
                 && (message_header__endian_detector.b[1] == endian_expect[1]))
                little_endian = FALSE;
        else
                return 0;

        info.little_endian         = little_endian;
	info.nodeid;
        info.original_private_data = pinfo->private_data;
        info.master_tree           = parent_tree;
        pinfo->private_data        = &info;

	if (encapsulated)
		goto after_updating_col;

        if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "COROSYNC/TOTEMSRP");

        if (check_col(pinfo->cinfo, COL_INFO))
                col_clear(pinfo->cinfo, COL_INFO);

        if (check_col(pinfo->cinfo, COL_INFO))
                col_set_str(pinfo->cinfo, COL_INFO, 
                            "COROSYNC/TOTEMSRP");

        if (check_col(pinfo->cinfo, COL_INFO)) {
		int encapsulated = ((message_header__type == COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST)
				    && (message_header__encapsulated == COROSYNC_TOTEMSRP_MESSAGE_ENCAPSULATED));
                col_set_str(pinfo->cinfo, COL_INFO, 
			    encapsulated?
			    "ENCAPSULATED":
			    val_to_str(message_header__type,
                                       corosync_totemsrp_message_header_type,
                                       "packet-corosync-totemsrp.c internal bug"));
	}

after_updating_col:
        if (parent_tree) {
                offset = 0;

                item = proto_tree_add_item(parent_tree, proto_corosync_totemsrp, tvb, offset,
                                           -1, little_endian);
                tree = proto_item_add_subtree(item, ett_corosync_totemsrp);

                offset += 0;
                proto_tree_add_item(tree,
                                    hf_corosync_totemsrp_message_header_type,
                                    tvb, offset, 1, little_endian);
                offset += 1;
                proto_tree_add_item(tree,
                                    hf_corosync_totemsrp_message_header_encapsulated,
                                    tvb, offset, 1, little_endian);

                offset += 1;
                proto_tree_add_item(tree,
                                    hf_corosync_totemsrp_message_header_endian_detector,
                                    tvb, offset, 2, little_endian);

                offset += 2;
                proto_tree_add_item(tree,
                                    hf_corosync_totemsrp_message_header_nodeid,
                                    tvb, offset, 4, little_endian);
        } 
	else {
		tree = parent_tree;
		offset += 0 + 1 + 1 + 2;
	}
	info.nodeid = corosync_totemsrp_get_guint32(tvb, offset, little_endian);
	offset += 4;

	switch (message_header__type) {
	case COROSYNC_TOTEMSRP_MESSAGE_TYPE_ORF_TOKEN:
		dissect_corosync_totemsrp_orf_token(tvb, pinfo, tree, length, offset,
						    little_endian);
		break;
	case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MCAST:
		dissect_corosync_totemsrp_mcast(tvb, pinfo, tree, length, offset,
						message_header__encapsulated,
						little_endian);
		break;
	case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_MERGE_DETECT:
		dissect_corosync_totemsrp_memb_merge_detect(tvb, pinfo, tree, length, offset,
							    little_endian);
		break;
	case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_JOIN:
		dissect_corosync_totemsrp_memb_join(tvb, pinfo, tree, length, offset,
						    little_endian);
		break;
	case COROSYNC_TOTEMSRP_MESSAGE_TYPE_MEMB_COMMIT_TOKEN:
		dissect_corosync_totemsrp_memb_commit_token(tvb, pinfo, tree, length, offset,
							    little_endian);
		break;
	case COROSYNC_TOTEMSRP_MESSAGE_TYPE_TOKEN_HOLD_CANCEL:
		dissect_corosync_totemsrp_token_hold_cancel(tvb, pinfo, tree, length, offset,
							    little_endian);
		break;
	default:
		break;
	}

        pinfo->private_data = info.original_private_data;
        return tvb_length(tvb);
}

void
proto_register_corosync_totemsrp(void)
{
        static hf_register_info hf[] = {
                /* message_header */
                { &hf_corosync_totemsrp_message_header_type,
                  { "Type", "corosync_totemsrp.message_header.type",
                    FT_INT8, BASE_DEC, VALS(corosync_totemsrp_message_header_type), 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_message_header_encapsulated,
                  { "Encapsulated", "corosync_totemsrp.message_header.encapsulated",
                    FT_INT8, BASE_DEC, VALS(corosync_totemsrp_message_header_encapsulated), 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_message_header_endian_detector,
                  { "Endian detector", "corosync_totemsrp.message_header.endian_detector",
                    FT_UINT16, BASE_HEX, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_message_header_nodeid,
                  { "Node ID", "corosync_totemsrp.message_header.nodeid",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                /* orf_token */
                { &hf_corosync_totemsrp_orf_token,
                  { "Ordering, Reliability, Flow (ORF) control Token", "corosync_totemsrp.orf_token",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_orf_token_seq,
                  { "Sequence number allowing recognition of redundant copies of the token", "corosync_totemsrp.orf_token.seq",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_orf_token_token_seq,
                  { "The largest sequence number", "corosync_totemsrp.orf_token.seq",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "The largest sequence number of any message "
                    "that has been broadcast on the ring"
                    "[1]" , 
                    HFILL }},
                { &hf_corosync_totemsrp_orf_token_aru,
                  { "Sequnce number all received up to", "corosync_totemsrp.orf_token.aru",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_orf_token_aru_addr,
                  { "ID of node setting ARU", "corosync_totemsrp.orf_token.aru_addr",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_orf_token_backlog,
                  { "Backlog", "corosync_totemsrp.orf_token.backlog",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "The sum of the number of new message waiting to be transmitted by each processor on the ring "
                    "at the time at which that processor forwarded the token during the previous rotation"
                    "[1]", 
                    HFILL }},
                { &hf_corosync_totemsrp_orf_token_fcc,
                  { "FCC", 
                    "corosync_totemsrp.orf_token.fcc",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "A count of the number of messages broadcast by all processors "
                    "during the previous rotation of the token"
                    "[1]", 
                    HFILL }},
                { &hf_corosync_totemsrp_orf_token_retrnas_flg,
                  { "Retransmission flag", "corosync_totemsrp.orf_token.retrans_flg",
                    FT_INT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_orf_token_rtr_list_entries,
                  { "The number of retransmission list entries", "corosync_totemsrp.orf_token.rtr_list_entries",
                    FT_INT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                /* memb_ring_id */
                { &hf_corosync_totemsrp_memb_ring_id,
                  { "Member ring id", "corosync_totemsrp.memb_ring_id",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_memb_ring_id_seq,
                  { "Squence in member ring id", "corosync_totemsrp.memb_ring_id.seq",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                /* totem_ip_address */
                { &hf_corosync_totemsrp_ip_address,
                  { "Node IP address", "corosync_totemsrp.ip_address",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_ip_address_nodeid,
                  { "Node ID", "corosync_totemsrp.ip_address.nodeid",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_ip_address_family,
                  { "Address family", "corosync_totemsrp.ip_address.family",
                    FT_UINT16, BASE_DEC, VALS(corosync_totemsrp_ip_address_family), 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_ip_address_addr,
                  { "Address", "corosync_totemsrp.ip_address.addr",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_ip_address_addr4,
                  { "Address", "corosync_totemsrp.ip_address.addr4",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_ip_address_addr4_padding,
                  { "Address padding", "corosync_totemsrp.ip_address.addr4_padding",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_ip_address_addr6,
                  { "Address", "corosync_totemsrp.ip_address.addr6",
                    FT_IPv6, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},

                /* mcast */
                { &hf_corosync_totemsrp_mcast,
                  { "ring ordered multicast message", "corosync_totemsrp.mcast",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},
                { &hf_corosync_totemsrp_mcast_seq,
                  {"Multicast sequence number", "corosync_totemsrp.mcast.seq",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL }},
                { &hf_corosync_totemsrp_mcast_this_seqno,
                  {"This Sequence number", "corosync_totemsrp.mcast.this_seqno",
                   FT_INT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL }},
                { &hf_corosync_totemsrp_mcast_node_id,
                  {"Node id(unused?)", "corosync_totemsrp.mcast.node_id",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL }},
                { &hf_corosync_totemsrp_mcast_system_from,
                  {"System from address", "corosync_totemsrp.mcast.system_from",
                   FT_NONE, BASE_NONE, NULL, 0x0,
                   NULL, HFILL }},

                { &hf_corosync_totemsrp_mcast_guarantee,
                  {"Guarantee", "corosync_totemsrp.mcast.guarantee",
                   FT_INT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL }},
      
                /* memb_merge_detect */
                { &hf_corosync_totemsrp_memb_merge_detect,
                  { "Merge rings if there are available rings", "corosync_totemsrp.memb_merge_detect",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL }},

                /* srp_addr */
                { &hf_corosync_totemsrp_srp_addr,
                  {"Single Ring Protocol Address", "corosync_totemsrp.srp_addr",
                   FT_NONE, BASE_NONE, NULL, 0x0,
                   NULL, HFILL }},

                /* rtr_item */
                { &hf_corosync_totemsrp_rtr_item,
                  {"Retransmission Item", "corosync_totemsrp.rtr_item",
                   FT_NONE, BASE_NONE, NULL, 0x0,
                   NULL, HFILL }},
                { &hf_corosync_totemsrp_rtr_item_seq,
                  {"Sequence of Retransmission Item", "corosync_totemsrp.rtr_item.seq",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL }},

                /* memb_join */
                { &hf_corosync_totemsrp_memb_join,
                  {"Membership join message", "corosync_totemsrp.memb_join",
                   FT_NONE, BASE_NONE, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_join_proc_list_entries,
                  {"The number of processor list entries ", "corosync_totemsrp.memb_join.proc_list_entries",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_join_failed_list_entries,
                  {"The number of failed list entries ", "corosync_totemsrp.memb_join.failed_list_entries",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_join_ring_seq,
                  {"Ring sequence number", "corosync_totemsrp.memb_join.ring_seq",
                   FT_UINT64, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},

                /* memb_commit_token */
                { &hf_corosync_totemsrp_memb_commit_token,
                  {"Membership commit token", "corosync_totemsrp.memb_commit_token",
                   FT_NONE, BASE_NONE, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_token_seq,
                  {"Token sequence", "corosync_totemsrp.memb_commit_token.token_seq",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_retrans_flg,
                  {"Retransmission flag", "corosync_totemsrp.memb_commit_token.retrans_flg",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_memb_index,
                  {"Member index", "corosync_totemsrp.memb_commit_token.memb_index",
                   FT_INT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_addr_entries,
                  {"The number of address entries", "corosync_totemsrp.memb_commit_token.addr_entries",
                   FT_INT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},

                /* memb_commit_token_memb_entry */
                { &hf_corosync_totemsrp_memb_commit_token_memb_entry,
                  { "Membership entry", "corosync_totemsrp.memb_commit_token_memb_entry",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_memb_entry_aru,
                  {"Sequnce number all received up to", "corosync_totemsrp.memb_commit_token_memb_entry.aru",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_memb_entry_high_delivered,
                  {"High delivered", "corosync_totemsrp.memb_commit_token_memb_entry.high_delivered",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},
                { &hf_corosync_totemsrp_memb_commit_token_memb_entry_received_flg,
                  {"Received flag", "corosync_totemsrp.memb_commit_token_memb_entry.received_flg",
                   FT_UINT32, BASE_DEC, NULL, 0x0,
                   NULL, HFILL}},

                /* token_hold_canel */
                { &hf_corosync_totemsrp_token_hold_cancel,
                  {"Hold cancel token", "corosync_totemsrp.token_hold_canel",
                   FT_NONE, BASE_NONE, NULL, 0x0,
                   NULL, HFILL}},
        };

        static gint *ett[] = {
                &ett_corosync_totemsrp,
                &ett_corosync_totemsrp_orf_token,
                &ett_corosync_totemsrp_memb_ring_id,
                &ett_corosync_totemsrp_ip_address,
                &ett_corosync_totemsrp_mcast,
                &ett_corosync_totemsrp_memb_merge_detect,
                &ett_corosync_totemsrp_srp_addr,
                &ett_corosync_totemsrp_rtr_item,
                &ett_corosync_totemsrp_memb_join,
                &ett_corosync_totemsrp_memb_commit_token,
                &ett_corosync_totemsrp_memb_commit_token_memb_entry,
                &ett_corosync_totemsrp_token_hold_cancel,
                &ett_corosync_totemsrp_memb_join_proc_list,
                &ett_corosync_totemsrp_memb_join_failed_list

        };

        proto_corosync_totemsrp = proto_register_protocol("Totem Single Ring Protocol implemented in Corosync Cluster Engine",
                                                          "COROSYNC/TOTEMSRP", "corosync_totemsrp");
        proto_register_field_array(proto_corosync_totemsrp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        register_heur_dissector_list("corosync_totemsrp.mcast", &heur_subdissector_list);
}


/* Some code copyed from packet-dlm3.c. */
void
proto_reg_handoff_corosync_totemsrp(void)
{
  /* Nothing to be done.
     dissect_corosync_totemsrp is directly called from corosync_totemnet dissector. */
}



static guint16
corosync_totemsrp_get_guint16(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
        return (little_endian? tvb_get_letohs: tvb_get_ntohs)(tvb, offset);
}


static guint32
corosync_totemsrp_get_guint32(tvbuff_t* tvb, gint offset, gboolean little_endian)
{
        return (little_endian? tvb_get_letohl: tvb_get_ntohl)(tvb, offset);
}

static gint32
corosync_totemsrp_get_gint32 (tvbuff_t* tvb, gint offset, gboolean little_endian)
{       
        union {
                guint32 u;
                gint32  i;
        } v;

        v.u = corosync_totemsrp_get_guint32(tvb, offset, little_endian);
        return v.i;
}




gboolean
corosync_totemsrp_is_little_endian(packet_info *pinfo)
{
        struct corosync_totemsrp_info* info;


        info = (struct corosync_totemsrp_info*)pinfo->private_data;
        return info->little_endian;
}

guint
corosync_totemsrp_nodeid          (packet_info *pinfo)
{
        struct corosync_totemsrp_info* info;


        info = (struct corosync_totemsrp_info*)pinfo->private_data;
        return info->nodeid;
}

int
corosync_totemsrp_dissect_memb_ring_id(tvbuff_t *tvb,
                              packet_info *pinfo, 
                              proto_tree *parent_tree,
                              guint length, int offset)
{
        return dissect_corosync_totemsrp_memb_ring_id(tvb, pinfo, parent_tree,
                                             length, offset,
                                             corosync_totemsrp_is_little_endian(pinfo));
}
