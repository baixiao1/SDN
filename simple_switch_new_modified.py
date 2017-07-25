# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct
import time

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.mac import haddr_to_str
from ryu.lib.ip import *                         
from ryu.lib.ofctl_v1_0 import get_flow_stats    
from ryu.topology import event, switches         
from ryu.topology.api import get_switch, get_link 
from ryu.lib.packet import lldp                   
from ryu.ofproto.ether import ETH_TYPE_LLDP        


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    # predefined IP address and MAC address for h1, h2 & h3
    iphost1 = '10.0.0.1';
    iphost2 = '10.0.0.2';
    iphost3 = '10.0.0.3';
    ipuinthost1 = 167772161
    ipuinthost2 = 167772162
    ipuinthost3 = 167772163
    mhost1 = haddr_to_bin('00:00:00:00:00:01')
    mhost2 = haddr_to_bin('00:00:00:00:00:02')
    mhost3 = haddr_to_bin('00:00:00:00:00:03')

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        self.isInitialize = False
        self.portHost1 = -1;
        self.portHost2 = -1;
        self.portHost3 = -1;
        self.stats = []

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        
        # add wildcards
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        match = datapath.ofproto_parser.OFPMatch(wildcards, in_port, 0, dst, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        # the hard time is 60, so the rules will expire periodically, calling flow-deletion messages.
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=60,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        
        dpid = datapath.id

        # unpack using '6s6sH' to have the packet in certain format
        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        
        # get the port number of host 1 via MAC address
        if (self.portHost1 == -1 and src == SimpleSwitch.mhost1):
            self.portHost1 = msg.in_port
        
        # send states request to switch when host 1 receievd a packet
        if (not self.isInitialize and self.portHost1 != -1):
            self.isInitialize = True
            self._port_status_request(datapath)

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # block IPv4 traffic between host 2 and host 3
        if (self._block_packet(msg.data)):
            actions = []
            self._block_flow(datapath, SimpleSwitch.ipuinthost2, SimpleSwitch.ipuinthost3)
        else:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)
    

    # judging whether the flow is between host 2 and host 3, if yes, set to true, otherwise, set to false.
    def _block_packet(self, data):
        data_packet = packet.Packet(data)
        for protocol in data_packet.protocols:
            if (protocol.protocol_name == 'ipv4' and ((ipv4_to_str(protocol.src) == SimpleSwitch.iphost2 and ipv4_to_str(protocol.dst) == SimpleSwitch.iphost3) or (ipv4_to_str(protocol.src) == SimpleSwitch.iphost3 and ipv4_to_str(protocol.dst) == SimpleSwitch.iphost2))):
                return True
        return False
    
    # blocking flow between host 2 and host 3 as required
    def _block_flow(self, datapath, ip1, ip2):
        matches = []
        ofproto = datapath.ofproto
        
        # response to table states - wildcards (32 bits), which contains all the masks for fields in match structure
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~(ofproto_v1_0.OFPFW_NW_SRC_ALL | ofproto_v1_0.OFPFW_NW_DST_ALL)
        
        matches.append(datapath.ofproto_parser.OFPMatch(
                       wildcards, 0, 0, 0, 0, 0, 0, 0, 0, ip1, ip2, 0, 0))
        matches.append(datapath.ofproto_parser.OFPMatch(
                       wildcards, 0, 0, 0, 0, 0, 0, 0, 0, ip2, ip1, 0, 0))
    
        # setting hard time, and send the request to the switch
        for match in matches:
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=10,
                priority=ofproto.OFP_DEFAULT_PRIORITY,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=[])
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
            if (port_no == self.portHost1):
                self.logger.info('Host #1 traffic statistics - %s', self.stats)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_status_reply_handler(self, ev):
        body = ev.msg.body
        self.stats = []
        
        for stat in body:
            self.stats.append('port_no = %d , Tx_packets = %d , Rx_packets = %d' % (stat.port_no, stat.rx_packets, stat.tx_packets))
        
        # send port status request per second
        time.sleep(1)
        self._port_status_request(ev.msg.datapath)
    

    # send port request
    def _port_status_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, self.portHost1)
        datapath.send_msg(req) 

""" 
    # topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

# add LLDP database
class lldp(object):
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        pkt = packet.Packet()
        
        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)
"""