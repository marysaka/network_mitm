/*
 * Copyright (c) Mary Guillemard <mary@mary.zone>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "pcap_utils_packet.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace ams::ssl::mitm::pcap {
static struct in_addr GetInAddr(Ip4PeerInfo &peer) {
    struct in_addr *addr = reinterpret_cast<in_addr *>(peer.address.data);

    return *addr;
}

void CreateIp4Packet(IpPacket &packet, Ip4PeerInfo &dst, Ip4PeerInfo &src,
                     uint32_t sequence_number, uint32_t ack_number,
                     uint8_t th_flags, uint16_t data_size) {
    memset(&packet, 0, sizeof(IpPacket));

    packet.ip.ip_v = IPVERSION;
    packet.ip.ip_hl = sizeof(struct ip) >> 2;
    packet.ip.ip_tos = 0;
    packet.ip.ip_len = htons(sizeof(IpPacket) + data_size);
    packet.ip.ip_id = 0;
    packet.ip.ip_off = htons(IP_DF);
    packet.ip.ip_ttl = 64;
    packet.ip.ip_p = IPPROTO_TCP;
    packet.ip.ip_sum = 0;
    packet.ip.ip_dst = GetInAddr(dst);
    packet.ip.ip_src = GetInAddr(src);
    packet.tcp.th_dport = htons(dst.port);
    packet.tcp.th_sport = htons(src.port);
    packet.tcp.th_seq = htonl(sequence_number);
    packet.tcp.th_ack = htonl(ack_number);
    packet.tcp.th_off = (sizeof(IpPacket) - sizeof(struct ip)) >> 2;
    packet.tcp.th_flags = th_flags;
    packet.tcp.th_win = htons(UINT16_MAX);
}

void CreateEthernetPacket(EthernetPacket &packet, EthernetPeerInfo &dst,
                          EthernetPeerInfo &src, uint32_t sequence_number,
                          uint32_t ack_number, uint8_t th_flags,
                          uint16_t data_size) {
    std::memcpy(packet.ethernet.destination, dst.mac.data,
                sizeof(packet.ethernet.destination));
    std::memcpy(packet.ethernet.source, src.mac.data,
                sizeof(packet.ethernet.source));
    packet.ethernet.ether_type = htons(0x800);

    CreateIp4Packet(packet.ip, dst.ip, src.ip, sequence_number, ack_number,
                    th_flags, data_size);
}
} // namespace ams::ssl::mitm::pcap