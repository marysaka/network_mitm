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
#pragma once
#include <cstdint>
#include <netinet/in.h>
#include "external/ip.h"
#include <netinet/tcp.h>

namespace ams::ssl::mitm::pcap {
    const int MaccAddrSize = 6;
    const int Ip4AddrSize = 4;
    const int EthernetHeaderSize = 14;
    const int IpHeaderSize = 20;
    const int TcpHeaderSize = 20;

    struct __attribute__ ((packed)) EthernetHeader {
        uint8_t destination[6];
        uint8_t source[6];
        uint16_t ether_type;
    };

    struct  __attribute__ ((packed)) IpPacket {
        struct ip ip;
        struct tcphdr tcp;
    };

    static_assert(sizeof(EthernetHeader) == EthernetHeaderSize);
    static_assert(sizeof(IpPacket) == IpHeaderSize + TcpHeaderSize);

    struct  __attribute__ ((packed)) EthernetPacket {
        EthernetHeader ethernet;
        IpPacket ip;
    };

    static_assert(sizeof(EthernetPacket) == EthernetHeaderSize + IpHeaderSize + TcpHeaderSize);

    struct MacAdderss {
        uint8_t data[MaccAddrSize];

        MacAdderss(uint8_t data[MaccAddrSize]): data(*data) { }
    };

    struct Ip4Adderss {
        uint8_t data[Ip4AddrSize];

        Ip4Adderss(uint8_t data[Ip4AddrSize]): data(*data) { }
    };

    struct Ip4PeerInfo {
        Ip4Adderss address;
        uint16_t port;

        Ip4PeerInfo(Ip4Adderss address, uint16_t port) : address(address), port(port) { }
    };

    struct EthernetPeerInfo {
        MacAdderss mac;
        Ip4PeerInfo ip;

        EthernetPeerInfo(MacAdderss mac, Ip4Adderss address, uint16_t port) : mac(mac), ip(address, port) { }
    };

    void CreateIp4Packet(IpPacket &packet, Ip4PeerInfo &dst, Ip4PeerInfo &src, uint32_t sequence_number, uint32_t ack_number, uint8_t th_flags, uint16_t data_size);
    void CreateEthernetPacket(EthernetPacket &packet, EthernetPeerInfo &dst, EthernetPeerInfo &src, uint32_t sequence_number, uint32_t ack_number, uint8_t th_flags, uint16_t data_size);
}
