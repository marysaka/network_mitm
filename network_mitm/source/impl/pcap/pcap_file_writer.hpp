/*
 * Copyright (c) Mary <mary@mary.zone>
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
#include <stratosphere.hpp>
#include "pcap_utils_packet.hpp"

namespace ams::ssl::mitm::pcap {
    enum class PcapLinkType : uint32_t {
        Ethernet = 1,
        User = 147,
        Ip = 101,
    };

    enum class PcapDirection {
        Unspecified,
        Input, // Client <- Server
        Output, // Client -> Server
    };

    struct PcapTimeVal {
        uint32_t tv_sec;
        uint32_t tv_usec;

        PcapTimeVal(uint32_t tv_sec, uint32_t tv_usec) : tv_sec(tv_sec), tv_usec(tv_usec) {}
        PcapTimeVal(TimeSpan timestamp) : PcapTimeVal(static_cast<u32>(timestamp.GetSeconds()), static_cast<u32>(timestamp.GetMicroSeconds())) {}
    };

    // TODO: Split this maybe in multiple for ethernet and ip control?
    class PcapFileWriter {
        private:
            fs::FileHandle m_file_handle;
            os::SdkMutex m_packet_lock;
            PcapLinkType m_link_type;
            uint64_t m_file_position;
            PcapDirection m_last_direction;
            uint64_t m_last_packet_header_position;
            uint64_t m_last_packet_header_size;

            EthernetPeerInfo m_dst_peer_info;
            EthernetPeerInfo m_src_peer_info;
            uint32_t m_dst_seq;
            uint32_t m_src_seq;

            void PerformWrite(const void *buffer, uint32_t buffer_size, bool should_use_new_packet_header);
            void WriteFileAtPosition(uint64_t position, const void *buffer, size_t buffer_size);
            void WriteFile(const void *buffer, size_t buffer_size);
            void WritePacket(const void *extra_header, uint32_t extra_header_size,
                             const void *buffer, uint32_t buffer_size,
                             uint32_t arbitrary_extra_size, const PcapTimeVal &timestamp,
                             bool should_use_new_packet_header);
        public:
            PcapFileWriter(fs::FileHandle file_handle, PcapLinkType link_type, EthernetPeerInfo dst_peer_info, EthernetPeerInfo src_peer_info);
            ~PcapFileWriter();

            void Write(PcapDirection direction, const void *buffer, uint32_t buffer_size);
    };
}
