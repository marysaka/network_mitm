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
#include "pcap_file_writer.hpp"
#include "pcap_utils.hpp"

#include <netinet/tcp.h>

namespace ams::ssl::mitm::pcap {
#define LINKTYPE_ETHERNET 1
#define LINKTYPE_RAW 101
#define LINKTYPE_USER0 147

const uint32_t TcpDumpMagic = 0xa1b2c3d4;
const uint16_t PcapVersionMajor = 2;
const uint16_t PcapVersionMinor = 4;
const uint32_t PcapMaxSnapLength = 0x40000;

struct PcapFileHeader {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t this_zone;
    uint32_t sig_figs;
    uint32_t snap_length;
    uint32_t link_type;

    PcapFileHeader(PcapLinkType link_type)
        : magic(TcpDumpMagic), version_major(PcapVersionMajor),
          version_minor(PcapVersionMinor), this_zone(0), sig_figs(0),
          snap_length(PcapMaxSnapLength),
          link_type(static_cast<uint32_t>(link_type)) {}
};

struct PcapPacketHeader {
    PcapTimeVal ts;
    uint32_t capture_length;
    uint32_t packet_length;

    PcapPacketHeader(PcapTimeVal ts, uint32_t capture_length,
                     uint32_t packet_length)
        : ts(ts), capture_length(capture_length), packet_length(packet_length) {
    }
};

static PcapTimeVal GetCurrentTimeForPcap() {
    return PcapTimeVal(os::GetSystemTick().ToTimeSpan());
}

PcapFileWriter::PcapFileWriter(fs::FileHandle file_handle,
                               PcapLinkType link_type,
                               EthernetPeerInfo dst_peer_info,
                               EthernetPeerInfo src_peer_info)
    : m_file_handle(file_handle), m_packet_lock(), m_link_type(link_type),
      m_file_position(0), m_last_direction(PcapDirection::Unspecified),
      m_last_packet_header_position(0), m_last_packet_header_size(0),
      m_dst_peer_info(dst_peer_info), m_src_peer_info(src_peer_info) {
    m_src_seq = 0x100000;
    m_dst_seq = 0x900000;

    const auto header = PcapFileHeader(m_link_type);
    WriteFile(&header, sizeof(header));
}

void PcapFileWriter::PerformWrite(const void *buffer, uint32_t buffer_size,
                                  bool should_use_new_packet_header) {
    PcapTimeVal timestamp = GetCurrentTimeForPcap();

    EthernetPeerInfo *src_peer_info;
    uint32_t *src_seq;
    EthernetPeerInfo *dst_peer_info;

    if (m_last_direction == PcapDirection::Input) {
        src_peer_info = &m_dst_peer_info;
        src_seq = &m_dst_seq;

        dst_peer_info = &m_src_peer_info;
    } else {
        src_peer_info = &m_src_peer_info;
        src_seq = &m_src_seq;

        dst_peer_info = &m_dst_peer_info;
    }

    uint64_t target_data_size = buffer_size;

    if (m_link_type == PcapLinkType::User) {
        should_use_new_packet_header = true;
    }

    if (!should_use_new_packet_header) {
        target_data_size += m_last_packet_header_size;
    } else {
        *src_seq += 1;
    }

    switch (m_link_type) {
    case PcapLinkType::Ethernet:
        EthernetPacket ethernet_packet;

        CreateEthernetPacket(ethernet_packet, *dst_peer_info, *src_peer_info,
                             *src_seq, 0, 0, target_data_size);
        WritePacket(&ethernet_packet, sizeof(ethernet_packet), buffer,
                    buffer_size, 0, timestamp, should_use_new_packet_header);

        break;

    case PcapLinkType::Ip:
        IpPacket ip_packet;

        CreateIp4Packet(ip_packet, dst_peer_info->ip, src_peer_info->ip,
                        *src_seq, 0, 0, target_data_size);
        WritePacket(&ip_packet, sizeof(ip_packet), buffer, buffer_size, 0,
                    timestamp, should_use_new_packet_header);
        break;

    case PcapLinkType::User:
    default:
        WritePacket(&m_last_direction, sizeof(m_last_direction), buffer,
                    buffer_size, 0, timestamp, should_use_new_packet_header);
        break;
    }
}

void PcapFileWriter::Write(PcapDirection direction, const void *buffer,
                           uint32_t buffer_size) {
    std::scoped_lock lk(m_packet_lock);

    const bool should_use_new_packet_header =
        m_last_direction == PcapDirection::Unspecified ||
        m_last_direction != direction;

    m_last_direction = direction;

    PerformWrite(buffer, buffer_size, should_use_new_packet_header);
}

void PcapFileWriter::WriteFileAtPosition(uint64_t position, const void *buffer,
                                         size_t buffer_size) {
    R_ABORT_UNLESS(fs::WriteFile(m_file_handle, position, buffer, buffer_size,
                                 fs::WriteOption::None));
}

void PcapFileWriter::WriteFile(const void *buffer, size_t buffer_size) {
    WriteFileAtPosition(m_file_position, buffer, buffer_size);

    m_file_position += buffer_size;
}

void PcapFileWriter::WritePacket(const void *extra_header,
                                 uint32_t extra_header_size, const void *buffer,
                                 uint32_t buffer_size,
                                 uint32_t arbitrary_extra_size,
                                 const PcapTimeVal &timestamp,
                                 bool should_use_new_packet_header) {
    const uint32_t capture_length =
        buffer_size + extra_header_size + arbitrary_extra_size;
    auto packet_header =
        PcapPacketHeader(timestamp, capture_length, capture_length);

    if (should_use_new_packet_header) {
        m_last_packet_header_position = m_file_position;

        WriteFile(&packet_header, sizeof(packet_header));

        if (extra_header != nullptr && extra_header_size != 0) {
            WriteFile(extra_header, extra_header_size);
        }

        m_last_packet_header_size = 0;
    } else {
        R_ABORT_UNLESS(fs::ReadFile(m_file_handle,
                                    m_last_packet_header_position,
                                    &packet_header, sizeof(packet_header)));

        packet_header.ts = timestamp;
        packet_header.capture_length += buffer_size;
        packet_header.packet_length += buffer_size;

        WriteFileAtPosition(m_last_packet_header_position, &packet_header,
                            sizeof(packet_header));

        if (extra_header != nullptr && extra_header_size != 0) {
            WriteFileAtPosition(m_last_packet_header_position +
                                    sizeof(packet_header),
                                extra_header, extra_header_size);
        }
    }

    if (buffer != nullptr && buffer_size != 0) {
        WriteFile(buffer, buffer_size);
    }

    if (should_use_new_packet_header) {
        R_ABORT_UNLESS(fs::FlushFile(m_file_handle));
    }

    m_last_packet_header_size += buffer_size;
}

PcapFileWriter::~PcapFileWriter() {
    std::scoped_lock lk(m_packet_lock);

    fs::FlushFile(m_file_handle);
    fs::CloseFile(m_file_handle);
}
} // namespace ams::ssl::mitm::pcap
