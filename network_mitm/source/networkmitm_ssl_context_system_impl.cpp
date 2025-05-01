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
#include "networkmitm_ssl_context_system_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslContextForSystemImpl::CreateConnectionEx(
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out) {

    Service out_tmp;
    R_TRY(sslContextCreateConnectionEx_sfMitm(m_forward_service.get(),
                                                       std::addressof(out_tmp)))

    const ams::sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(out_tmp))};

    PcapFileWriter *writer = nullptr;

    if (m_should_dump_traffic) {
        Result pcap_setup = EnsureDirectory(m_client_info.program_id);

        if (R_SUCCEEDED(pcap_setup)) {
            char pcap_path[ams::fs::EntryNameLengthMax + 1];

            int retry_count = 0;
            const int max_retry_count = 5;

            while ((R_FAILED(pcap_setup) || retry_count == 0) &&
                    retry_count < max_retry_count) {

                GetNewFilePathForPcap(pcap_path, sizeof(pcap_path),
                                        m_client_info.program_id);

                pcap_setup = fs::CreateFile(pcap_path, 0);

                retry_count++;
            }

            fs::FileHandle file_handle;
            pcap_setup = fs::OpenFile(std::addressof(file_handle), pcap_path,
                                        fs::OpenMode_All);

            if (R_SUCCEEDED(pcap_setup)) {
                u8 mac_dst[6] = {0xfe, 0xff, 0x20, 0x00, 0x01, 0x00};
                u8 ip_dst[4] = {0x05, 0x05, 0x05, 0x05};
                uint16_t port_dst = 80;

                u8 mac_src[6] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
                u8 ip_src[4] = {0x03, 0x03, 0x03, 0x03};
                uint16_t port_src = 6969;

                EthernetPeerInfo dst(mac_dst, Ip4Adderss(ip_dst), port_dst);
                EthernetPeerInfo src(mac_src, Ip4Adderss(ip_src), port_src);

                writer =
                    new PcapFileWriter(file_handle, m_link_type, dst, src);
            }
        }

        if (R_FAILED(pcap_setup)) {
            AMS_LOG("PCAP file creation failed, capture will be disabled for "
                    "this session!\n");
        }
    }

    const auto outValue = ams::sf::CreateSharedObjectEmplaced<ISslConnection, SslConnectionImpl>(
        std::make_shared<::Service>(out_tmp), m_client_info, writer, m_should_disable_ssl_verification);

    if (m_should_disable_ssl_verification) {
        auto impl = outValue.GetImpl();
        if (R_FAILED(impl.SetOptionReal(true, ams::ssl::sf::OptionType::SkipDefaultVerify))) {
            AMS_LOG("Failed to set SkipDefaultVerify!\n");
        }
        if (R_FAILED(impl.SetVerifyOptionReal(static_cast<ams::ssl::sf::VerifyOption>(0)))) {
            AMS_LOG("Failed to SetVerifyOptionReal(0)!\n");
        }
    }

    out.SetValue(outValue, target_object_id);
    
    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
