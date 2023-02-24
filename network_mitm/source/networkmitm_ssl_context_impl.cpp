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
#include "networkmitm_ssl_context_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslContextImpl::SetOption(const ams::ssl::sf::OptionType &option,
                                 u32 value) {
    Result res = sslContextSetOption_sfMitm(m_forward_service.get(),
                                            static_cast<u32>(option), value);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::GetOption(const ams::ssl::sf::OptionType &option,
                                 ams::sf::Out<u32> value) {
    Result res = sslContextGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(option), value.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::CreateConnection(
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out) {
    Service out_tmp;
    Result res = sslContextCreateConnection_sfMitm(m_forward_service.get(),
                                                   std::addressof(out_tmp));

    if (res.IsFailure()) {
        return res;
    }

    PcapFileWriter *writter = nullptr;

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

                writter =
                    new PcapFileWriter(file_handle, m_link_type, dst, src);
            }
        }

        if (R_FAILED(pcap_setup)) {
            AMS_LOG("PCAP file creation failed, capture will be disabled for "
                    "this session!");
        }
    }

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslConnection, SslConnectionImpl>(
            std::make_shared<::Service>(out_tmp), m_client_info, writter));

    R_SUCCEED();
}

Result SslContextImpl::GetConnectionCount(ams::sf::Out<u32> count) {
    Result res = sslContextGetConnectionCount_sfMitm(m_forward_service.get(),
                                                     count.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::ImportServerPki(
    const ams::ssl::sf::CertificateFormat &certificateFormat,
    const ams::sf::InBuffer &certificate, ams::sf::Out<u64> certificate_id) {
    Result res = sslContextImportServerPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(certificateFormat),
        certificate.GetPointer(), certificate.GetSize(),
        certificate_id.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::ImportClientPki(const ams::sf::InBuffer &certificate,
                                       const ams::sf::InBuffer &ascii_password,
                                       ams::sf::Out<u64> certificate_id) {
    Result res = sslContextImportClientPki_sfMitm(
        m_forward_service.get(), certificate.GetPointer(),
        certificate.GetSize(), ascii_password.GetPointer(),
        ascii_password.GetSize(), certificate_id.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::RemoveServerPki(u64 certificate_id) {
    Result res = sslContextRemoveServerPki_sfMitm(m_forward_service.get(),
                                                  certificate_id);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::RemoveClientPki(u64 certificate_id) {
    Result res = sslContextRemoveClientPki_sfMitm(m_forward_service.get(),
                                                  certificate_id);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::RegisterInternalPki(const ams::ssl::sf::InternalPki &pki,
                                           ams::sf::Out<u64> certificate_id) {
    Result res = sslContextRegisterInternalPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(pki),
        certificate_id.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslContextImpl::AddPolicyOid(const ams::sf::InBuffer &cert_policy_checking) {
    Result res = sslContextAddPolicyOid_sfMitm(
        m_forward_service.get(), cert_policy_checking.GetPointer(),
        cert_policy_checking.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::ImportCrl(const ams::sf::InBuffer &crl,
                                 ams::sf::Out<u64> crl_id) {
    Result res =
        sslContextImportCrl_sfMitm(m_forward_service.get(), crl.GetPointer(),
                                   crl.GetSize(), crl_id.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslContextImpl::RemoveCrl(u64 crl_id) {
    Result res = sslContextRemoveCrl_sfMitm(m_forward_service.get(), crl_id);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
