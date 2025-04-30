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
Result SslContextImpl::CreateConnection(
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out) {

    Service out_tmp;
    R_TRY(sslContextCreateConnection_sfMitm(m_forward_service.get(),
                                                   std::addressof(out_tmp)));

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
        Result res;
        if (R_FAILED(res = impl.SetOptionReal(true, ams::ssl::sf::OptionType::SkipDefaultVerify))) {
            AMS_LOG("Failed to set SkipDefaultVerify! %d-%d\n", res.GetModule()+2000, res.GetValue());
        }
        if (R_FAILED(res = impl.SetVerifyOptionReal(static_cast<ams::ssl::sf::VerifyOption>(0)))) {
            AMS_LOG("Failed to SetVerifyOptionReal(0)! %d-%d\n", res.GetModule()+2000, res.GetValue());
        }
    }

    out.SetValue(outValue, target_object_id);

    R_SUCCEED();
}

// shim

Result SslContextImpl::SetOption(const ams::ssl::sf::OptionType &option,
                                 u32 value) {
    R_TRY(sslContextSetOption_sfMitm(m_forward_service.get(),
                                            static_cast<u32>(option), value));

    R_SUCCEED();
}

Result SslContextImpl::GetOption(const ams::ssl::sf::OptionType &option,
                                 ams::sf::Out<u32> value) {
    R_TRY(sslContextGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(option), value.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::GetConnectionCount(ams::sf::Out<u32> count) {
    R_TRY(sslContextGetConnectionCount_sfMitm(m_forward_service.get(),
                                              count.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::ImportServerPki(
    const ams::ssl::sf::CertificateFormat &certificateFormat,
    const ams::sf::InBuffer &certificate, ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextImportServerPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(certificateFormat),
        certificate.GetPointer(), certificate.GetSize(),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::ImportClientPki(const ams::sf::InBuffer &certificate,
                                       const ams::sf::InBuffer &ascii_password,
                                       ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextImportClientPki_sfMitm(
        m_forward_service.get(), certificate.GetPointer(),
        certificate.GetSize(), ascii_password.GetPointer(),
        ascii_password.GetSize(), certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::RemoveServerPki(u64 certificate_id) {
    R_TRY(sslContextRemoveServerPki_sfMitm(m_forward_service.get(),
                                                  certificate_id));

    R_SUCCEED();
}

Result SslContextImpl::RemoveClientPki(u64 certificate_id) {
    R_TRY(sslContextRemoveClientPki_sfMitm(m_forward_service.get(),
                                                  certificate_id));

    R_SUCCEED();
}

Result SslContextImpl::RegisterInternalPki(const ams::ssl::sf::InternalPki &pki,
                                           ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextRegisterInternalPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(pki),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result
SslContextImpl::AddPolicyOid(const ams::sf::InBuffer &cert_policy_checking) {
    R_TRY(sslContextAddPolicyOid_sfMitm(
        m_forward_service.get(), cert_policy_checking.GetPointer(),
        cert_policy_checking.GetSize()));

    R_SUCCEED();
}

Result SslContextImpl::ImportCrl(const ams::sf::InBuffer &crl,
                                 ams::sf::Out<u64> crl_id) {
    R_TRY(sslContextImportCrl_sfMitm(m_forward_service.get(), crl.GetPointer(),
                                     crl.GetSize(), crl_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::RemoveCrl(u64 crl_id) {
    R_TRY(sslContextRemoveCrl_sfMitm(m_forward_service.get(), crl_id));

    R_SUCCEED();
}

Result SslContextImpl::ImportClientCertKeyPki(const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key,
                       const ams::ssl::sf::CertificateFormat &certificateFormat, ams::sf::Out<u64> pki_id) {
    R_TRY(sslContextImportClientCertKeyPki_sfMitm(m_forward_service.get(),
        cert.GetPointer(), cert.GetSize(), key.GetPointer(), key.GetSize(), (u32)certificateFormat,
        pki_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextImpl::GeneratePrivateKeyAndCert(
    const ams::sf::OutBuffer &cert, const ams::sf::OutBuffer &key,
    const ams::sf::InBuffer &params, u32 always1, ams::sf::Out<u32> cert_size,
    ams::sf::Out<u32> key_size) {
    R_TRY(sslContextGeneratePrivateKeyAndCert_sfMitm(m_forward_service.get(),
        cert.GetPointer(), cert.GetSize(), key.GetPointer(), key.GetSize(), 
        always1, params.GetPointer(), cert_size.GetPointer(), key_size.GetPointer()));

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
