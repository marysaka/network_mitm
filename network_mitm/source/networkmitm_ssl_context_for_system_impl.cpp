#include "networkmitm_ssl_context_for_system_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result
SslContextForSystemImpl::SetOption(const ams::ssl::sf::OptionType &option,
                                   u32 value) {
    R_TRY(sslContextForSystemSetOption_sfMitm(m_forward_service.get(),
                                              static_cast<u32>(option), value));

    R_SUCCEED();
}

Result
SslContextForSystemImpl::GetOption(const ams::ssl::sf::OptionType &option,
                                   ams::sf::Out<u32> value) {
    R_TRY(sslContextForSystemGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(option), value.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::CreateConnection(
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out) {
    Service out_tmp;
    R_TRY(sslContextForSystemCreateConnection_sfMitm(m_forward_service.get(),
                                                     std::addressof(out_tmp)));

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
                    "this session! (tid: %lx)\n", static_cast<u64>(m_client_info.program_id));
        }
    }

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslConnection, SslConnectionImpl>(
            std::make_shared<::Service>(out_tmp), m_client_info, writter),
        target_object_id);

    R_SUCCEED();
}

Result SslContextForSystemImpl::GetConnectionCount(ams::sf::Out<u32> count) {
    R_TRY(sslContextForSystemGetConnectionCount_sfMitm(m_forward_service.get(),
                                                       count.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::ImportServerPki(
    const ams::ssl::sf::CertificateFormat &certificateFormat,
    const ams::sf::InBuffer &certificate, ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextForSystemImportServerPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(certificateFormat),
        certificate.GetPointer(), certificate.GetSize(),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::ImportClientPki(
    const ams::sf::InBuffer &certificate,
    const ams::sf::InBuffer &ascii_password, ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextForSystemImportClientPki_sfMitm(
        m_forward_service.get(), certificate.GetPointer(),
        certificate.GetSize(), ascii_password.GetPointer(),
        ascii_password.GetSize(), certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::RemoveServerPki(u64 certificate_id) {
    R_TRY(sslContextForSystemRemoveServerPki_sfMitm(m_forward_service.get(),
                                                    certificate_id));

    R_SUCCEED();
}

Result SslContextForSystemImpl::RemoveClientPki(u64 certificate_id) {
    R_TRY(sslContextForSystemRemoveClientPki_sfMitm(m_forward_service.get(),
                                                    certificate_id));

    R_SUCCEED();
}

Result SslContextForSystemImpl::RegisterInternalPki(
    const ams::ssl::sf::InternalPki &pki, ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextForSystemRegisterInternalPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(pki),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::AddPolicyOid(
    const ams::sf::InBuffer &cert_policy_checking) {
    R_TRY(sslContextForSystemAddPolicyOid_sfMitm(
        m_forward_service.get(), cert_policy_checking.GetPointer(),
        cert_policy_checking.GetSize()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::ImportCrl(const ams::sf::InBuffer &crl,
                                          ams::sf::Out<u64> crl_id) {
    R_TRY(sslContextForSystemImportCrl_sfMitm(m_forward_service.get(),
                                              crl.GetPointer(), crl.GetSize(),
                                              crl_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::RemoveCrl(u64 crl_id) {
    R_TRY(sslContextForSystemRemoveCrl_sfMitm(m_forward_service.get(), crl_id));

    R_SUCCEED();
}

Result SslContextForSystemImpl::ImportClientCertKeyPki(
    const ams::ssl::sf::CertificateFormat &certificateFormat,
    const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key,
    ams::sf::Out<u64> certificate_id) {
    R_TRY(sslContextForSystemImportClientCertKeyPki_sfMitm(
        m_forward_service.get(), static_cast<u32>(certificateFormat),
        cert.GetPointer(), cert.GetSize(), key.GetPointer(), key.GetSize(),
        certificate_id.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::GeneratePrivateKeyAndCert(
    u32 val, const ams::sf::InBuffer &params, const ams::sf::OutBuffer &cert,
    const ams::sf::OutBuffer &key, ams::sf::Out<u32> out_cert_size,
    ams::sf::Out<u32> out_key_size) {
    R_TRY(sslContextForSystemGeneratePrivateKeyAndCert_sfMitm(
        m_forward_service.get(), val, params.GetPointer(), params.GetSize(),
        cert.GetPointer(), cert.GetSize(), key.GetPointer(), key.GetSize(),
        out_cert_size.GetPointer(), out_key_size.GetPointer()));

    R_SUCCEED();
}

Result SslContextForSystemImpl::CreateConnectionEx(
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out) {
    Service out_tmp;
    R_TRY(sslContextForSystemCreateConnectionEx_sfMitm(
        m_forward_service.get(), std::addressof(out_tmp)));

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
                    "this session! (tid: %lx)\n", static_cast<u64>(m_client_info.program_id));
        }
    }

    const ams::sf::cmif::DomainObjectId target_object_id{
        serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslConnection, SslConnectionImpl>(
            std::make_shared<::Service>(out_tmp), m_client_info, writter),
        target_object_id);

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl