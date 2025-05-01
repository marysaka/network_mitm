#pragma once
#include <stratosphere.hpp>
#include "networkmitm_ssl_types.hpp"
#include "networkmitm_ssl_connection_impl.hpp"

#define AMS_INTERFACE_ISSLCONTEXTFORSYSTEM_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, SetOption, (const ams::ssl::sf::OptionType &option, u32 value), (option, value)) \
    AMS_SF_METHOD_INFO(C, H, 1, Result, GetOption, (const ams::ssl::sf::OptionType &option, ams::sf::Out<u32> value), (option, value)) \
    AMS_SF_METHOD_INFO(C, H, 2, Result, CreateConnection, (ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out), (out)) \
    AMS_SF_METHOD_INFO(C, H, 3, Result, GetConnectionCount, (ams::sf::Out<u32> count), (count)) \
    AMS_SF_METHOD_INFO(C, H, 4, Result, ImportServerPki, (const ams::ssl::sf::CertificateFormat &certificateFormat, const ams::sf::InBuffer &certificate, ams::sf::Out<u64> certificate_id), (certificateFormat, certificate, certificate_id)) \
    AMS_SF_METHOD_INFO(C, H, 5, Result, ImportClientPki, (const ams::sf::InBuffer &certificate, const ams::sf::InBuffer &ascii_password, ams::sf::Out<u64> certificate_id), (certificate, ascii_password, certificate_id)) \
    AMS_SF_METHOD_INFO(C, H, 6, Result, RemoveServerPki, (u64 certificate_id), (certificate_id)) \
    AMS_SF_METHOD_INFO(C, H, 7, Result, RemoveClientPki, (u64 certificate_id), (certificate_id)) \
    AMS_SF_METHOD_INFO(C, H, 8, Result, RegisterInternalPki, (const ams::ssl::sf::InternalPki &pki, ams::sf::Out<u64> certificate_id), (pki, certificate_id)) \
    AMS_SF_METHOD_INFO(C, H, 9, Result, AddPolicyOid, (const ams::sf::InBuffer &cert_policy_checking), (cert_policy_checking)) \
    AMS_SF_METHOD_INFO(C, H, 10, Result, ImportCrl, (const ams::sf::InBuffer &crl, ams::sf::Out<u64> crl_id), (crl, crl_id)) \
    AMS_SF_METHOD_INFO(C, H, 11, Result, RemoveCrl, (u64 crl_id), (crl_id)) \
    AMS_SF_METHOD_INFO(C, H, 12, Result, ImportClientCertKeyPki, (const ams::ssl::sf::CertificateFormat &certificateFormat, const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key, ams::sf::Out<u64> certificate_id), (certificateFormat, cert, key, certificate_id), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 13, Result, GeneratePrivateKeyAndCert, (u32 val, const ams::sf::InBuffer &params, const ams::sf::OutBuffer &cert, const ams::sf::OutBuffer &key, ams::sf::Out<u32> out_cert_size, ams::sf::Out<u32> out_key_size), (val, params, cert, key, out_cert_size, out_key_size), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 100, Result, CreateConnectionEx, (ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out), (out))

AMS_SF_DEFINE_INTERFACE(ams::ssl::sf, ISslContextForSystem, AMS_INTERFACE_ISSLCONTEXTFORSYSTEM_INFO, 0x153C59F4)


namespace ams::ssl::sf::impl {
    class SslContextForSystemImpl {
        protected:
            std::shared_ptr<::Service> m_forward_service;
            sm::MitmProcessInfo m_client_info;
            bool m_should_dump_traffic;
            PcapLinkType m_link_type;
        public:
            SslContextForSystemImpl(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c, bool should_dump_traffic, PcapLinkType link_type) : m_forward_service(std::move(s)), m_client_info(c), m_should_dump_traffic(should_dump_traffic), m_link_type(link_type) { /* ... */ }

            Result SetOption(const ams::ssl::sf::OptionType &option, u32 value);
            Result GetOption(const ams::ssl::sf::OptionType &option, ams::sf::Out<u32> value);
            Result CreateConnection(ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out);
            Result GetConnectionCount(ams::sf::Out<u32> count);
            Result ImportServerPki(const ams::ssl::sf::CertificateFormat &certificateFormat, const ams::sf::InBuffer &certificate, ams::sf::Out<u64> certificate_id);
            Result ImportClientPki(const ams::sf::InBuffer &certificate, const ams::sf::InBuffer &ascii_password, ams::sf::Out<u64> certificate_id);
            Result RemoveServerPki(u64 certificate_id);
            Result RemoveClientPki(u64 certificate_id);
            Result RegisterInternalPki(const ams::ssl::sf::InternalPki &pki, ams::sf::Out<u64> certificate_id);
            Result AddPolicyOid(const ams::sf::InBuffer &cert_policy_checking);
            Result ImportCrl(const ams::sf::InBuffer &crl, ams::sf::Out<u64> crl_id);
            Result RemoveCrl(u64 crl_id);
            Result ImportClientCertKeyPki(const ams::ssl::sf::CertificateFormat &certificateFormat, const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key, ams::sf::Out<u64> certificate_id);
            Result GeneratePrivateKeyAndCert(u32 val, const ams::sf::InBuffer &params, const ams::sf::OutBuffer &cert, const ams::sf::OutBuffer &key, ams::sf::Out<u32> out_cert_size, ams::sf::Out<u32> out_key_size);
            Result CreateConnectionEx(ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslConnection>> out);
    };

    static_assert(ams::ssl::sf::IsISslContextForSystem<ams::ssl::sf::impl::SslContextForSystemImpl>);
}
