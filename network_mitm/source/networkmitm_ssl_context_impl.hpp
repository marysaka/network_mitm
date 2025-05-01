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
#include "networkmitm_ssl_types.hpp"
#include "networkmitm_ssl_connection_impl.hpp"

#define AMS_INTERFACE_ISSLCONTEXT_INFO(C, H) \
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
        AMS_SF_METHOD_INFO(C, H, 10, Result, ImportCrl, (const ams::sf::InBuffer &crl, ams::sf::Out<u64> crl_id), (crl, crl_id), hos::Version_3_0_0) \
        AMS_SF_METHOD_INFO(C, H, 11, Result, RemoveCrl, (u64 crl_id), (crl_id), hos::Version_3_0_0) \
        AMS_SF_METHOD_INFO(C, H, 12, Result, ImportClientCertKeyPki, (const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key, const ams::ssl::sf::CertificateFormat &certificateFormat, ams::sf::Out<u64> pki_id), (cert, key, certificateFormat, pki_id), hos::Version_16_0_0) \
        AMS_SF_METHOD_INFO(C, H, 13, Result, GeneratePrivateKeyAndCert, (const ams::sf::OutBuffer &cert, const ams::sf::OutBuffer &key, const ams::sf::InBuffer &params, u32 always1, ams::sf::Out<u32> cert_size, ams::sf::Out<u32> key_size), (cert, key, params, always1, cert_size, key_size), hos::Version_16_0_0)

AMS_SF_DEFINE_MITM_INTERFACE(ams::ssl::sf, ISslContext, AMS_INTERFACE_ISSLCONTEXT_INFO, 0x46DF8B0C)


namespace ams::ssl::sf::impl {
    class SslContextImpl {
        protected:
            std::shared_ptr<::Service> m_forward_service;
            sm::MitmProcessInfo m_client_info;
            bool m_should_dump_traffic;
            PcapLinkType m_link_type;
            bool m_should_disable_ssl_verification;
        public:
            SslContextImpl(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c, bool should_dump_traffic, PcapLinkType link_type, bool should_disable_ssl_verification) : m_forward_service(std::move(s)), m_client_info(c), m_should_dump_traffic(should_dump_traffic), m_link_type(link_type), m_should_disable_ssl_verification(should_disable_ssl_verification) { /* ... */ }

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
            Result ImportClientCertKeyPki(const ams::sf::InBuffer &cert, const ams::sf::InBuffer &key, const ams::ssl::sf::CertificateFormat &certificateFormat, ams::sf::Out<u64> pki_id);
            Result GeneratePrivateKeyAndCert(const ams::sf::OutBuffer &cert, const ams::sf::OutBuffer &key, const ams::sf::InBuffer &params, u32 always1, ams::sf::Out<u32> cert_size, ams::sf::Out<u32> key_size);
    };

    static_assert(ams::ssl::sf::IsISslContext<ams::ssl::sf::impl::SslContextImpl>);
}
