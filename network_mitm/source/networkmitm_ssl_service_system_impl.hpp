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
#include "networkmitm_ssl_context_system_impl.hpp"
#include "networkmitm_ssl_service_impl.hpp"

#define AMS_INTERFACE_ISSLSERVICEFORSYSTEM_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, CreateContext, (const ams::ssl::sf::SslVersion &version, const ams::sf::ClientProcessId &client_pid, ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out), (version, client_pid, out)) \
    AMS_SF_METHOD_INFO(C, H, 2, Result, GetCertificates, (const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &certificates), (ids, certificates_count, certificates)) \
    AMS_SF_METHOD_INFO(C, H, 3, Result, GetCertificateBufSize, (const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> buffer_size), (ids, buffer_size)) \
    AMS_SF_METHOD_INFO(C, H, 100, Result, CreateContextForSystem, (const ams::ssl::sf::SslVersion &version, const ams::sf::ClientProcessId &client_pid, ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContextForSystem>> out), (version, client_pid, out)) \

AMS_SF_DEFINE_MITM_INTERFACE(ams::ssl::sf, ISslServiceForSystem, AMS_INTERFACE_ISSLSERVICEFORSYSTEM_INFO, 0x806C9E9C)


namespace ams::ssl::sf::impl {

    class SslServiceForSystemImpl : public SslServiceImpl {
        public:
            SslServiceForSystemImpl(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c, bool should_dump_traffic, PcapLinkType link_type, Span<uint8_t> ca_certificate_public_key_der, bool should_disable_ssl_verification) : SslServiceImpl(std::move(s), c, should_dump_traffic, link_type, ca_certificate_public_key_der, should_disable_ssl_verification) { /* ... */ }

            inline static bool ShouldMitm(__unused const ams::sm::MitmProcessInfo &client_info) {
                return true;
            }

            Result CreateContextForSystem(const ams::ssl::sf::SslVersion &version, const ams::sf::ClientProcessId &client_pid, ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContextForSystem>> out);
    };

    static_assert(ams::ssl::sf::IsISslServiceForSystem<ams::ssl::sf::impl::SslServiceForSystemImpl>);
}
