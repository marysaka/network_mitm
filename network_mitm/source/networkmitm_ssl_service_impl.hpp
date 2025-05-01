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
#include <stratosphere.hpp>
#include "networkmitm_ssl_types.hpp"
#include "networkmitm_ssl_context_impl.hpp"
#include "networkmitm_cert_utils.hpp"

#define AMS_INTERFACE_ISSLSERVICE_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, CreateContext, (const ams::ssl::sf::SslVersion &version, const ams::sf::ClientProcessId &client_pid, ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out), (version, client_pid, out)) \
    AMS_SF_METHOD_INFO(C, H, 2, Result, GetCertificates, (const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &certificates), (ids, certificates_count, certificates)) \
    AMS_SF_METHOD_INFO(C, H, 3, Result, GetCertificateBufSize, (const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> buffer_size), (ids, buffer_size)) \

AMS_SF_DEFINE_MITM_INTERFACE(ams::ssl::sf, ISslService, AMS_INTERFACE_ISSLSERVICE_INFO, 0xE01918D)


namespace ams::ssl::sf::impl {
    enum class TrustedCertStatus : u32 {
        Removed,
        EnabledTrusted,
        EnabledNotTrusted,
        Revoked,
    };

    struct BuiltInCertificateInfo {
        ams::ssl::sf::CaCertificateId id;
        TrustedCertStatus status;
        uint64_t certificate_data_size;
        uint64_t certificate_data_offset;
    };

    class SslServiceImpl : ams::sf::MitmServiceImplBase {
        private:
            bool m_should_dump_traffic;
            PcapLinkType m_link_type;
            Span<uint8_t> m_ca_certificate_public_key_der;
        public:
            SslServiceImpl(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c, bool should_dump_traffic, PcapLinkType link_type, Span<uint8_t> ca_certificate_public_key_der) : MitmServiceImplBase(std::move(s), c), m_should_dump_traffic(should_dump_traffic), m_link_type(link_type), m_ca_certificate_public_key_der(ca_certificate_public_key_der) { /* ... */ }

            static bool ShouldMitmImpl(const ams::sm::MitmProcessInfo &client_info) {
                // TODO: Allow a user configureable list
                return (ncm::IsApplicationId(client_info.program_id)); //|| client_info.override_status.IsHbl());
            }

            static bool ShouldMitm(const ams::sm::MitmProcessInfo &client_info) {
                bool should_mitm = ShouldMitmImpl(client_info);

                // AMS_LOG("ShouldMitm pid: %lx tid: %lx (should_mitm: %d)\n", (u64)client_info.process_id, (u64)client_info.program_id, should_mitm);

                return should_mitm;
            }

            Result CreateContext(const ams::ssl::sf::SslVersion &version, const ams::sf::ClientProcessId &client_pid, ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out);
            Result GetCertificates(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &certificates);
            Result GetCertificateBufSize(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> buffer_size);
    };

    static_assert(ams::ssl::sf::IsISslService<ams::ssl::sf::impl::SslServiceImpl>);
}
