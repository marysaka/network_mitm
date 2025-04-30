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
#include "networkmitm_ssl_service_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslServiceImpl::CreateContext(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContext>> out) {

    Service out_tmp;
    R_TRY(sslCreateContext_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp)));

    const ams::sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslContext, SslContextImpl>(
            std::make_shared<::Service>(out_tmp), m_client_info,
            m_should_dump_traffic, m_link_type, m_should_disable_ssl_verification),
        target_object_id);

    R_SUCCEED();
}

Result SslServiceImpl::GetCertificates(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &certificates) {
    R_TRY(sslGetCertificates_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        certificates_count.GetPointer(), certificates.GetPointer(),
        certificates.GetSize()));

    if (m_ca_certificate_public_key_der.empty()) {
        R_SUCCEED();
    }

    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoCAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::NintendoCAG4 ||
            ids[i] == ams::ssl::sf::CaCertificateId::All) {
            should_inject = true;
            break;
        }
    }

    if (should_inject) {
        const auto certificates_count_value = certificates_count.GetValue();

        BuiltInCertificateInfo *infos =
            reinterpret_cast<BuiltInCertificateInfo *>(
                certificates.GetPointer());

        u64 target_offset =
            infos[certificates_count_value - 1].certificate_data_offset +
            infos[certificates_count_value - 1].certificate_data_size;

        memcpy(certificates.GetPointer() + target_offset,
               m_ca_certificate_public_key_der.data(),
               m_ca_certificate_public_key_der.size_bytes());

        bool found_target_ca = false;

        for (size_t i = 0; i < certificates_count_value; i++) {
            if (infos[i].id == ams::ssl::sf::CaCertificateId::NintendoCAG3 ||
                infos[i].id == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
                infos[i].id == ams::ssl::sf::CaCertificateId::NintendoCAG4) {
                infos[i].certificate_data_offset = target_offset;
                infos[i].certificate_data_size =
                    m_ca_certificate_public_key_der.size_bytes();

                found_target_ca = true;
            }
        }

        if (!found_target_ca) {
            AMS_LOG("GetCertificates injection failed?! couldn't find the "
                    "target CA in output!\n");
        }
    }

    R_SUCCEED();
}

Result SslServiceImpl::GetCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    R_TRY(sslGetCertificateBufSize_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        buffer_size.GetPointer()));

    if (m_ca_certificate_public_key_der.empty()) {
        R_SUCCEED();
    }

    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoCAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::NintendoCAG4 ||
            ids[i] == ams::ssl::sf::CaCertificateId::All) {
            should_inject = true;
            break;
        }
    }

    if (should_inject) {
        buffer_size.SetValue(buffer_size.GetValue() +
                             m_ca_certificate_public_key_der.size_bytes());
    }

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
