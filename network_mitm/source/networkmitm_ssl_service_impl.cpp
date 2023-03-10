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
    // If we aren't mitm the traffic, we don't want to control the sub objects
    // to reduce overhead.
    if (!m_should_dump_traffic) {
        return sm::mitm::ResultShouldForwardToSession();
    }

    Service out_tmp;
    Result res = sslCreateContext_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp));

    if (res.IsFailure()) {
        return res;
    }

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslContext, SslContextImpl>(
            std::make_shared<::Service>(out_tmp), m_client_info,
            m_should_dump_traffic, m_link_type));

    R_SUCCEED();
}

Result SslServiceImpl::GetContextCount(ams::sf::Out<u32> count) {
    Result res =
        sslGetContextCount_sfMitm(m_forward_service.get(), count.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslServiceImpl::GetCertificates(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &certificates) {
    Result res = sslGetCertificates_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        certificates_count.GetPointer(), certificates.GetPointer(),
        certificates.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
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
            if (infos[i].id ==
                ams::ssl::sf::CaCertificateId::NintendoClass2CAG3) {
                infos[i].certificate_data_offset = target_offset;
                infos[i].certificate_data_size =
                    m_ca_certificate_public_key_der.size_bytes();

                found_target_ca = true;
                break;
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
    Result res = sslGetCertificateBufSize_sfMitm(
        m_forward_service.get(),
        reinterpret_cast<const u32 *>(ids.GetPointer()), ids.GetSize(),
        buffer_size.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
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

Result SslServiceImpl::DebugIoctl() {
    Result res = sslDebugIoctl_sfMitm(m_forward_service.get());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslServiceImpl::SetInterfaceVersion(u32 version) {
    Result res =
        sslSetInterfaceVersion_sfMitm(m_forward_service.get(), version);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslServiceImpl::FlushSessionCache(
    const ams::ssl::sf::FlushSessionCacheOptionType &option,
    const ams::sf::InBuffer &value) {
    Result res = sslFlushSessionCache_sfMitm(
        m_forward_service.get(), static_cast<u32>(option), value.GetPointer(),
        value.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslServiceImpl::SetDebugOption(const ams::ssl::sf::DebugOptionType &option,
                               const ams::sf::InBuffer &value) {
    Result res = sslSetDebugOption_sfMitm(m_forward_service.get(),
                                          static_cast<u32>(option),
                                          value.GetPointer(), value.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslServiceImpl::GetDebugOption(const ams::ssl::sf::DebugOptionType &option,
                               const ams::sf::OutBuffer &value) {
    Result res = sslGetDebugOption_sfMitm(m_forward_service.get(),
                                          static_cast<u32>(option),
                                          value.GetPointer(), value.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslServiceImpl::ClearTls12FallbackFlag() {
    Result res = sslClearTls12FallbackFlag_sfMitm(m_forward_service.get());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
