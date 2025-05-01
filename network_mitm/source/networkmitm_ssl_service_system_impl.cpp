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
#include "networkmitm_ssl_service_system_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {

Result SslServiceForSystemImpl::CreateContextForSystem(
    const ams::ssl::sf::SslVersion &version,
    const ams::sf::ClientProcessId &client_pid,
    ams::sf::Out<ams::sf::SharedPointer<ams::ssl::sf::ISslContextForSystem>> out) {

    Service out_tmp;
    R_TRY(sslCreateContextForSystem_sfMitm(
        m_forward_service.get(), static_cast<u32>(version),
        static_cast<u64>(client_pid.GetValue()),
        static_cast<u64>(client_pid.GetValue()), std::addressof(out_tmp)));

    const ams::sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(out_tmp))};

    out.SetValue(
        ams::sf::CreateSharedObjectEmplaced<ISslContextForSystem, SslContextForSystemImpl>(
            std::make_shared<::Service>(out_tmp), m_client_info,
            m_should_dump_traffic, m_link_type, m_should_disable_ssl_verification),
        target_object_id);

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
