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
#include "networkmitm_ssl_connection_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result SslConnectionImpl::SetVerifyOption(const ams::ssl::sf::VerifyOption &option) {
    if (m_should_disable_ssl_verification) {
        m_requested_option = option;
        R_SUCCEED();
    }
    
    return SetVerifyOptionReal(option);
}

Result SslConnectionImpl::SetVerifyOptionReal(const ams::ssl::sf::VerifyOption &option) {
    return sslConnectionSetVerifyOption_sfMitm(m_forward_service.get(),
                                              static_cast<u32>(option));
}

Result SslConnectionImpl::GetVerifyOption(
    ams::sf::Out<ams::ssl::sf::VerifyOption> option) {
    ams::ssl::sf::VerifyOption returned_value;
    R_TRY(sslConnectionGetVerifyOption_sfMitm(m_forward_service.get(),
                                              (u32*)&returned_value));

    option.SetValue(m_should_disable_ssl_verification 
                    ? m_requested_option : returned_value);
    
    R_SUCCEED();
}

Result SslConnectionImpl::Read(ams::sf::Out<u32> read_count,
                               const ams::sf::OutBuffer &buffer) {
    R_TRY(sslConnectionRead_sfMitm(
        m_forward_service.get(), read_count.GetPointer(), buffer.GetPointer(),
        buffer.GetSize()));

    if (m_writer != nullptr) {
        m_writer->Write(PcapDirection::Input, buffer.GetPointer(),
                         read_count.GetValue());
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Write(const ams::sf::InBuffer &buffer,
                                ams::sf::Out<u32> write_count) {
    R_TRY(sslConnectionWrite_sfMitm(m_forward_service.get(), buffer.GetPointer(),
                                    buffer.GetSize(), write_count.GetPointer()));

    if (m_writer != nullptr) {
        m_writer->Write(PcapDirection::Output, buffer.GetPointer(),
                         write_count.GetValue());
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetOption(bool value,
                                    const ams::ssl::sf::OptionType &option) {
    if (m_should_disable_ssl_verification && 
        option == ams::ssl::sf::OptionType::SkipDefaultVerify)
    {
        m_requested_default_verify = value;
        value = true; // force SkipDefaultVerify on, even when requested disabled
    }

    return SetOptionReal(value, option);
}

Result SslConnectionImpl::SetOptionReal(bool value,
    const ams::ssl::sf::OptionType &option) {
    return sslConnectionSetOption_sfMitm(m_forward_service.get(), value,
                                        static_cast<u32>(option));
}

Result SslConnectionImpl::GetOption(const ams::ssl::sf::OptionType &value,
                                    ams::sf::Out<bool> option) {
    bool returned_value;
    R_TRY(sslConnectionGetOption_sfMitm(m_forward_service.get(),
                        static_cast<u32>(value), &returned_value));

    if (m_should_disable_ssl_verification
         && value == ams::ssl::sf::OptionType::SkipDefaultVerify) {
        option.SetValue(m_requested_default_verify);
    }
    else {
        option.SetValue(returned_value);
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetPrivateOption(bool value,
                                    const ams::ssl::sf::OptionType &option) {
    if (m_should_disable_ssl_verification &&
         option == ams::ssl::sf::OptionType::SkipDefaultVerify)
    {
        m_requested_default_verify = value;
        value = true; // force SkipDefaultVerify on, even when requested disabled
    }

    return SetPrivateOptionReal(value, option);
}

Result SslConnectionImpl::SetPrivateOptionReal(bool value,
    const ams::ssl::sf::OptionType &option) {
    return sslConnectionSetPrivateOption_sfMitm(m_forward_service.get(), value,
                                                     static_cast<u32>(option));
}

// shim

Result SslConnectionImpl::SetSocketDescriptor(u32 input_socket_fd,
                                       ams::sf::Out<u32> output_socket_fd) {
    return sslConnectionSetSocketDescriptor_sfMitm(
        m_forward_service.get(), input_socket_fd,
        output_socket_fd.GetPointer());
}

Result SslConnectionImpl::SetHostName(const ams::sf::InBuffer &hostname) {
    return sslConnectionSetHostName_sfMitm(
        m_forward_service.get(), hostname.GetPointer(), hostname.GetSize());
}

Result SslConnectionImpl::SetIoMode(const ams::ssl::sf::IoMode &mode) {
    return sslConnectionSetIoMode_sfMitm(m_forward_service.get(),
                                               static_cast<u32>(mode));
}

Result SslConnectionImpl::GetSocketDescriptor(ams::sf::Out<u32> socket_fd) {
    return sslConnectionGetSocketDescriptor_sfMitm(
        m_forward_service.get(), socket_fd.GetPointer());
}

Result SslConnectionImpl::GetHostName(ams::sf::Out<u32> hostname_length,
                                      const ams::sf::OutBuffer &hostname) {
    return sslConnectionGetHostName_sfMitm(
        m_forward_service.get(), hostname_length.GetPointer(),
        hostname.GetPointer(), hostname.GetSize());
}

Result SslConnectionImpl::GetIoMode(ams::sf::Out<ams::ssl::sf::IoMode> mode) {
    return sslConnectionGetIoMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer()));
}

Result SslConnectionImpl::DoHandshake() {
    return sslConnectionDoHandshake_sfMitm(m_forward_service.get());
}

Result SslConnectionImpl::DoHandshakeGetServerCert(
    ams::sf::Out<u32> buffer_size, ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &server_cert_buffer) {
    return sslConnectionDoHandshakeGetServerCert_sfMitm(
        m_forward_service.get(), buffer_size.GetPointer(),
        certificates_count.GetPointer(), server_cert_buffer.GetPointer(),
        server_cert_buffer.GetSize());
}

Result SslConnectionImpl::Pending(ams::sf::Out<u32> pending_count) {
    return sslConnectionPending_sfMitm(m_forward_service.get(),
                                             pending_count.GetPointer());
}

Result SslConnectionImpl::Peek(ams::sf::Out<u32> peek_count,
                               const ams::sf::OutBuffer &buffer) {
    return sslConnectionPeek_sfMitm(
        m_forward_service.get(), peek_count.GetPointer(), buffer.GetPointer(),
        buffer.GetSize());
}

Result
SslConnectionImpl::Poll(const ams::ssl::sf::PollEvent &poll_event, u32 timeout,
                        ams::sf::Out<ams::ssl::sf::PollEvent> out_poll_event) {
    return sslConnectionPoll_sfMitm(
        m_forward_service.get(), static_cast<u32>(poll_event), timeout,
        reinterpret_cast<u32 *>(out_poll_event.GetPointer()));
}

Result SslConnectionImpl::GetVerifyCertError() {
    return sslConnectionGetVerifyCertError_sfMitm(m_forward_service.get());
}

Result SslConnectionImpl::GetNeededServerCertBufferSize(
    ams::sf::Out<u32> needed_buffer_size) {
    return sslConnectionGetNeededServerCertBufferSize_sfMitm(
        m_forward_service.get(), needed_buffer_size.GetPointer());
}

Result SslConnectionImpl::SetSessionCacheMode(
    const ams::ssl::sf::SessionCacheMode &mode) {
    return sslConnectionSetSessionCacheMode_sfMitm(
        m_forward_service.get(), static_cast<u32>(mode));
}

Result SslConnectionImpl::GetSessionCacheMode(
    ams::sf::Out<ams::ssl::sf::SessionCacheMode> mode) {
    return sslConnectionGetSessionCacheMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer()));
}

Result SslConnectionImpl::FlushSessionCache() {
    return sslConnectionFlushSessionCache_sfMitm(m_forward_service.get());
}

Result SslConnectionImpl::SetRenegotiationMode(
    const ams::ssl::sf::RenegotiationMode &mode) {
    return sslConnectionSetRenegotiationMode_sfMitm(
        m_forward_service.get(), static_cast<u32>(mode));
}

Result SslConnectionImpl::GetRenegotiationMode(
    ams::sf::Out<ams::ssl::sf::RenegotiationMode> mode) {
    return sslConnectionGetRenegotiationMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer()));
}

Result SslConnectionImpl::GetVerifyCertErrors(ams::sf::Out<u32> unk0,
                                              ams::sf::Out<u32> unk1,
                                              const ams::sf::OutBuffer &unk2) {
    return sslConnectionGetVerifyCertErrors_sfMitm(
        m_forward_service.get(), unk0.GetPointer(), unk1.GetPointer(),
        unk2.GetPointer(), unk2.GetSize());
}

Result SslConnectionImpl::GetCipherInfo(u32 unk0,
                                        const ams::sf::OutBuffer &cipher_info) {
    return sslConnectionGetCipherInfo_sfMitm(
        m_forward_service.get(), unk0, cipher_info.GetPointer(),
        cipher_info.GetSize());
}

Result
SslConnectionImpl::SetNextAlpnProto(const ams::sf::InBuffer &alpn_proto) {
    return sslConnectionSetNextAlpnProto_sfMitm(
        m_forward_service.get(), alpn_proto.GetPointer(), alpn_proto.GetSize());
}

Result SslConnectionImpl::GetNextAlpnProto(
    ams::sf::Out<ams::ssl::sf::AlpnProtoState> state,
    ams::sf::Out<u32> alpn_proto_out_size,
    const ams::sf::OutBuffer &alpn_proto) {
    return sslConnectionGetNextAlpnProto_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(state.GetPointer()),
        alpn_proto_out_size.GetPointer(), alpn_proto.GetPointer(),
        alpn_proto.GetSize());
}

Result
SslConnectionImpl::SetDtlsSocketDescriptor(s32 sock_fd,
                const ams::sf::InBuffer &sock_addr, ams::sf::Out<s32> out_sock_fd) {
    return sslConnectionSetDtlsSocketDescriptor_sfMitm(
        m_forward_service.get(), sock_fd, sock_addr.GetPointer(), sock_addr.GetSize(),
        out_sock_fd.GetPointer());
}

Result
SslConnectionImpl::GetDtlsHandshakeTimeout(const ams::sf::OutBuffer &timespan) {
    return sslConnectionGetDtlsHandshakeTimeout_sfMitm(m_forward_service.get(),
        timespan.GetPointer());
}

Result SslConnectionImpl::SetSrtpCiphers(const ams::sf::InBuffer &ciphers) {
    return sslConnectionSetSrtpCiphers_sfMitm(m_forward_service.get(),
        ciphers.GetPointer(), ciphers.GetSize());
}

Result SslConnectionImpl::GetSrtpCipher(ams::sf::Out<u16> cipher) {
    return sslConnectionGetSrtpCipher_sfMitm(m_forward_service.get(),
        cipher.GetPointer());
}

Result
SslConnectionImpl::ExportKeyingMaterial(const ams::sf::OutBuffer &material,
                                        const ams::sf::InBuffer &label,
                                        const ams::sf::InBuffer &context) {
    return sslConnectionExportKeyingMaterial_sfMitm(m_forward_service.get(),
        material.GetPointer(), material.GetSize(), label.GetPointer(),
        label.GetSize(), context.GetPointer(), context.GetSize());
}

Result SslConnectionImpl::SetIoTimeout(u32 timeout) { 
    return sslConnectionSetIoTimeout_sfMitm(m_forward_service.get(),
        timeout);
}

Result SslConnectionImpl::GetIoTimeout(ams::sf::Out<u32> timeout) {
    return sslConnectionGetIoTimeout_sfMitm(m_forward_service.get(),
        timeout.GetPointer());
}

} // namespace ams::ssl::sf::impl
