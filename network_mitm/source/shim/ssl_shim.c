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
#include "ssl_shim.h"
#include <stratosphere/sf/sf_mitm_dispatch.h>

Result sslCreateContext_sfMitm(Service *s, u32 version, u64 pid_placeholder,
                               u64 client_pid, Service *out) {
    const struct {
        u32 version;
        u64 pid_placeholder;
    } in = {version, pid_placeholder};

    return serviceMitmDispatchIn(s, 0, in, .in_send_pid = true,
                                 .override_pid = client_pid,
                                 .out_num_objects = 1, .out_objects = out);
}

Result sslGetContextCount_sfMitm(Service *s, u32 *count) {
    return serviceMitmDispatchOut(s, 1, *count);
}

Result sslGetCertificates_sfMitm(Service *s, const u32 *ids, size_t ids_size,
                                 u32 *certificates_count, void *certificates,
                                 size_t certificates_size) {
    return serviceMitmDispatchOut(
        s, 2, *certificates_count,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias,
                         SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{ids, ids_size * sizeof(u32)},
                    {certificates, certificates_size}});
}

Result sslGetCertificateBufSize_sfMitm(Service *s, const u32 *ids,
                                       size_t ids_size, u32 *buffer_size) {
    return serviceMitmDispatchOut(
        s, 3, *buffer_size,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{ids, ids_size * sizeof(u32)}});
}

Result sslDebugIoctl_sfMitm(Service *s) { return serviceMitmDispatch(s, 4); }

Result sslSetInterfaceVersion_sfMitm(Service *s, u32 version) {
    return serviceMitmDispatchIn(s, 5, version);
}

Result sslFlushSessionCache_sfMitm(Service *s, u32 option, const void *value,
                                   size_t value_size) {
    return serviceMitmDispatchIn(
        s, 6, option,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{value, value_size}});
}

Result sslSetDebugOption_sfMitm(Service *s, u32 option, const void *value,
                                size_t value_size) {
    return serviceMitmDispatchIn(
        s, 7, option,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{value, value_size}});
}

Result sslGetDebugOption_sfMitm(Service *s, u32 option, void *value,
                                size_t value_size) {
    return serviceMitmDispatchIn(
        s, 8, option,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{value, value_size}});
}

Result sslClearTls12FallbackFlag_sfMitm(Service *s) {
    return serviceMitmDispatch(s, 9);
}

Result sslContextSetOption_sfMitm(Service *s, u32 option, u32 value) {
    const struct {
        u32 option;
        u32 value;
    } in = {option, value};

    return serviceMitmDispatchIn(s, 0, in);
}

Result sslContextGetOption_sfMitm(Service *s, u32 option, u32 *value) {
    return serviceMitmDispatchInOut(s, 1, option, *value);
}

Result sslContextCreateConnection_sfMitm(Service *s, Service *out) {
    return serviceMitmDispatch(s, 2, .out_num_objects = 1, .out_objects = out);
}

Result sslContextGetConnectionCount_sfMitm(Service *s, u32 *count) {
    return serviceMitmDispatchOut(s, 3, *count);
}

Result sslContextImportServerPki_sfMitm(Service *s, u32 certificateFormat,
                                        const void *certificate,
                                        size_t certificate_size,
                                        u64 *certificate_id) {
    return serviceMitmDispatchInOut(
        s, 4, certificateFormat, *certificate_id,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{certificate, certificate_size}});
}

Result sslContextImportClientPki_sfMitm(Service *s, const void *certificate,
                                        size_t certificate_size,
                                        const void *ascii_password,
                                        size_t ascii_password_size,
                                        u64 *certificate_id) {
    return serviceMitmDispatchOut(
        s, 5, *certificate_id,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias,
                         SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{certificate, certificate_size},
                    {ascii_password, ascii_password_size}});
}

Result sslContextRemoveServerPki_sfMitm(Service *s, u64 certificate_id) {
    return serviceMitmDispatchIn(s, 6, certificate_id);
}

Result sslContextRemoveClientPki_sfMitm(Service *s, u64 certificate_id) {
    return serviceMitmDispatchIn(s, 7, certificate_id);
}

Result sslContextRegisterInternalPki_sfMitm(Service *s, u32 pki,
                                            u64 *certificate_id) {
    return serviceMitmDispatchInOut(s, 8, pki, *certificate_id);
}

Result sslContextAddPolicyOid_sfMitm(Service *s,
                                     const void *cert_policy_checking,
                                     size_t cert_policy_checking_size) {
    return serviceMitmDispatch(
        s, 9, .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{cert_policy_checking, cert_policy_checking_size}});
}

Result sslContextImportCrl_sfMitm(Service *s, const void *crl, size_t crl_size,
                                  u64 *crl_id) {
    return serviceMitmDispatchOut(
        s, 10, *crl_id,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{crl, crl_size}});
}

Result sslContextRemoveCrl_sfMitm(Service *s, u64 crl_id) {
    return serviceMitmDispatchIn(s, 11, crl_id);
}

Result sslConnectionSetSocketDescriptor_sfMitm(Service *s, u32 input_socket_fd,
                                               u32 *output_socket_fd) {
    return serviceMitmDispatchInOut(s, 0, input_socket_fd, *output_socket_fd);
}

Result sslConnectionSetHostName_sfMitm(Service *s, const void *hostname,
                                       size_t hostname_size) {
    return serviceMitmDispatch(
        s, 1, .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{hostname, hostname_size}});
}

Result sslConnectionSetVerifyOption_sfMitm(Service *s, u32 option) {
    return serviceMitmDispatchIn(s, 2, option);
}

Result sslConnectionSetIoMode_sfMitm(Service *s, u32 mode) {
    return serviceMitmDispatchIn(s, 3, mode);
}

Result sslConnectionGetSocketDescriptor_sfMitm(Service *s, u32 *socket_fd) {
    return serviceMitmDispatchOut(s, 4, *socket_fd);
}

Result sslConnectionGetHostName_sfMitm(Service *s, u32 *hostname_length,
                                       void *hostname, size_t hostname_size) {
    return serviceMitmDispatchOut(
        s, 5, *hostname_length,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{hostname, hostname_size}});
}

Result sslConnectionGetVerifyOption_sfMitm(Service *s, u32 *option) {
    return serviceMitmDispatchOut(s, 6, *option);
}

Result sslConnectionGetIoMode_sfMitm(Service *s, u32 *mode) {
    return serviceMitmDispatchOut(s, 7, *mode);
}

Result sslConnectionDoHandshake_sfMitm(Service *s) {
    return serviceMitmDispatch(s, 8);
}

Result sslConnectionDoHandshakeGetServerCert_sfMitm(
    Service *s, u32 *buffer_size, u32 *certificates_count,
    void *server_cert_buffer, size_t server_cert_buffer_size) {
    struct {
        u32 buffer_size;
        u32 certificates_count;
    } out;

    Result rc = serviceMitmDispatchOut(
        s, 9, out,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{server_cert_buffer, server_cert_buffer_size}});

    if (R_SUCCEEDED(rc)) {
        if (buffer_size)
            *buffer_size = out.buffer_size;
        if (certificates_count)
            *certificates_count = out.certificates_count;
    }

    return rc;
}

Result sslConnectionRead_sfMitm(Service *s, u32 *read_count, void *buffer,
                                size_t buffer_size) {
    return serviceMitmDispatchOut(
        s, 10, *read_count,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{buffer, buffer_size}});
}

Result sslConnectionWrite_sfMitm(Service *s, const void *buffer,
                                 size_t buffer_size, u32 *write_count) {
    return serviceMitmDispatchOut(
        s, 11, *write_count,
        .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{buffer, buffer_size}});
}

Result sslConnectionPending_sfMitm(Service *s, u32 *pending_count) {
    return serviceMitmDispatchOut(s, 12, *pending_count);
}

Result sslConnectionPeek_sfMitm(Service *s, u32 *peek_count, void *buffer,
                                size_t buffer_size) {
    return serviceMitmDispatchOut(
        s, 13, *peek_count,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{buffer, buffer_size}});
}

Result sslConnectionPoll_sfMitm(Service *s, u32 poll_event, u32 timeout,
                                u32 *out_poll_event) {
    const struct {
        u32 poll_event;
        u32 timeout;
    } in = {poll_event, timeout};

    return serviceMitmDispatchInOut(s, 14, in, *out_poll_event);
}

Result sslConnectionGetVerifyCertError_sfMitm(Service *s) {
    return serviceMitmDispatch(s, 15);
}

Result
sslConnectionGetNeededServerCertBufferSize_sfMitm(Service *s,
                                                  u32 *needed_buffer_size) {
    return serviceMitmDispatchOut(s, 16, *needed_buffer_size);
}

Result sslConnectionSetSessionCacheMode_sfMitm(Service *s, u32 mode) {
    return serviceMitmDispatchIn(s, 17, mode);
}

Result sslConnectionGetSessionCacheMode_sfMitm(Service *s, u32 *mode) {
    return serviceMitmDispatchOut(s, 18, *mode);
}

Result sslConnectionFlushSessionCache_sfMitm(Service *s) {
    return serviceMitmDispatch(s, 19);
}

Result sslConnectionSetRenegotiationMode_sfMitm(Service *s, u32 mode) {
    return serviceMitmDispatchIn(s, 20, mode);
}

Result sslConnectionGetRenegotiationMode_sfMitm(Service *s, u32 *mode) {
    return serviceMitmDispatchOut(s, 21, *mode);
}

Result sslConnectionSetOption_sfMitm(Service *s, bool value, u32 option) {
    const struct {
        bool value;
        u32 option;
    } in = {value, option};

    return serviceMitmDispatchIn(s, 22, in);
}

Result sslConnectionGetOption_sfMitm(Service *s, u32 value, bool *option) {
    return serviceMitmDispatchInOut(s, 23, value, *option);
}

Result sslConnectionGetVerifyCertErrors_sfMitm(Service *s, u32 *unk0, u32 *unk1,
                                               void *unk2, size_t unk2_size) {
    struct {
        u32 unk0;
        u32 unk1;
    } out;

    Result rc = serviceMitmDispatchOut(
        s, 24, out,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{unk2, unk2_size}});

    if (R_SUCCEEDED(rc)) {
        if (unk0)
            *unk0 = out.unk0;
        if (unk1)
            *unk1 = out.unk1;
    }

    return rc;
}

Result sslConnectionGetCipherInfo_sfMitm(Service *s, u32 unk0,
                                         void *cipher_info,
                                         size_t cipher_info_size) {
    return serviceMitmDispatchIn(
        s, 25, unk0,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{cipher_info, cipher_info_size}});
}

Result sslConnectionSetNextAlpnProto_sfMitm(Service *s, const void *alpn_proto,
                                            size_t alpn_proto_size) {
    return serviceMitmDispatch(
        s, 26, .buffer_attrs = {SfBufferAttr_In | SfBufferAttr_HipcMapAlias},
        .buffers = {{alpn_proto, alpn_proto_size}});
}

Result sslConnectionGetNextAlpnProto_sfMitm(Service *s, u32 *state,
                                            u32 *alpn_proto_out_size,
                                            void *alpn_proto,
                                            size_t alpn_proto_size) {
    struct {
        u32 state;
        u32 alpn_proto_out_size;
    } out;

    Result rc = serviceMitmDispatchOut(
        s, 27, out,
        .buffer_attrs = {SfBufferAttr_Out | SfBufferAttr_HipcMapAlias},
        .buffers = {{alpn_proto, alpn_proto_size}});

    if (R_SUCCEEDED(rc)) {
        if (state)
            *state = out.state;
        if (alpn_proto_out_size)
            *alpn_proto_out_size = out.alpn_proto_out_size;
    }

    return rc;
}
