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
#include <switch/sf/service.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AlpnProtoState_NoSupport_sf = 0,
    AlpnProtoState_Negotiated_sf = 1,
    AlpnProtoState_NoOverlap_sf = 2,
    AlpnProtoState_Selected_sf = 3,
    AlpnProtoState_EarlyValue_sf = 4,
} AlpnProtoState_sf;

typedef enum {
    CaCertificateId_NintendoCAG3_sf = 1,
    CaCertificateId_NintendoClass2CAG3_sf = 2,
    CaCertificateId_AmazonRootCA1_sf = 1000,
    CaCertificateId_StarfieldServicesRootCertificateAuthorityG2_sf = 1001,
    CaCertificateId_AddTrustExternalCARoot_sf = 1002,
    CaCertificateId_COMODOCertificationAuthority_sf = 1003,
    CaCertificateId_UTNDATACorpSGC_sf = 1004,
    CaCertificateId_UTNUSERFirstHardware_sf = 1005,
    CaCertificateId_BaltimoreCyberTrustRoot_sf = 1006,
    CaCertificateId_CybertrustGlobalRoot_sf = 1007,
    CaCertificateId_VerizonGlobalRootCA_sf = 1008,
    CaCertificateId_DigiCertAssuredIDRootCA_sf = 1009,
    CaCertificateId_DigiCertAssuredIDRootG2_sf = 1010,
    CaCertificateId_DigiCertGlobalRootCA_sf = 1011,
    CaCertificateId_DigiCertGlobalRootG2_sf = 1012,
    CaCertificateId_DigiCertHighAssuranceEVRootCA_sf = 1013,
    CaCertificateId_EntrustnetCertificationAuthority2048_sf = 1014,
    CaCertificateId_EntrustRootCertificationAuthority_sf = 1015,
    CaCertificateId_EntrustRootCertificationAuthorityG2_sf = 1016,
    CaCertificateId_GeoTrustGlobalCA2_sf = 1017,
    CaCertificateId_GeoTrustGlobalCA_sf = 1018,
    CaCertificateId_GeoTrustPrimaryCertificationAuthorityG3_sf = 1019,
    CaCertificateId_GeoTrustPrimaryCertificationAuthority_sf = 1020,
    CaCertificateId_GlobalSignRootCA_sf = 1021,
    CaCertificateId_GlobalSignRootCAR2_sf = 1022,
    CaCertificateId_GlobalSignRootCAR3_sf = 1023,
    CaCertificateId_GoDaddyClass2CertificationAuthority_sf = 1024,
    CaCertificateId_GoDaddyRootCertificateAuthorityG2_sf = 1025,
    CaCertificateId_StarfieldClass2CertificationAuthority_sf = 1026,
    CaCertificateId_StarfieldRootCertificateAuthorityG2_sf = 1027,
    CaCertificateId_ThawtePrimaryRootCAG3_sf = 1028,
    CaCertificateId_ThawtePrimaryRootCA_sf = 1029,
    CaCertificateId_VeriSignClass3PublicPrimaryCertificationAuthorityG3_sf =
        1030,
    CaCertificateId_VeriSignClass3PublicPrimaryCertificationAuthorityG5_sf =
        1031,
    CaCertificateId_VeriSignUniversalRootCertificationAuthority_sf = 1032,
    CaCertificateId_DSTRootCAX3_sf = 1033,
    CaCertificateId_USERTrustRSACertificationAuthority_sf = 1034,
    CaCertificateId_ISRGRootX10_sf = 1035,
    CaCertificateId_USERTrustECCCertificationAuthority_sf = 1036,
    CaCertificateId_COMODORSACertificationAuthority_sf = 1037,
    CaCertificateId_COMODOECCCertificationAuthority_sf = 1038,
    CaCertificateId_AmazonRootCA2_sf = 1039,
    CaCertificateId_AmazonRootCA3_sf = 1040,
    CaCertificateId_AmazonRootCA4_sf = 1041,
    CaCertificateId_DigiCertAssuredIDRootG3_sf = 1042,
    CaCertificateId_DigiCertGlobalRootG3_sf = 1042,
    CaCertificateId_DigiCertTrustedRootG4_sf = 1043,
    CaCertificateId_EntrustRootCertificationAuthorityEC1_sf = 1044,
    CaCertificateId_EntrustRootCertificationAuthorityG4_sf = 1045,
    CaCertificateId_GlobalSignECCRootCAR4_sf = 1046,
    CaCertificateId_GlobalSignECCRootCAR5_sf = 1047,
    CaCertificateId_GlobalSignECCRootCAR6_sf = 1048,
    CaCertificateId_GTSRootR1_sf = 1049,
    CaCertificateId_GTSRootR2_sf = 1050,
    CaCertificateId_GTSRootR3_sf = 1051,
    CaCertificateId_GTSRootR4_sf = 1052,
    CaCertificateId_SecurityCommunicationRootCA_sf = 1053,
    CaCertificateId_DigiCertTLSECCP384RootG5 = 1054,
    CaCertificateId_DigiCertTLSRSA4096RootG5 = 1055,
    CaCertificateId_NintendoTempRootCAG4 = 65536,
    CaCertificateId_All_sf = 4294967295,
} CaCertificateId_sf;

typedef enum {
    CertificateFormat_Pem_sf = 1,
    CertificateFormat_Der_sf = 2,
} CertificateFormat_sf;

typedef enum {
    ContextOption_None_sf = 0,
    ContextOption_CrlImportDateCheckEnable_sf = 1,
} ContextOption_sf;

typedef enum {
    DebugOptionType_AllowDisableVerifyOption_sf = 0,
} DebugOptionType_sf;

typedef enum {
    FlushSessionCacheOptionType_SingleHost_sf = 0,
    FlushSessionCacheOptionType_AllHosts_sf = 0,
} FlushSessionCacheOptionType_sf;

typedef enum {
    InternalPki_None_sf = 0,
    InternalPki_DeviceClientCertDefault_sf = 0,
} InternalPki_sf;

typedef enum {
    IoMode_Blocking_sf = 1,
    IoMode_NonBlocking_sf = 1,
} IoMode_sf;

typedef enum {
    OptionType_DoNotCloseSocket_sf = 0,
    OptionType_GetServerCertChain_sf = 1,
    OptionType_SkipDefaultVerify_sf = 2,
    OptionType_EnableAlpn_sf = 3,
} OptionType_sf;

typedef enum {
    PollEvent_Read_sf = 0,
    PollEvent_Write_sf = 1,
    PollEvent_Except_sf = 2,
} PollEvent_sf;

typedef enum {
    RenegotiationMode_None_sf = 0,
    RenegotiationMode_Secure_sf = 1,
} RenegotiationMode_sf;

typedef enum {
    SessionCacheMode_None_sf = 0,
    SessionCacheMode_SessionId_sf = 1,
    SessionCacheMode_SessionTicket_sf = 2,
} SessionCacheMode_sf;

typedef enum {
    SslVersion_Auto_sf = 1,
    SslVersion_TlsV10_sf = 8,
    SslVersion_TlsV11_sf = 16,
    SslVersion_TlsV12_sf = 32,
    SslVersion_TlsV13_sf = 64,
} SslVersion_sf;

typedef enum {
    VerifyOption_PeerCa_sf = 0,
    VerifyOption_HostName_sf = 1,
    VerifyOption_DateCheck_sf = 2,
    VerifyOption_EvCertPartial_sf = 3,
    VerifyOption_EvPolicyOid_sf = 4,
    VerifyOption_EvCertFingerprint_sf = 5,
} VerifyOption_sf;

Result sslCreateContext_sfMitm(Service *s, u32 version, u64 pid_placeholder,
                               u64 client_pid, Service *out);
Result sslGetContextCount_sfMitm(Service *s, u32 *count);
Result sslGetCertificates_sfMitm(Service *s, const u32 *ids, size_t ids_size,
                                 u32 *certificates_count, void *certificates,
                                 size_t certificates_size);
Result sslGetCertificateBufSize_sfMitm(Service *s, const u32 *ids,
                                       size_t ids_size, u32 *buffer_size);
Result sslDebugIoctl_sfMitm(Service *s);
Result sslSetInterfaceVersion_sfMitm(Service *s, u32 version);
Result sslFlushSessionCache_sfMitm(Service *s, u32 option, const void *value,
                                   size_t value_size);
Result sslSetDebugOption_sfMitm(Service *s, u32 option, const void *value,
                                size_t value_size);
Result sslGetDebugOption_sfMitm(Service *s, u32 option, void *value,
                                size_t value_size);
Result sslClearTls12FallbackFlag_sfMitm(Service *s);
Result sslContextSetOption_sfMitm(Service *s, u32 option, u32 value);
Result sslContextGetOption_sfMitm(Service *s, u32 option, u32 *value);
Result sslContextCreateConnection_sfMitm(Service *s, Service *out);
Result sslContextGetConnectionCount_sfMitm(Service *s, u32 *count);
Result sslContextImportServerPki_sfMitm(Service *s, u32 certificateFormat,
                                        const void *certificate,
                                        size_t certificate_size,
                                        u64 *certificate_id);
Result sslContextImportClientPki_sfMitm(Service *s, const void *certificate,
                                        size_t certificate_size,
                                        const void *ascii_password,
                                        size_t ascii_password_size,
                                        u64 *certificate_id);
Result sslContextRemoveServerPki_sfMitm(Service *s, u64 certificate_id);
Result sslContextRemoveClientPki_sfMitm(Service *s, u64 certificate_id);
Result sslContextRegisterInternalPki_sfMitm(Service *s, u32 pki,
                                            u64 *certificate_id);
Result sslContextAddPolicyOid_sfMitm(Service *s,
                                     const void *cert_policy_checking,
                                     size_t cert_policy_checking_size);
Result sslContextImportCrl_sfMitm(Service *s, const void *crl, size_t crl_size,
                                  u64 *crl_id);
Result sslContextRemoveCrl_sfMitm(Service *s, u64 crl_id);
Result sslConnectionSetSocketDescriptor_sfMitm(Service *s, u32 input_socket_fd,
                                               u32 *output_socket_fd);
Result sslConnectionSetHostName_sfMitm(Service *s, const void *hostname,
                                       size_t hostname_size);
Result sslConnectionSetVerifyOption_sfMitm(Service *s, u32 option);
Result sslConnectionSetIoMode_sfMitm(Service *s, u32 mode);
Result sslConnectionGetSocketDescriptor_sfMitm(Service *s, u32 *socket_fd);
Result sslConnectionGetHostName_sfMitm(Service *s, u32 *hostname_length,
                                       void *hostname, size_t hostname_size);
Result sslConnectionGetVerifyOption_sfMitm(Service *s, u32 *option);
Result sslConnectionGetIoMode_sfMitm(Service *s, u32 *mode);
Result sslConnectionDoHandshake_sfMitm(Service *s);
Result sslConnectionDoHandshakeGetServerCert_sfMitm(
    Service *s, u32 *buffer_size, u32 *certificates_count,
    void *server_cert_buffer, size_t server_cert_buffer_size);
Result sslConnectionRead_sfMitm(Service *s, u32 *read_count, void *buffer,
                                size_t buffer_size);
Result sslConnectionWrite_sfMitm(Service *s, const void *buffer,
                                 size_t buffer_size, u32 *write_count);
Result sslConnectionPending_sfMitm(Service *s, u32 *pending_count);
Result sslConnectionPeek_sfMitm(Service *s, u32 *peek_count, void *buffer,
                                size_t buffer_size);
Result sslConnectionPoll_sfMitm(Service *s, u32 poll_event, u32 timeout,
                                u32 *out_poll_event);
Result sslConnectionGetVerifyCertError_sfMitm(Service *s);
Result
sslConnectionGetNeededServerCertBufferSize_sfMitm(Service *s,
                                                  u32 *needed_buffer_size);
Result sslConnectionSetSessionCacheMode_sfMitm(Service *s, u32 mode);
Result sslConnectionGetSessionCacheMode_sfMitm(Service *s, u32 *mode);
Result sslConnectionFlushSessionCache_sfMitm(Service *s);
Result sslConnectionSetRenegotiationMode_sfMitm(Service *s, u32 mode);
Result sslConnectionGetRenegotiationMode_sfMitm(Service *s, u32 *mode);
Result sslConnectionSetOption_sfMitm(Service *s, bool value, u32 option);
Result sslConnectionGetOption_sfMitm(Service *s, u32 value, bool *option);
Result sslConnectionGetVerifyCertErrors_sfMitm(Service *s, u32 *unk0, u32 *unk1,
                                               void *unk2, size_t unk2_size);
Result sslConnectionGetCipherInfo_sfMitm(Service *s, u32 unk0,
                                         void *cipher_info,
                                         size_t cipher_info_size);
Result sslConnectionSetNextAlpnProto_sfMitm(Service *s, const void *alpn_proto,
                                            size_t alpn_proto_size);
Result sslConnectionGetNextAlpnProto_sfMitm(Service *s, u32 *state,
                                            u32 *alpn_proto_out_size,
                                            void *alpn_proto,
                                            size_t alpn_proto_size);

#ifdef __cplusplus
}
#endif