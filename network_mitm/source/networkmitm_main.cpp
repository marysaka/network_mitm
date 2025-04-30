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
#include "networkmitm_ssl_service_system_impl.hpp"
#include <stratosphere.hpp>

namespace ams {
namespace impl {
#define AMS_DEFINE_SYSTEM_THREAD(__AMS_THREAD_PRIORITY__, __AMS_MODULE__,      \
                                 __AMS_THREAD_NAME__)                          \
    constexpr inline const ::ams::impl::SystemThreadDefinition                 \
        SystemThreadDefinition_##__AMS_MODULE__##_##__AMS_THREAD_NAME__ = {    \
            __AMS_THREAD_PRIORITY__,                                           \
            "ams." #__AMS_MODULE__ "." #__AMS_THREAD_NAME__}

AMS_DEFINE_SYSTEM_THREAD(10, network_mitm, Main);

#undef AMS_DEFINE_SYSTEM_THREAD
} // namespace impl

namespace diag::impl {
void ReplaceDefaultLogObserver(LogObserver observer);
void ResetDefaultLogObserver();
} // namespace diag::impl

namespace ssl {

constinit u8 g_fs_heap_memory[32_KB];
constinit lmem::HeapHandle g_fs_heap_handle;

void *AllocateForFs(size_t size) {
    return lmem::AllocateFromExpHeap(g_fs_heap_handle, size);
}

void DeallocateForFs(void *p, size_t size) {
    AMS_UNUSED(size);
    return lmem::FreeToExpHeap(g_fs_heap_handle, p);
}

void InitializeFsHeap() {
    g_fs_heap_handle = lmem::CreateExpHeap(
        g_fs_heap_memory, sizeof(g_fs_heap_memory), lmem::CreateOption_None);
}

void FinalizeFsHeap() { lmem::DestroyExpHeap(g_fs_heap_handle); }
} // namespace ssl

namespace {
static fs::FileHandle g_logger_file;
static s64 g_logger_file_ofs;
constinit os::SdkMutex g_logger_file_mutex;

void LogFileLogObserver(const diag::LogMetaData &meta,
                        const diag::LogBody &body, void *) {
    AMS_UNUSED(meta);

    std::scoped_lock lk(g_logger_file_mutex);

    R_ABORT_UNLESS(fs::WriteFile(g_logger_file, g_logger_file_ofs, body.message,
                                 body.message_size, fs::WriteOption::Flush));
    g_logger_file_ofs += body.message_size;
}

void InitializeFileLogger() {
    char logs_dir_path[ams::fs::EntryNameLengthMax + 1];
    util::SNPrintf(logs_dir_path, sizeof(logs_dir_path),
                   "%s:/atmosphere/logs/",
                   ams::fs::impl::SdCardFileSystemMountName);
    bool dir_exists;
    auto result = fs::HasDirectory(&dir_exists, logs_dir_path);
    if (R_FAILED(result)) {
        AMS_ABORT("Cannot access SD!");
    }

    if (!dir_exists) {
        result = fs::CreateDirectory(logs_dir_path);
        if (R_FAILED(result)) {
            AMS_ABORT("Cannot access SD!");
        }
    }

    char log_file_path[ams::fs::EntryNameLengthMax + 1];
    util::SNPrintf(log_file_path, sizeof(log_file_path),
                   "%s:/atmosphere/logs/network_mitm_observer.log",
                   ams::fs::impl::SdCardFileSystemMountName);

    result = fs::CreateFile(log_file_path, 0);
    if (R_FAILED(result) && !fs::ResultPathAlreadyExists::Includes(result)) {
        AMS_ABORT("Cannot create log file!");
    }

    R_ABORT_UNLESS(fs::OpenFile(std::addressof(g_logger_file), log_file_path,
                                fs::OpenMode_All));

    g_logger_file_ofs = 0;

    diag::impl::ReplaceDefaultLogObserver(LogFileLogObserver);
}

void FinalizeFileLogger() {
    diag::impl::ResetDefaultLogObserver();

    fs::CloseFile(g_logger_file);
}
} // namespace

namespace {
/* TODO: Use an ExpHeap and see if we need less/more */
constexpr size_t MallocBufferSize = 1_MB;
alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];
} // namespace

namespace init {

void InitializeSystemModule() {
    /* Initialize fs heap. */
    ssl::InitializeFsHeap();

    /* Initialize our connection to sm. */
    R_ABORT_UNLESS(sm::Initialize());

    /* Initialize fs. */
    fs::InitializeForSystem();
    fs::SetAllocator(ssl::AllocateForFs, ssl::DeallocateForFs);
    fs::SetEnabledAutoAbort(false);

    cfg::WaitSdCardInitialized();

    R_ABORT_UNLESS(fs::MountSdCard(ams::fs::impl::SdCardFileSystemMountName));

    /* Initialize logger early */
    // FIXME: Broken rn and cause memory corruption even on hello world.
    // ams::lm::Initialize();
    InitializeFileLogger();

    /* Initialize settings */
    R_ABORT_UNLESS((Result)::setsysInitialize());

    /* Initialize time for file dating */
    R_ABORT_UNLESS((Result)::timeInitialize());
}

void FinalizeSystemModule() {
    timeExit();

    setsysExit();

    FinalizeFileLogger();

    // TODO: fs finalize?

    // ams::lm::Finalize();

    /* Close sm session */
    R_ABORT_UNLESS(sm::Finalize());

    /* Finalize the fs heap */
    ssl::FinalizeFsHeap();
}

void Startup() {
    /* Initialize the global malloc allocator. */
    init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
}

} // namespace init

bool ShouldSslMitm() {
    u8 en = 0;
    if (settings::fwdbg::GetSettingsItemValue(std::addressof(en), sizeof(en),
                                              "network_mitm",
                                              "enable_ssl") == sizeof(en)) {
        return (en != 0);
    }

    return false;
}

bool ShouldDisableSslVerification() {
    u8 en = 0;
    if (settings::fwdbg::GetSettingsItemValue(std::addressof(en), sizeof(en),
                                              "network_mitm",
                                              "disable_ssl_verification") == sizeof(en)) {
        return (en != 0);
    }

    return false;
}

bool ShouldDumpSslTraffic() {
    u8 en = 0;
    if (settings::fwdbg::GetSettingsItemValue(
            std::addressof(en), sizeof(en), "network_mitm",
            "should_dump_ssl_traffic") == sizeof(en)) {
        return (en != 0);
    }

    return false;
}

namespace ssl::sf::impl {
const int CAKeyStorageSize = 0x1000;
constinit u8 g_ca_public_key_storage_der[CAKeyStorageSize];
Span<uint8_t> g_ca_certificate_public_key_der = Span<uint8_t>();
bool g_should_dump_ssl_traffic;
bool g_should_disable_ssl_verification;
PcapLinkType g_link_type;

enum PortIndex {
    PortIndex_SslMitm,
    PortIndex_SslSMitm,
    PortIndex_Count,
};

constexpr sm::ServiceName MitmSslServiceName = sm::ServiceName::Encode("ssl");
constexpr sm::ServiceName MitmSslSServiceName = sm::ServiceName::Encode("ssl:s");

struct ServerOptions {
    // FIXME: Use real values from SSL after reverse
    static constexpr size_t PointerBufferSize = 0x10000;
    static constexpr size_t MaxDomains = 0x40;
    static constexpr size_t MaxDomainObjects = 0x4000;
    static constexpr bool CanDeferInvokeRequest = false;
    static constexpr bool CanManageMitmServers = true;
};

class ServerManager final
    : public ams::sf::hipc::ServerManager<PortIndex_Count, ServerOptions> {
  private:
    virtual Result OnNeedsToAccept(int port_index, Server *server) override;
};

ServerManager g_server_manager_ssl;
ServerManager g_server_manager_ssl_s;

Result ServerManager::OnNeedsToAccept(int port_index, Server *server) {
    /* Acknowledge the mitm session. */
    std::shared_ptr<::Service> forward_service;
    sm::MitmProcessInfo client_info;
    server->AcknowledgeMitmSession(std::addressof(forward_service),
                                   std::addressof(client_info));

    Result res;
    switch (port_index) {
    case PortIndex_SslMitm:
        R_RETURN(this->AcceptMitmImpl(
            server,
            ams::sf::CreateSharedObjectEmplaced<ISslService, SslServiceImpl>(
                decltype(forward_service)(forward_service), client_info,
                g_should_dump_ssl_traffic, g_link_type,
                g_ca_certificate_public_key_der, g_should_disable_ssl_verification),
            forward_service));
    case PortIndex_SslSMitm:
        R_RETURN(this->AcceptMitmImpl(
                server,
                ams::sf::CreateSharedObjectEmplaced<ISslServiceForSystem, SslServiceForSystemImpl>(
                    decltype(forward_service)(forward_service), client_info,
                    g_should_dump_ssl_traffic, g_link_type,
                    g_ca_certificate_public_key_der, g_should_disable_ssl_verification),
                forward_service));
    AMS_UNREACHABLE_DEFAULT_CASE();
    }
}

constexpr size_t TotalThreads = 2; // raise if needed
static_assert(TotalThreads >= 2, "TotalThreads");
constexpr size_t NumExtraThreads = TotalThreads - 1;
constexpr size_t ThreadStackSize = 0x8000;
alignas(os::MemoryPageSize) u8
    g_extra_thread_stacks[NumExtraThreads][ThreadStackSize];

os::ThreadType g_extra_threads[NumExtraThreads];

void LoopServerThreadSsl(void *) {
    /* Loop forever, servicing our services. */
    g_server_manager_ssl.LoopProcess();
}

void LoopServerThreadSslS(void *) {
    /* Loop forever, servicing our services. */
    g_server_manager_ssl_s.LoopProcess();
}


void ProcessForServerOnAllThreads() {
    /* Initialize threads. */
    if constexpr (NumExtraThreads > 0) {
        const s32 priority =
            os::GetThreadCurrentPriority(os::GetCurrentThread());
        for (size_t i = 0; i < NumExtraThreads; i++) {
            R_ABORT_UNLESS(os::CreateThread(
                g_extra_threads + i, i % 2 ? LoopServerThreadSslS : LoopServerThreadSsl, nullptr,
                g_extra_thread_stacks[i], ThreadStackSize, priority));
        }
    }

    /* Start extra threads. */
    if constexpr (NumExtraThreads > 0) {
        for (size_t i = 0; i < NumExtraThreads; i++) {
            os::StartThread(g_extra_threads + i);
        }
    }

    /* Loop this thread. */
    LoopServerThreadSslS(nullptr);

    /* Wait for extra threads to finish. */
    if constexpr (NumExtraThreads > 0) {
        for (size_t i = 0; i < NumExtraThreads; i++) {
            os::WaitThread(g_extra_threads + i);
        }
    }
}

Result ReadFileToBuffer(const char *path, void *buffer, size_t buffer_size,
                        size_t &out_size) {
    /* Open the value file. */
    fs::FileHandle file;
    R_TRY(fs::OpenFile(std::addressof(file), path, fs::OpenMode_Read));
    ON_SCOPE_EXIT { fs::CloseFile(file); };

    /* Get the value size. */
    s64 file_size;
    R_TRY(fs::GetFileSize(std::addressof(file_size), file));

    /* Ensure there's enough space for the value. */
    R_UNLESS(file_size <= static_cast<s64>(buffer_size),
             kvdb::ResultBufferInsufficient());

    /* Read the value. */
    const size_t value_size = static_cast<size_t>(file_size);
    R_TRY(fs::ReadFile(file, 0, buffer, value_size));
    out_size = value_size;

    R_SUCCEED();
}

void Initialize(bool should_dump_ssl_traffic, bool should_disable_ssl_verification) {
    g_should_dump_ssl_traffic = should_dump_ssl_traffic;
    g_should_disable_ssl_verification = should_disable_ssl_verification;
    
    g_link_type = PcapLinkType::User;

    char pcap_link_type[16];
    auto read_size = settings::fwdbg::GetSettingsItemValue(
        pcap_link_type, sizeof(pcap_link_type), "network_mitm",
        "pcap_link_type");

    if (read_size != 0) {
        if (!strncmp(pcap_link_type, "user", 4)) {
            g_link_type = PcapLinkType::User;
        } else if (!strncmp(pcap_link_type, "ip", 2)) {
            g_link_type = PcapLinkType::Ip;
        } else if (!strncmp(pcap_link_type, "ethernet", 8)) {
            g_link_type = PcapLinkType::Ethernet;
        }
    }

    char setting_path[ams::fs::EntryNameLengthMax + 1];
    char custom_cert_path[ams::fs::EntryNameLengthMax + 1];
    read_size = settings::fwdbg::GetSettingsItemValue(
        setting_path, sizeof(setting_path), "network_mitm",
        "custom_ca");
    if (read_size != 0) {
        util::SNPrintf(custom_cert_path, sizeof(custom_cert_path), "%s:/%s",
                       ams::fs::impl::SdCardFileSystemMountName, setting_path);
        AMS_LOG("Attempting to load custom CA public cert at %s\n",
                custom_cert_path);
        
        size_t out_size;

        if (R_SUCCEEDED(ReadFileToBuffer(
                custom_cert_path, g_ca_public_key_storage_der,
                sizeof(g_ca_public_key_storage_der), out_size))) {
            AMS_LOG("Loaded custom CA.\n");
            g_ca_certificate_public_key_der = MakeSpan(
                g_ca_public_key_storage_der, out_size);
        } else {
            AMS_LOG("Failed to load custom CA public cert file at %s\n",
                    custom_cert_path);
        }
    }
}
} // namespace ssl::sf::impl

void Main() {
    /* Set thread name. */
    os::SetThreadNamePointer(os::GetCurrentThread(),
                             AMS_GET_SYSTEM_THREAD_NAME(network_mitm, Main));
    AMS_ASSERT(os::GetThreadPriority(os::GetCurrentThread()) ==
               AMS_GET_SYSTEM_THREAD_PRIORITY(network_mitm, Main));

    if (!ShouldSslMitm()) {
        AMS_LOG("network_mitm is disabled by configuration.\n");
        AMS_LOG("To enable SSL mitm, set \"enable_ssl = 1\" in "
                "system_settings.ini\n");

        return;
    }

    using namespace ams::ssl::sf::impl;

    AMS_LOG("network_mitm enabled\n");
    bool should_dump_ssl_traffic = ShouldDumpSslTraffic();
    if (should_dump_ssl_traffic) {
        AMS_LOG("SSL service traffic dumping is temporarily disabled due to a bug\n");
        should_dump_ssl_traffic = false;
    }

    const bool should_disable_ssl_verification = ShouldDisableSslVerification();
    if (!should_disable_ssl_verification) {
        AMS_LOG("SSL certificate verification will remain enabled\n");
    }


    Initialize(should_dump_ssl_traffic, should_disable_ssl_verification);

    /* Create mitm servers. */
    R_ABORT_UNLESS((g_server_manager_ssl.RegisterMitmServer<SslServiceImpl>(
        PortIndex_SslMitm, MitmSslServiceName)));
    if (hos::GetVersion() > hos::Version_15_0_0)
        R_ABORT_UNLESS((g_server_manager_ssl_s.RegisterMitmServer<SslServiceForSystemImpl>(
            PortIndex_SslSMitm, MitmSslSServiceName)));

    /* Loop forever, servicing our services. */
    AMS_LOG("Accepting requests.\n");
    ProcessForServerOnAllThreads();
}

} // namespace ams
