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
#include "pcap_utils.hpp"

namespace ams::ssl::mitm::pcap {
static Result EnsureDirectoryByPath(const char *path) {
    R_TRY_CATCH(fs::CreateDirectory(path)) {
        R_CATCH(fs::ResultPathAlreadyExists) { /* It's okay if the directory
                                                  already exists. */
        }
    }
    R_END_TRY_CATCH;

    R_SUCCEED();
}

static void GetBaseDirectory(char *buffer, size_t buffer_size) {
    util::SNPrintf(buffer, buffer_size - 1, "%s:/atmosphere/pcap",
                   ams::fs::impl::SdCardFileSystemMountName);
}

static void GetTitleDirectrory(char *buffer, size_t buffer_size,
                               ncm::ProgramId programId) {
    char base_path[ams::fs::EntryNameLengthMax + 1];

    GetBaseDirectory(base_path, sizeof(base_path));
    EnsureDirectoryByPath(base_path);

    util::SNPrintf(buffer, buffer_size - 1, "%s/%016lx", base_path,
                   static_cast<u64>(programId));
}

Result EnsureDirectory(ncm::ProgramId programId) {
    char title_path[ams::fs::EntryNameLengthMax + 1];

    GetTitleDirectrory(title_path, sizeof(title_path), programId);

    return EnsureDirectoryByPath(title_path);
}

void GetCurrentTime(u64 *out) {
    if (R_FAILED(timeGetCurrentTime(TimeType_LocalSystemClock, out))) {
        // Grab system ticks in case of absolute failure
        *out = os::GetSystemTick().GetInt64Value();
    }
}

void GetNewFilePathForPcap(char *buffer, size_t buffer_size,
                           ncm::ProgramId programId) {
    u64 timestamp;

    GetCurrentTime(&timestamp);

    char title_path[ams::fs::EntryNameLengthMax + 1];

    GetTitleDirectrory(title_path, sizeof(title_path), programId);

    util::SNPrintf(buffer, buffer_size - 1, "%s/%011lu.pcap", title_path,
                   timestamp);
}
} // namespace ams::ssl::mitm::pcap