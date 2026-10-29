#include "FileScanner.h"
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <unordered_set>
#include <limits>
// ─── Helpers ───────────────────────────────────────────────

static std::string filetimeToString(FILETIME ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

// ─── Existing file walk ────────────────────────────────────

void FileScanner::walkDirectory(const std::string& path,
                                 std::vector<FileEntry>& results) {
    std::string searchPath = path + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;

        FileEntry entry;
        entry.name = name;
        entry.fullPath = path + "\\" + name;
        entry.status = FileStatus::EXISTING;
        entry.isDirectory = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);

        ULARGE_INTEGER size;
        size.LowPart  = fd.nFileSizeLow;
        size.HighPart = fd.nFileSizeHigh;
        entry.sizeBytes = size.QuadPart;
        entry.lastModified = filetimeToString(fd.ftLastWriteTime);

        results.push_back(entry);

        if (entry.isDirectory) {
            walkDirectory(entry.fullPath, results);
        }

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

std::vector<FileEntry> FileScanner::scanExisting(
    const std::string& driveLetter)
{
    std::vector<FileEntry> results;
    std::string root = driveLetter + ":";
    walkDirectory(root, results);
    return results;
}

// ─── Filesystem detection ──────────────────────────────────

uint8_t FileScanner::detectFilesystem(HANDLE hDrive) {
    // Read boot sector (first 512 bytes)
    uint8_t sector[512] = {};
    DWORD br = 0;
    LARGE_INTEGER pos; pos.QuadPart = 0;
    SetFilePointerEx(hDrive, pos, NULL, FILE_BEGIN);
    ReadFile(hDrive, sector, 512, &br, NULL);

    // FAT32: bytes 82-89 = "FAT32   "
    if (memcmp(sector + 82, "FAT32   ", 8) == 0) return 32;

    // exFAT: bytes 3-10 = "EXFAT   "
    if (memcmp(sector + 3, "EXFAT   ", 8) == 0) return 64;

    return 0; // unknown
}

// ─── FAT32 deleted file parser ─────────────────────────────

#pragma pack(push, 1)
struct FAT32DirEntry {
    uint8_t  name[11];
    uint8_t  attr;
    uint8_t  reserved;
    uint8_t  createTimeTenth;
    uint16_t createTime;
    uint16_t createDate;
    uint16_t accessDate;
    uint16_t clusterHigh;
    uint16_t writeTime;
    uint16_t writeDate;
    uint16_t clusterLow;
    uint32_t fileSize;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct FAT32LFNEntry
{
    uint8_t order;
    uint16_t name1[5];
    uint8_t attr;
    uint8_t type;
    uint8_t checksum;
    uint16_t name2[6];
    uint16_t firstCluster;
    uint16_t name3[2];
};
#pragma pack(pop)

static std::string decodeLFNCharacters(const FAT32LFNEntry& lfn)
{
    std::string result;

    uint16_t chars[13];

    for (int i = 0; i < 5; ++i)
        chars[i] = lfn.name1[i];

    for (int i = 0; i < 6; ++i)
        chars[5 + i] = lfn.name2[i];

    for (int i = 0; i < 2; ++i)
        chars[11 + i] = lfn.name3[i];

    for (int i = 0; i < 13; ++i)
    {
        uint16_t c = chars[i];

        if (c == 0x0000 || c == 0xFFFF)
            break;

        if (c < 128)
            result += static_cast<char>(c);
        else
            result += '?';
    }

    return result;
}

static std::string buildDeletedShortName(const FAT32DirEntry& entry)
{
    char fname[12] = {};
    fname[0] = '?';

    for (int j = 1; j < 8; ++j)
    {
        if (entry.name[j] == 0x20)
            break;

        fname[j] = static_cast<char>(entry.name[j]);
    }

    bool hasExt = false;
    char ext[4] = {};

    for (int j = 0; j < 3; ++j)
    {
        if (entry.name[8 + j] != 0x20)
        {
            ext[j] = static_cast<char>(entry.name[8 + j]);
            hasExt = true;
        }
    }

    std::string result = fname;

    if (hasExt)
        result += "." + std::string(ext);

    return result;
}

std::vector<FileEntry> FileScanner::parseFAT32Deleted(HANDLE hDrive)
{
    std::vector<FileEntry> results;

    uint8_t boot[512] = {};
    DWORD br = 0;

    LARGE_INTEGER pos;
    pos.QuadPart = 0;

    SetFilePointerEx(hDrive, pos, NULL, FILE_BEGIN);

    if (!ReadFile(hDrive, boot, 512, &br, NULL) || br != 512)
        return results;

    uint16_t bytesPerSector =
        *(uint16_t*)(boot + 11);

    uint8_t sectorsPerCluster =
        *(uint8_t*)(boot + 13);

    uint16_t reservedSectors =
        *(uint16_t*)(boot + 14);

    uint8_t numFATs =
        *(uint8_t*)(boot + 16);

    uint32_t sectorsPerFAT =
        *(uint32_t*)(boot + 36);

    uint32_t rootCluster =
        *(uint32_t*)(boot + 44);

    uint16_t totalSectors16 =
        *(uint16_t*)(boot + 19);

    uint32_t totalSectors32 =
        *(uint32_t*)(boot + 32);

    if (bytesPerSector == 0 ||
        sectorsPerCluster == 0 ||
        numFATs == 0 ||
        sectorsPerFAT == 0 ||
        rootCluster < 2 ||
        (bytesPerSector & (bytesPerSector - 1)) != 0 ||
        bytesPerSector < sizeof(uint32_t))
    {
        return results;
    }

    const uint64_t totalSectors =
        totalSectors16 != 0 ? totalSectors16 : totalSectors32;
    const uint64_t firstDataSector =
        (uint64_t)reservedSectors + (uint64_t)numFATs * sectorsPerFAT;
    if (totalSectors <= firstDataSector) {
        return results;
    }

    uint64_t fatStart =
        (uint64_t)reservedSectors * bytesPerSector;

    uint64_t dataStart =
        fatStart +
        (uint64_t)numFATs *
        sectorsPerFAT *
        bytesPerSector;

    uint64_t clusterSize =
        (uint64_t)sectorsPerCluster *
        bytesPerSector;

    const uint64_t fatSizeBytes =
        (uint64_t)sectorsPerFAT * bytesPerSector;
    const uint64_t fatEnd = fatStart + fatSizeBytes;
    const uint64_t dataClusterCount =
        (totalSectors - firstDataSector) / sectorsPerCluster;
    const uint64_t maxDataCluster = dataClusterCount + 1;

    uint32_t cluster = rootCluster;

    uint64_t clusterOffset =
        dataStart +
        (uint64_t)(cluster - 2) *
        clusterSize;

    std::vector<uint8_t> clusterData(clusterSize);

    LARGE_INTEGER seekPos;
    seekPos.QuadPart = (LONGLONG)clusterOffset;

    SetFilePointerEx(
        hDrive,
        seekPos,
        NULL,
        FILE_BEGIN
    );

    if (!ReadFile(
            hDrive,
            clusterData.data(),
            (DWORD)clusterSize,
            &br,
            NULL))
    {
        return results;
    }

    if (br != clusterSize)
        return results;

    size_t entryCount =
        clusterSize / sizeof(FAT32DirEntry);

    FAT32DirEntry* entries =
        reinterpret_cast<FAT32DirEntry*>(
            clusterData.data()
        );

    for (size_t i = 0; i < entryCount; ++i)
    {
        uint8_t first =
            entries[i].name[0];

        if (first == 0x00)
            break;

        /*
         * Deleted LFN entries are kept so that
         * they can be associated with the
         * deleted short-name entry that follows.
         */
        if (first == 0xE5 &&
            entries[i].attr == 0x0F)
        {
            continue;
        }

        if (first != 0xE5)
            continue;

        if (entries[i].attr == 0x0F)
            continue;

        if (entries[i].attr & 0x10)
            continue;

        if (entries[i].attr & 0x08)
            continue;

        if (entries[i].fileSize == 0 &&
            entries[i].clusterLow == 0 &&
            entries[i].clusterHigh == 0)
        {
            continue;
        }

        /*
         * Look backwards for consecutive deleted
         * LFN entries belonging to this file.
         */
        std::vector<std::pair<uint8_t, std::string>> lfnParts;

        size_t j = i;

        while (j > 0)
        {
            --j;

            FAT32LFNEntry* lfn =
                reinterpret_cast<FAT32LFNEntry*>(
                    &entries[j]
                );

            if (entries[j].name[0] != 0xE5)
                break;

            if (entries[j].attr != 0x0F)
                break;

            std::string part =
                decodeLFNCharacters(*lfn);

            lfnParts.push_back(
                {
                    static_cast<uint8_t>(
                        lfn->order & 0x1F
                    ),
                    part
                }
            );

            /*
             * The LAST_LONG_ENTRY flag is 0x40.
             * Once found, the LFN sequence is complete.
             */
        }

        std::string fullName;

        if (!lfnParts.empty())
        {
            std::sort(
                lfnParts.begin(),
                lfnParts.end(),
                [](const auto& a, const auto& b)
                {
                    return a.first < b.first;
                }
            );

            for (const auto& part : lfnParts)
                fullName += part.second;
        }

        if (fullName.empty())
            fullName =
                buildDeletedShortName(entries[i]);

        FileEntry entry;

        entry.name =
            fullName;

        entry.fullPath =
            "[DELETED] " + fullName;

        entry.sizeBytes =
            entries[i].fileSize;

        entry.lastModified =
            "Unknown";

        entry.status =
            FileStatus::DELETED;

        entry.isDirectory = false;

uint32_t startCluster =
    ((uint32_t)entries[i].clusterHigh << 16) |
    entries[i].clusterLow;

entry.startCluster = startCluster;

if (startCluster >= 2) {
    entry.dataOffset =
        dataStart +
        (uint64_t)(startCluster - 2) * clusterSize;
}

entry.clusterSize = clusterSize;
entry.dataRegionStart = dataStart;

if (startCluster >= 2) {
    entry.dataOffset =
        dataStart + (uint64_t)(startCluster - 2) * clusterSize;
} else {
    entry.dataOffset = 0;
}

bool chainValid = true;
uint64_t remainingBytes = entry.sizeBytes;
uint32_t currentCluster = startCluster;
size_t iterations = 0;
const size_t maxClusterVisits = 0x100000;
const uint64_t expectedClusterCount = clusterSize == 0
    ? 0
    : entry.sizeBytes / clusterSize + (entry.sizeBytes % clusterSize != 0);
std::unordered_set<uint32_t> visitedClusters;

if (startCluster < 2 || startCluster > maxDataCluster ||
    (entry.sizeBytes > 0 && startCluster == 0) ||
    expectedClusterCount > maxClusterVisits) {
    chainValid = false;
}

while (chainValid &&
       currentCluster >= 2 &&
       currentCluster < 0x0FFFFFF8 &&
       remainingBytes > 0 &&
       iterations < maxClusterVisits) {
    if (currentCluster > maxDataCluster ||
        !visitedClusters.insert(currentCluster).second) {
        chainValid = false;
        break;
    }

    entry.clusterChain.push_back(currentCluster);

    uint64_t extentOffset =
        dataStart + (uint64_t)(currentCluster - 2) * clusterSize;
    uint64_t extentLength = std::min<uint64_t>(clusterSize, remainingBytes);
    entry.extents.push_back({extentOffset, extentLength});
    remainingBytes -= extentLength;

    if (remainingBytes == 0) {
        break;
    }

    uint64_t fatEntryOffset = fatStart + (uint64_t)currentCluster * 4;
    const uint64_t fatEntryWithinFat = fatEntryOffset - fatStart;
    const uint64_t fatSectorOffset =
        (fatEntryOffset / bytesPerSector) * bytesPerSector;
    const uint64_t entryOffsetInSector = fatEntryOffset - fatSectorOffset;

    if (fatEntryWithinFat > fatSizeBytes - sizeof(uint32_t) ||
        fatSectorOffset < fatStart ||
        fatSectorOffset > fatEnd - bytesPerSector ||
        entryOffsetInSector > bytesPerSector - sizeof(uint32_t)) {
        chainValid = false;
        break;
    }

    LARGE_INTEGER fatPos;
    fatPos.QuadPart = (LONGLONG)fatSectorOffset;

    if (!SetFilePointerEx(hDrive, fatPos, NULL, FILE_BEGIN)) {
        chainValid = false;
        break;
    }

    std::vector<uint8_t> fatSector(bytesPerSector);
    DWORD fatBytesRead = 0;

    if (!ReadFile(hDrive,
                  fatSector.data(),
                  bytesPerSector,
                  &fatBytesRead,
                  NULL) ||
        fatBytesRead != bytesPerSector) {
        chainValid = false;
        break;
    }

    uint32_t nextCluster = 0;
    memcpy(&nextCluster,
           fatSector.data() + entryOffsetInSector,
           sizeof(nextCluster));
    nextCluster &= 0x0FFFFFFF;

    if (nextCluster >= 0x0FFFFFF8 && nextCluster <= 0x0FFFFFFF) {
        if (remainingBytes > 0) {
            chainValid = false;
        }
        break;
    }

    if (nextCluster < 2 ||
        nextCluster == 0x0FFFFFF7 ||
        (nextCluster >= 0x0FFFFFF0 && nextCluster <= 0x0FFFFFF6) ||
        nextCluster == currentCluster ||
        visitedClusters.find(nextCluster) != visitedClusters.end() ||
        nextCluster > maxDataCluster) {
        chainValid = false;
        break;
    }

    currentCluster = nextCluster;
    ++iterations;
}

if (entry.sizeBytes == 0) {
    if (!entry.clusterChain.empty()) {
        chainValid = false;
    }
} else {
    if (remainingBytes > 0) {
        chainValid = false;
    }
}

if (!chainValid) {
    // A deleted FAT32 directory entry often retains file size and start cluster,
    // while the FAT chain is cleared by the filesystem. Only infer a contiguous
    // extent if every candidate cluster is inside the data region and FREE in
    // every FAT copy. If any candidate is allocated or metadata is ambiguous,
    // leave the file unavailable rather than risking an active file.
    entry.clusterChain.clear();
    entry.extents.clear();
    entry.dataOffset = 0;
    entry.isValid = false;

    std::unordered_set<uint32_t> claimedClusters;
    for (const auto& priorEntry : results) {
        if (priorEntry.isValid) {
            for (uint32_t priorCluster : priorEntry.clusterChain)
                claimedClusters.insert(priorCluster);
        }
    }

    bool contiguousCandidate = entry.sizeBytes > 0 &&
        startCluster >= 2 &&
        startCluster <= maxDataCluster &&
        expectedClusterCount > 0 &&
        expectedClusterCount <= maxClusterVisits &&
        expectedClusterCount <= maxDataCluster - startCluster + 1;

    if (contiguousCandidate) {
        const uint64_t candidateOffset =
            dataStart + static_cast<uint64_t>(startCluster - 2) * clusterSize;
        const uint64_t volumeBytes = totalSectors * bytesPerSector;
        contiguousCandidate = candidateOffset <= volumeBytes &&
            entry.sizeBytes <= volumeBytes - candidateOffset &&
            expectedClusterCount * clusterSize >= entry.sizeBytes;
        
        bool allCandidateClustersFree = contiguousCandidate;
        for (uint8_t fatCopy = 0;
             allCandidateClustersFree && fatCopy < numFATs;
             ++fatCopy) {
            const uint64_t currentFatStart =
                fatStart + static_cast<uint64_t>(fatCopy) * fatSizeBytes;
            const uint64_t currentFatEnd = currentFatStart + fatSizeBytes;
            uint64_t cachedSectorOffset = std::numeric_limits<uint64_t>::max();
            std::vector<uint8_t> fatSector(bytesPerSector);

            for (uint64_t clusterIndex = 0;
                 clusterIndex < expectedClusterCount;
                 ++clusterIndex) {
                const uint64_t candidateCluster =
                    static_cast<uint64_t>(startCluster) + clusterIndex;
                const uint64_t fatEntryRelative = candidateCluster * sizeof(uint32_t);
                if (candidateCluster > maxDataCluster ||
                    claimedClusters.find(static_cast<uint32_t>(candidateCluster)) != claimedClusters.end() ||
                    fatEntryRelative > fatSizeBytes - sizeof(uint32_t)) {
                    allCandidateClustersFree = false;
                    break;
                }

                const uint64_t fatEntryOffset = currentFatStart + fatEntryRelative;
                const uint64_t sectorOffset =
                    (fatEntryOffset / bytesPerSector) * bytesPerSector;
                const uint64_t offsetInSector = fatEntryOffset - sectorOffset;

                if (sectorOffset < currentFatStart ||
                    sectorOffset > currentFatEnd - bytesPerSector ||
                    offsetInSector > bytesPerSector - sizeof(uint32_t)) {
                    allCandidateClustersFree = false;
                    break;
                }

                if (sectorOffset != cachedSectorOffset) {
                    LARGE_INTEGER fatPosition;
                    fatPosition.QuadPart = static_cast<LONGLONG>(sectorOffset);
                    DWORD fatBytesRead = 0;
                    if (!SetFilePointerEx(hDrive, fatPosition, NULL, FILE_BEGIN) ||
                        !ReadFile(hDrive, fatSector.data(), bytesPerSector,
                                  &fatBytesRead, NULL) ||
                        fatBytesRead != bytesPerSector) {
                        allCandidateClustersFree = false;
                        break;
                    }
                    cachedSectorOffset = sectorOffset;
                }

                uint32_t fatValue = 0;
                memcpy(&fatValue, fatSector.data() + offsetInSector, sizeof(fatValue));
                fatValue &= 0x0FFFFFFF;
                if (fatValue != 0) {
                    allCandidateClustersFree = false;
                    break;
                }
            }
        }

        if (allCandidateClustersFree) {
            uint64_t remainingBytes = entry.sizeBytes;
            for (uint64_t clusterIndex = 0;
                 clusterIndex < expectedClusterCount;
                 ++clusterIndex) {
                const uint32_t candidateCluster =
                    static_cast<uint32_t>(static_cast<uint64_t>(startCluster) + clusterIndex);
                const uint64_t extentOffset =
                    dataStart + static_cast<uint64_t>(candidateCluster - 2) * clusterSize;
                const uint64_t extentLength =
                    std::min<uint64_t>(clusterSize, remainingBytes);
                entry.clusterChain.push_back(candidateCluster);
                entry.extents.push_back({extentOffset, extentLength});
                claimedClusters.insert(candidateCluster);
                remainingBytes -= extentLength;
            }

            if (remainingBytes == 0) {
                entry.dataOffset = candidateOffset;
                entry.isValid = true;
                entry.extentMappingInferred = true;
            } else {
                entry.clusterChain.clear();
                entry.extents.clear();
                entry.dataOffset = 0;
                entry.isValid = false;
            }
        }
    }
}

results.push_back(entry);
    }

    return results;
}

// ─── exFAT deleted file parser ─────────────────────────────

std::vector<FileEntry> FileScanner::parseExFATDeleted(HANDLE hDrive)
{
    std::vector<FileEntry> results;

    uint8_t boot[512] = {};
    DWORD bytesRead = 0;
    LARGE_INTEGER position{};
    if (!SetFilePointerEx(hDrive, position, NULL, FILE_BEGIN) ||
        !ReadFile(hDrive, boot, sizeof(boot), &bytesRead, NULL) ||
        bytesRead != sizeof(boot)) {
        return results;
    }

    auto readU16 = [](const uint8_t* p) {
        uint16_t value = 0;
        memcpy(&value, p, sizeof(value));
        return value;
    };
    auto readU32 = [](const uint8_t* p) {
        uint32_t value = 0;
        memcpy(&value, p, sizeof(value));
        return value;
    };
    auto readU64 = [](const uint8_t* p) {
        uint64_t value = 0;
        memcpy(&value, p, sizeof(value));
        return value;
    };

    const uint64_t volumeLengthSectors = readU64(boot + 72);
    const uint32_t fatOffsetSectors = readU32(boot + 80);
    const uint32_t fatLengthSectors = readU32(boot + 84);
    const uint32_t clusterHeapOffset = readU32(boot + 88);
    const uint32_t clusterCount = readU32(boot + 92);
    const uint32_t rootCluster = readU32(boot + 96);
    const uint16_t volumeFlags = readU16(boot + 106);
    const uint8_t sectorShift = boot[108];
    const uint8_t clusterShift = boot[109];
    const uint8_t numberOfFats = boot[110];

    if (sectorShift < 9 || sectorShift > 12 ||
        clusterShift > 25 ||
        static_cast<unsigned>(sectorShift) + clusterShift >= 32 ||
        clusterCount == 0 || rootCluster < 2 ||
        rootCluster > static_cast<uint64_t>(clusterCount) + 1 ||
        fatLengthSectors == 0 ||
        (numberOfFats != 1 && numberOfFats != 2) ||
        volumeLengthSectors == 0) {
        return results;
    }

    const uint64_t bytesPerSector = 1ULL << sectorShift;
    const uint64_t bytesPerCluster = bytesPerSector << clusterShift;
    if (volumeLengthSectors > std::numeric_limits<uint64_t>::max() / bytesPerSector)
        return results;

    const uint64_t volumeSizeBytes = volumeLengthSectors * bytesPerSector;
    const uint64_t fatStart = static_cast<uint64_t>(fatOffsetSectors) * bytesPerSector;
    const uint64_t fatSizeBytes = static_cast<uint64_t>(fatLengthSectors) * bytesPerSector;
    const uint64_t dataRegionStart = static_cast<uint64_t>(clusterHeapOffset) * bytesPerSector;
    const uint64_t maxCluster = static_cast<uint64_t>(clusterCount) + 1;
    const uint32_t activeFat = (numberOfFats == 2) ? (volumeFlags & 1U) : 0U;

    if (bytesPerCluster == 0 ||
        bytesPerCluster > std::numeric_limits<DWORD>::max() ||
        dataRegionStart >= volumeSizeBytes ||
        static_cast<uint64_t>(clusterCount) >
            (volumeSizeBytes - dataRegionStart) / bytesPerCluster ||
        fatStart >= volumeSizeBytes ||
        fatSizeBytes > volumeSizeBytes - fatStart ||
        fatSizeBytes < sizeof(uint32_t) * (static_cast<uint64_t>(maxCluster) + 1) ||
        static_cast<uint64_t>(activeFat + 1) * fatSizeBytes > volumeSizeBytes - fatStart) {
        return results;
    }

    auto readFatEntry = [&](uint32_t clusterId, uint32_t& value) -> bool {
        if (clusterId > maxCluster)
            return false;
        const uint64_t entryRelative = static_cast<uint64_t>(clusterId) * sizeof(uint32_t);
        if (entryRelative > fatSizeBytes - sizeof(uint32_t))
            return false;
        const uint64_t entryOffset =
            fatStart + static_cast<uint64_t>(activeFat) * fatSizeBytes + entryRelative;
        if (entryOffset > volumeSizeBytes - sizeof(uint32_t))
            return false;
        LARGE_INTEGER entryPosition{};
        entryPosition.QuadPart = static_cast<LONGLONG>(entryOffset);
        if (!SetFilePointerEx(hDrive, entryPosition, NULL, FILE_BEGIN))
            return false;
        DWORD count = 0;
        uint32_t rawValue = 0;
        if (!ReadFile(hDrive, &rawValue, sizeof(rawValue), &count, NULL) ||
            count != sizeof(rawValue))
            return false;
        value = rawValue;
        return true;
    };

    // Walk the root directory's allocation chain, rather than looking only
    // at its first cluster. New entries are commonly stored in later clusters.
    std::vector<uint8_t> directoryData;
    uint32_t currentRootCluster = rootCluster;
    std::unordered_set<uint32_t> seenRootClusters;
    bool rootReadValid = true;
    for (uint64_t n = 0; n < clusterCount; ++n) {
        if (currentRootCluster < 2 || currentRootCluster > maxCluster ||
            !seenRootClusters.insert(currentRootCluster).second) {
            rootReadValid = false;
            break;
        }

        const uint64_t clusterOffset = dataRegionStart +
            static_cast<uint64_t>(currentRootCluster - 2) * bytesPerCluster;
        if (clusterOffset > volumeSizeBytes ||
            bytesPerCluster > volumeSizeBytes - clusterOffset) {
            rootReadValid = false;
            break;
        }

        const size_t oldSize = directoryData.size();
        if (bytesPerCluster > std::numeric_limits<size_t>::max() - oldSize) {
            rootReadValid = false;
            break;
        }
        directoryData.resize(oldSize + static_cast<size_t>(bytesPerCluster));
        LARGE_INTEGER clusterPosition{};
        clusterPosition.QuadPart = static_cast<LONGLONG>(clusterOffset);
        DWORD clusterBytesRead = 0;
        if (!SetFilePointerEx(hDrive, clusterPosition, NULL, FILE_BEGIN) ||
            !ReadFile(hDrive, directoryData.data() + oldSize,
                      static_cast<DWORD>(bytesPerCluster), &clusterBytesRead, NULL) ||
            clusterBytesRead != bytesPerCluster) {
            directoryData.resize(oldSize);
            rootReadValid = false;
            break;
        }

        uint32_t nextCluster = 0;
        if (!readFatEntry(currentRootCluster, nextCluster)) {
            rootReadValid = false;
            break;
        }
        if (nextCluster >= 0xFFFFFFF8U && nextCluster <= 0xFFFFFFFFU)
            break;
        if (nextCluster < 2 || nextCluster == 0xFFFFFFF7U ||
            (nextCluster >= 0xFFFFFFF0U && nextCluster <= 0xFFFFFFF6U) ||
            nextCluster > maxCluster || seenRootClusters.find(nextCluster) != seenRootClusters.end()) {
            rootReadValid = false;
            break;
        }
        currentRootCluster = nextCluster;
    }
    if (!rootReadValid || directoryData.empty())
        return results;

    size_t offset = 0;
    while (offset + 32 <= directoryData.size()) {
        const uint8_t entryType = directoryData[offset];
        if (entryType == 0x00)
            break;
        if (entryType != 0x05) { // inactive/deleted primary File entry
            offset += 32;
            continue;
        }

        const uint8_t secondaryCount = directoryData[offset + 1];
        const size_t setSize = (static_cast<size_t>(secondaryCount) + 1U) * 32U;
        if (secondaryCount < 2 || setSize > directoryData.size() - offset) {
            offset += 32;
            continue;
        }

        const uint8_t* stream = nullptr;
        std::vector<const uint8_t*> nameEntries;
        for (size_t entryOffset = offset + 32;
             entryOffset + 32 <= offset + setSize;
             entryOffset += 32) {
            const uint8_t* childEntry = directoryData.data() + entryOffset;
            const uint8_t inactiveType = childEntry[0];
            if (inactiveType == 0x40)
                stream = childEntry;
            else if (inactiveType == 0x41)
                nameEntries.push_back(childEntry);
        }

        if (!stream) {
            offset += setSize;
            continue;
        }

        const uint8_t streamFlags = stream[1];
        const uint8_t nameLength = stream[3];
        const uint32_t firstCluster = readU32(stream + 20);
        const uint64_t dataLength = readU64(stream + 24);
        const bool noFatChain = (streamFlags & 0x02U) != 0;

        std::wstring wideName;
        wideName.reserve(nameLength);
        for (const uint8_t* nameEntry : nameEntries) {
            for (size_t n = 0; n < 15 && wideName.size() < nameLength; ++n) {
                const uint16_t codeUnit = readU16(nameEntry + 2 + n * sizeof(uint16_t));
                if (codeUnit == 0)
                    break;
                wideName.push_back(static_cast<wchar_t>(codeUnit));
            }
            if (wideName.size() >= nameLength)
                break;
        }

        std::string fileName = "[recovered]";
        if (!wideName.empty()) {
            const int needed = WideCharToMultiByte(CP_UTF8, 0, wideName.data(),
                static_cast<int>(wideName.size()), NULL, 0, NULL, NULL);
            if (needed > 0) {
                fileName.resize(static_cast<size_t>(needed));
                WideCharToMultiByte(CP_UTF8, 0, wideName.data(),
                    static_cast<int>(wideName.size()), fileName.data(),
                    needed, NULL, NULL);
            }
        }

        FileEntry entry{};
        entry.name = fileName;
        entry.fullPath = "[DELETED] " + fileName;
        entry.sizeBytes = dataLength;
        entry.lastModified = "Unknown";
        entry.status = FileStatus::DELETED;
        entry.isDirectory = false;
        entry.isValid = false;
        entry.startCluster = firstCluster;
        entry.clusterSize = bytesPerCluster;
        entry.dataRegionStart = dataRegionStart;

        if (dataLength == 0) {
            entry.isValid = true;
            results.push_back(entry);
            offset += setSize;
            continue;
        }

        const uint64_t neededClusters =
            dataLength / bytesPerCluster + (dataLength % bytesPerCluster != 0);
        if (firstCluster < 2 || firstCluster > maxCluster ||
            neededClusters == 0 || neededClusters > clusterCount ||
            neededClusters > maxCluster - firstCluster + 1) {
            results.push_back(entry);
            offset += setSize;
            continue;
        }

        uint64_t remainingBytes = dataLength;
        uint32_t currentCluster = firstCluster;
        std::unordered_set<uint32_t> visited;
        bool chainValid = true;

        for (uint64_t clusterIndex = 0; clusterIndex < neededClusters; ++clusterIndex) {
            if (currentCluster < 2 || currentCluster > maxCluster ||
                !visited.insert(currentCluster).second) {
                chainValid = false;
                break;
            }

            const uint64_t extentOffset =
                dataRegionStart + static_cast<uint64_t>(currentCluster - 2) * bytesPerCluster;
            const uint64_t extentLength = std::min<uint64_t>(bytesPerCluster, remainingBytes);
            if (extentOffset > volumeSizeBytes ||
                extentLength > volumeSizeBytes - extentOffset) {
                chainValid = false;
                break;
            }

            entry.extents.push_back({extentOffset, extentLength});
            entry.clusterChain.push_back(currentCluster);
            entry.clusters.push_back(currentCluster);
            remainingBytes -= extentLength;
            if (remainingBytes == 0)
                break;

            if (noFatChain) {
                // The stream explicitly says this allocation is contiguous.
                currentCluster = firstCluster + static_cast<uint32_t>(clusterIndex) + 1U;
                continue;
            }

            uint32_t nextCluster = 0;
            if (!readFatEntry(currentCluster, nextCluster)) {
                chainValid = false;
                break;
            }
            if (nextCluster >= 0xFFFFFFF8U && nextCluster <= 0xFFFFFFFFU) {
                if (remainingBytes != 0)
                    chainValid = false;
                break;
            }
            if (nextCluster < 2 || nextCluster == 0xFFFFFFF7U ||
                (nextCluster >= 0xFFFFFFF0U && nextCluster <= 0xFFFFFFF6U) ||
                nextCluster > maxCluster ||
                visited.find(nextCluster) != visited.end()) {
                chainValid = false;
                break;
            }
            currentCluster = nextCluster;
        }

        if (remainingBytes != 0)
            chainValid = false;

        if (chainValid) {
            entry.isValid = true;
            entry.dataOffset = dataRegionStart +
                static_cast<uint64_t>(firstCluster - 2) * bytesPerCluster;
        } else {
            entry.extents.clear();
            entry.clusterChain.clear();
            entry.clusters.clear();
            entry.dataOffset = 0;
            entry.isValid = false;
        }

        results.push_back(entry);
        offset += setSize;
    }

    return results;
}
std::vector<FileEntry> FileScanner::scanDeleted(const std::string& physicalPath)
{
    std::vector<FileEntry> results;

    // IMPORTANT: Open WITHOUT FILE_FLAG_NO_BUFFERING to avoid corruption
    // NO_BUFFERING requires sector-aligned memory which std::vector doesn't guarantee
    HANDLE hDrive = CreateFileA(
        physicalPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        0, NULL);  // NO FILE_FLAG_NO_BUFFERING - this prevents corruption!

    if (hDrive == INVALID_HANDLE_VALUE) return results;

    uint8_t fs = detectFilesystem(hDrive);
    if (fs == 32)      results = parseFAT32Deleted(hDrive);
    else if (fs == 64) results = parseExFATDeleted(hDrive);

    CloseHandle(hDrive);
    return results;
}
// ─── Combined scan ─────────────────────────────────────────

std::vector<FileEntry> FileScanner::scanAll(
    const std::string& driveLetter,
    const std::string& physicalPath)
{
    // Existing files
    auto results = scanExisting(driveLetter);

    // Open physical drive for raw read - WITHOUT FILE_FLAG_NO_BUFFERING
    HANDLE hDrive = CreateFileA(
        physicalPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        0, NULL);  // NO FILE_FLAG_NO_BUFFERING - prevents corruption!

    if (hDrive != INVALID_HANDLE_VALUE) {
        uint8_t fs = detectFilesystem(hDrive);

        std::vector<FileEntry> deleted;
        if (fs == 32)      deleted = parseFAT32Deleted(hDrive);
        else if (fs == 64) deleted = parseExFATDeleted(hDrive);

        for (auto& d : deleted) results.push_back(d);
        CloseHandle(hDrive);
    }

    return results;
}