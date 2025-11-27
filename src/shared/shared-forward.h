/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* IWYU pragma: always_keep */

#include "sd-forward.h"         /* IWYU pragma: export */

typedef int (*copy_progress_bytes_t)(uint64_t n_bytes, uint64_t bytes_per_second, void *userdata);
typedef int (*copy_progress_path_t)(const char *path, const struct stat *st, void *userdata);

struct local_address;
struct in_addr_prefix;
struct in_addr_full;

typedef enum AskPasswordFlags AskPasswordFlags;
typedef enum BootEntryTokenType BootEntryTokenType;
typedef enum BusPrintPropertyFlags BusPrintPropertyFlags;
typedef enum BusTransport BusTransport;
typedef enum CatFlags CatFlags;
typedef enum CertificateSourceType CertificateSourceType;
typedef enum DnsAnswerFlags DnsAnswerFlags;
typedef enum DnsCacheMode DnsCacheMode;
typedef enum DnsOverTlsMode DnsOverTlsMode;
typedef enum DnsProtocol DnsProtocol;
typedef enum DnssecMode DnssecMode;
typedef enum Fido2EnrollFlags Fido2EnrollFlags;
typedef enum KeySourceType KeySourceType;
typedef enum LabelFixFlags LabelFixFlags;
typedef enum MountInNamespaceFlags MountInNamespaceFlags;
typedef enum NamePolicy NamePolicy;
typedef enum OutputFlags OutputFlags;
typedef enum OutputMode OutputMode;
typedef enum PagerFlags PagerFlags;
typedef enum PatternCompileCase PatternCompileCase;
typedef enum RemoveFlags RemoveFlags;
typedef enum ResolveSupport ResolveSupport;
typedef enum TPM2Flags TPM2Flags;
typedef enum Tpm2Support Tpm2Support;
typedef enum Tpm2UserspaceEventType Tpm2UserspaceEventType;
typedef enum UnitFileFlags UnitFileFlags;
typedef enum UnitFilePresetMode UnitFilePresetMode;
typedef enum UnitFileState UnitFileState;
typedef enum UserDBFlags UserDBFlags;
typedef enum UserRecordLoadFlags UserRecordLoadFlags;
typedef enum UserStorage UserStorage;

typedef struct Bitmap Bitmap;
typedef struct BootConfig BootConfig;
typedef struct BPFProgram BPFProgram;
typedef struct BusObjectImplementation BusObjectImplementation;
typedef struct CalendarSpec CalendarSpec;
typedef struct Condition Condition;
typedef struct ConfigSection ConfigSection;
typedef struct ConfigTableItem ConfigTableItem;
typedef struct CPUSet CPUSet;
typedef struct DissectedImage DissectedImage;
typedef struct DnsAnswer DnsAnswer;
typedef struct DnsPacket DnsPacket;
typedef struct DnsQuestion DnsQuestion;
typedef struct DnsResourceKey DnsResourceKey;
typedef struct DnsResourceRecord DnsResourceRecord;
typedef struct DnsSvcParam DnsSvcParam;
typedef struct DnsTxtItem DnsTxtItem;
typedef struct FDSet FDSet;
typedef struct Fido2HmacSalt Fido2HmacSalt;
typedef struct GroupRecord GroupRecord;
typedef struct Image Image;
typedef struct ImageFilter ImageFilter;
typedef struct ImagePolicy ImagePolicy;
typedef struct InstallChange InstallChange;
typedef struct InstallInfo InstallInfo;
typedef struct LookupPaths LookupPaths;
typedef struct LoopDevice LoopDevice;
typedef struct MachineBindUserContext MachineBindUserContext;
typedef struct MachineCredentialContext MachineCredentialContext;
typedef struct MountOptions MountOptions;
typedef struct MStack MStack;
typedef struct OpenFile OpenFile;
typedef struct Pkcs11EncryptedKey Pkcs11EncryptedKey;
typedef struct Table Table;
typedef struct Tpm2Context Tpm2Context;
typedef struct Tpm2Handle Tpm2Handle;
typedef struct Tpm2PCRValue Tpm2PCRValue;
typedef struct UnitInfo UnitInfo;
typedef struct UserRecord UserRecord;
typedef struct VeritySettings VeritySettings;
