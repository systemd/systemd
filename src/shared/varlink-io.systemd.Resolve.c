/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolve-util.h"
#include "varlink-io.systemd.Resolve.h"

SD_VARLINK_DEFINE_ENUM_TYPE(
                DNSProtocol,
                SD_VARLINK_FIELD_COMMENT("DNS"),
                SD_VARLINK_DEFINE_ENUM_VALUE(dns),
                SD_VARLINK_FIELD_COMMENT("Multicast DNS"),
                SD_VARLINK_DEFINE_ENUM_VALUE(mdns),
                SD_VARLINK_FIELD_COMMENT("LLMNR"),
                SD_VARLINK_DEFINE_ENUM_VALUE(llmnr));

SD_VARLINK_DEFINE_ENUM_TYPE(
                DNSOverTLSMode,
                SD_VARLINK_FIELD_COMMENT("DNSOverTLS is disabled."),
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_FIELD_COMMENT("DNSOverTLS is enabled."),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_FIELD_COMMENT("Try to use DNSOverTLS, but disabled when the server does not support it."),
                SD_VARLINK_DEFINE_ENUM_VALUE(opportunistic));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ResolveSupport,
                SD_VARLINK_FIELD_COMMENT("The protocol is disabled."),
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_FIELD_COMMENT("The protocol is enabled."),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_FIELD_COMMENT("The protocol is used only for resolving."),
                SD_VARLINK_DEFINE_ENUM_VALUE(resolve));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ResolvConfMode,
                SD_VARLINK_FIELD_COMMENT("/etc/resolv.conf is a symbolic link to "PRIVATE_UPLINK_RESOLV_CONF"."),
                SD_VARLINK_DEFINE_ENUM_VALUE(uplink),
                SD_VARLINK_FIELD_COMMENT("/etc/resolv.conf is a symbolic link to "PRIVATE_STUB_RESOLV_CONF"."),
                SD_VARLINK_DEFINE_ENUM_VALUE(stub),
                SD_VARLINK_FIELD_COMMENT("/etc/resolv.conf is a symbolic link to "PRIVATE_STATIC_RESOLV_CONF"."),
                SD_VARLINK_DEFINE_ENUM_VALUE(static),
                SD_VARLINK_FIELD_COMMENT("/etc/resolv.conf does not exist."),
                SD_VARLINK_DEFINE_ENUM_VALUE(missing),
                SD_VARLINK_FIELD_COMMENT("/etc/resolv.conf is not managed by systemd-resolved."),
                SD_VARLINK_DEFINE_ENUM_VALUE(foreign));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceKey,
                SD_VARLINK_FIELD_COMMENT("The RR class, almost always IN, i.e 0x01. If unspecified defaults to IN."),
                SD_VARLINK_DEFINE_FIELD(class, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The RR types, one of A, AAAA, PTR, …"),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The domain name."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResourceRecord,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(key, ResourceKey, 0),
                SD_VARLINK_DEFINE_FIELD(priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(weight, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(cpu, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(os, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(items, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(mname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(rname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(serial, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(refresh, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(expire, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(minimum, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(exchange, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(version, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(size, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(horiz_pre, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(vert_pre, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(latitude, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(longitude, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(altitude, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(keyTag, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(algorithm, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(digestType, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(digest, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(fptype, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(fingerprint, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(protocol, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(dnskey, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(signer, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(typeCovered, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(labels, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(originalTtl, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(expiration, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(inception, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(signature, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(nextDomain, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(types, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(iterations, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(salt, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(hash, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(certUsage, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(selector, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(matchingType, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(data, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(tag, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(target, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                /* This field is retired */
                /* SD_VARLINK_DEFINE_FIELD(params, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY), */
                SD_VARLINK_DEFINE_FIELD(svcparams, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(order, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(preference, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(naptrFlags, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(services, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(regexp, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(replacement, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedAddress,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                ResolveHostname,
                SD_VARLINK_FIELD_COMMENT("The Linux interface index for the network interface to search on. Typically left unspecified, in order to search on all interfaces."),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The host name to resolve."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The address family to search for, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_INPUT(family, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Various search flags."),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of resolved IP addresses"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(addresses, ResolvedAddress, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Canonical name of the host."),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Various flags indicating details on discovered data."),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedName,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BrowseServiceUpdateFlag,
                SD_VARLINK_FIELD_COMMENT("Indicates that the service was added."),
                SD_VARLINK_DEFINE_ENUM_VALUE(added),
                SD_VARLINK_FIELD_COMMENT("Indicates that the service was removed."),
                SD_VARLINK_DEFINE_ENUM_VALUE(removed));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ServiceData,
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(updateFlag, BrowseServiceUpdateFlag, 0),
                SD_VARLINK_FIELD_COMMENT("The address family of the service, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The name of the service, e.g., 'My Service'. May be null if not specified."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The type of service, e.g., '_http._tcp'."),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The domain in which the service resides, e.g., 'local'."),
                SD_VARLINK_DEFINE_FIELD(domain, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The Linux interface index for the network interface associated with this service."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResolveAddress,
                SD_VARLINK_FIELD_COMMENT("The Linux interface index for the network interface to search on. Typically left unspecified, in order to search on all interfaces."),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The address family of the specified address, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_INPUT(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The IP address to look up, either 4 or 16 integers (depending if an AF_INET or AF_INET6 address shall be resolved)."),
                SD_VARLINK_DEFINE_INPUT(address, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(names, ResolvedName, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedService,
                SD_VARLINK_DEFINE_FIELD(priority, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(weight, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(hostname, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(canonicalName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(addresses, ResolvedAddress, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedCanonical,
                SD_VARLINK_FIELD_COMMENT("The DNS-SD name of the service. For simple SRV services this field is absent or null."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(domain, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ResolveService,
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(domain, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(family, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(services, ResolvedService, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(txt, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(canonical, ResolvedCanonical, 0),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ResolvedRecord,
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(rr, ResourceRecord, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(raw, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                DNSServer,
                SD_VARLINK_FIELD_COMMENT("IPv4 or IPv6 address of the server."),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("IPv4 or IPv6 address of the server, formatted as a human-readable string."),
                SD_VARLINK_DEFINE_FIELD(addressString, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Address family of the server, one of AF_INET or AF_INET6."),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Port number of the server."),
                SD_VARLINK_DEFINE_FIELD(port, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Interface index for which this server is configured."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Server Name Indication (SNI) of the server."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates if the DNS server is accessible or not."),
                SD_VARLINK_DEFINE_FIELD(accessible, SD_VARLINK_BOOL, 0));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                SearchDomain,
                SD_VARLINK_FIELD_COMMENT("Domain name."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Indicates whether or not this is a routing-only domain."),
                SD_VARLINK_DEFINE_FIELD(routeOnly, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Interface index for which this search domain is configured."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                DNSScope,
                SD_VARLINK_FIELD_COMMENT("Protocol associated with this scope."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(protocol, DNSProtocol, 0),
                SD_VARLINK_FIELD_COMMENT("Address family associated with this scope."),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Interface index associated with this scope."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Interface name associated with this scope."),
                SD_VARLINK_DEFINE_FIELD(ifname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("DNSSEC mode associated with this scope."),
                SD_VARLINK_DEFINE_FIELD(dnssec, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("DNSOverTLS mode associated with this scope."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(dnsOverTLS, DNSOverTLSMode, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                DNSConfiguration,
                SD_VARLINK_FIELD_COMMENT("Interface name, if any, associated with this configuration. Empty for global configuration."),
                SD_VARLINK_DEFINE_FIELD(ifname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Interface index, if any, associated with this configuration. Empty for global configuration."),
                SD_VARLINK_DEFINE_FIELD(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Delegate name, if any, associated with this configuration. Empty for global or link configurations."),
                SD_VARLINK_DEFINE_FIELD(delegate, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates whether or not this link's DNS servers will be used for resolving domain names that do not match any link's configured domains."),
                SD_VARLINK_DEFINE_FIELD(defaultRoute, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("DNS server currently selected to use for lookups."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(currentServer, DNSServer, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of configured DNS servers."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(servers, DNSServer, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of configured fallback DNS servers, set for global configuration only."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(fallbackServers, DNSServer, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of configured search domains."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(searchDomains, SearchDomain, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of configured DNSSEC negative trust anchors."),
                SD_VARLINK_DEFINE_FIELD(negativeTrustAnchors, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("DNSSEC mode."),
                SD_VARLINK_DEFINE_FIELD(dnssec, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Indicates if the current DNS server supports DNSSEC. Always false if DNSSEC mode is \"no\"."),
                SD_VARLINK_DEFINE_FIELD(dnssecSupported, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("DNSOverTLS mode."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(dnsOverTLS, DNSOverTLSMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("LLMNR support."),
                //SD_VARLINK_DEFINE_FIELD_BY_TYPE(llmnr, ResolveSupport, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(llmnr, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("mDNS support."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(mDNS, ResolveSupport, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("resolv.conf mode, set for global configuration only."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(resolvConfMode, ResolvConfMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of current DNS scopes."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(scopes, DNSScope, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ResolveRecord,
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(class, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(type, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(rrs, ResolvedRecord, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_OUTPUT(flags, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                BrowseServices,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("The domain to browse for services. If null, the default browsing domain local is used."),
                SD_VARLINK_DEFINE_INPUT(domain, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The service type to browse for (e.g., '_http._tcp')."),
                SD_VARLINK_DEFINE_INPUT(type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The Linux interface index for the network interface to search on."),
                SD_VARLINK_DEFINE_INPUT(ifindex, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Various browsing flags to modify the operation."),
                SD_VARLINK_DEFINE_INPUT(flags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An array of service data containing information about discovered services."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(browserServiceData, ServiceData, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                DumpDNSConfiguration,
                SD_VARLINK_FIELD_COMMENT("The current global and per-interface DNS configurations"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(configuration, DNSConfiguration, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoNameServers);
static SD_VARLINK_DEFINE_ERROR(NoSuchResourceRecord);
static SD_VARLINK_DEFINE_ERROR(QueryTimedOut);
static SD_VARLINK_DEFINE_ERROR(MaxAttemptsReached);
static SD_VARLINK_DEFINE_ERROR(InvalidReply);
static SD_VARLINK_DEFINE_ERROR(QueryAborted);
static SD_VARLINK_DEFINE_ERROR(QueryRefused);
static SD_VARLINK_DEFINE_ERROR(
                DNSSECValidationFailed,
                SD_VARLINK_DEFINE_FIELD(result, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorMessage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(NoTrustAnchor);
static SD_VARLINK_DEFINE_ERROR(ResourceRecordTypeUnsupported);
static SD_VARLINK_DEFINE_ERROR(NetworkDown);
static SD_VARLINK_DEFINE_ERROR(NoSource);
static SD_VARLINK_DEFINE_ERROR(StubLoop);
static SD_VARLINK_DEFINE_ERROR(
                DNSError,
                SD_VARLINK_DEFINE_FIELD(rcode, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(extendedDNSErrorMessage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));
static SD_VARLINK_DEFINE_ERROR(CNAMELoop);
static SD_VARLINK_DEFINE_ERROR(BadAddressSize);
static SD_VARLINK_DEFINE_ERROR(ResourceRecordTypeInvalidForQuery);
static SD_VARLINK_DEFINE_ERROR(ZoneTransfersNotPermitted);
static SD_VARLINK_DEFINE_ERROR(ResourceRecordTypeObsolete);
static SD_VARLINK_DEFINE_ERROR(InconsistentServiceRecords);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Resolve,
                "io.systemd.Resolve",
                SD_VARLINK_SYMBOL_COMMENT("Resolves a hostname to one or more IP addresses."),
                &vl_method_ResolveHostname,
                SD_VARLINK_SYMBOL_COMMENT("Resolves an IP address to a hostname."),
                &vl_method_ResolveAddress,
                SD_VARLINK_SYMBOL_COMMENT("Resolves a named DNS-SD or unnamed simple SRV service."),
                &vl_method_ResolveService,
                SD_VARLINK_SYMBOL_COMMENT("Resolves a domain name to one or more DNS resource records."),
                &vl_method_ResolveRecord,
                SD_VARLINK_SYMBOL_COMMENT("Starts browsing for DNS-SD services of specified type."),
                &vl_method_BrowseServices,
                SD_VARLINK_SYMBOL_COMMENT("Current global and per-link DNS configurations."),
                &vl_method_DumpDNSConfiguration,
                SD_VARLINK_SYMBOL_COMMENT("The type of protocol."),
                &vl_type_DNSProtocol,
                SD_VARLINK_SYMBOL_COMMENT("The mode of DNSOverTLS."),
                &vl_type_DNSOverTLSMode,
                SD_VARLINK_SYMBOL_COMMENT("Whether the protocol is enabled."),
                &vl_type_ResolveSupport,
                SD_VARLINK_SYMBOL_COMMENT("The management mode of /etc/resolve.conf file."),
                &vl_type_ResolvConfMode,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a resolved address."),
                &vl_type_ResolvedAddress,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a resolved host name."),
                &vl_type_ResolvedName,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates resolved service information."),
                &vl_type_ResolvedService,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates the canonical name, type and domain of a DNS-SD or simple SRV service. Note that due to CNAME redirections and similar, a named DNS-SD service might resolve to a canonical service that is an unnamed simple SRV service. Or in other words: resolving a named service might return an unnamed canonical service."),
                &vl_type_ResolvedCanonical,
                SD_VARLINK_SYMBOL_COMMENT("The 'key' part of a DNS resource record."),
                &vl_type_ResourceKey,
                SD_VARLINK_SYMBOL_COMMENT("A full DNS resource record.."),
                &vl_type_ResourceRecord,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates information about a resolved DNS resource record "),
                &vl_type_ResolvedRecord,
                SD_VARLINK_SYMBOL_COMMENT("Describes the update flag for browsing services, indicating whether a service was added or removed during browsing."),
                &vl_type_BrowseServiceUpdateFlag,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates the service data obtained from browsing."),
                &vl_type_ServiceData,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a DNS server address specification."),
                &vl_type_DNSServer,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a search domain specification."),
                &vl_type_SearchDomain,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a global or per-link DNS configuration, including configured DNS servers, search domains, and more."),
                &vl_type_DNSConfiguration,
                SD_VARLINK_SYMBOL_COMMENT("Encapsulates a DNS scope specification."),
                &vl_type_DNSScope,
                &vl_error_NoNameServers,
                &vl_error_NoSuchResourceRecord,
                &vl_error_QueryTimedOut,
                &vl_error_MaxAttemptsReached,
                &vl_error_InvalidReply,
                &vl_error_QueryAborted,
                &vl_error_QueryRefused,
                &vl_error_DNSSECValidationFailed,
                &vl_error_NoTrustAnchor,
                &vl_error_ResourceRecordTypeUnsupported,
                &vl_error_NetworkDown,
                &vl_error_NoSource,
                &vl_error_StubLoop,
                &vl_error_DNSError,
                &vl_error_CNAMELoop,
                &vl_error_BadAddressSize,
                &vl_error_ResourceRecordTypeInvalidForQuery,
                &vl_error_ZoneTransfersNotPermitted,
                &vl_error_ResourceRecordTypeObsolete,
                SD_VARLINK_SYMBOL_COMMENT("The DNS resource records of the specified service are not consistent (e.g. lacks a DNS-SD service type when resolved)."),
                &vl_error_InconsistentServiceRecords);
