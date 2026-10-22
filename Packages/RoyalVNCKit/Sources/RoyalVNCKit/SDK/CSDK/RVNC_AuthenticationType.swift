#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import RoyalVNCKitC

extension RVNC_AUTHENTICATIONTYPE {
    var swiftVNCAuthenticationType: VNCAuthenticationType {
        switch self {
            case RVNC_AUTHENTICATIONTYPE_VNC:
                .vnc
            case RVNC_AUTHENTICATIONTYPE_APPLEREMOTEDESKTOP:
                .appleRemoteDesktop
            case RVNC_AUTHENTICATIONTYPE_ULTRAVNCMSLOGONII:
                .ultraVNCMSLogonII
            case RVNC_AUTHENTICATIONTYPE_RSAAES:
                .rsaAES
            default:
                fatalError("Unknown authentication type: \(self)")
        }
    }
}

extension VNCAuthenticationType {
    var cVNCAuthenticationType: RVNC_AUTHENTICATIONTYPE {
        switch self {
            case .vnc:
                RVNC_AUTHENTICATIONTYPE_VNC
            case .appleRemoteDesktop:
                RVNC_AUTHENTICATIONTYPE_APPLEREMOTEDESKTOP
            case .ultraVNCMSLogonII:
                RVNC_AUTHENTICATIONTYPE_ULTRAVNCMSLOGONII
            case .rsaAES:
                RVNC_AUTHENTICATIONTYPE_RSAAES
        }
    }
}

@_cdecl("rvnc_authentication_type_requires_username")
@_spi(RoyalVNCKitC)
@available(*, unavailable)
public func rvnc_authentication_type_requires_username(_ authenticationType: RVNC_AUTHENTICATIONTYPE) -> Bool {
    let authenticationTypeSwift = authenticationType.swiftVNCAuthenticationType

    return authenticationTypeSwift.requiresUsername
}

@_cdecl("rvnc_authentication_type_requires_password")
@_spi(RoyalVNCKitC)
@available(*, unavailable)
public func rvnc_authentication_type_requires_password(_ authenticationType: RVNC_AUTHENTICATIONTYPE) -> Bool {
    let authenticationTypeSwift = authenticationType.swiftVNCAuthenticationType

    return authenticationTypeSwift.requiresPassword
}
