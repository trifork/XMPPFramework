//
//  XMPPStanzaContentEncryption.swift
//  XMPPFramework
//
//  Created by Piotr Wegrzynek on 18/07/2025.
//

#if canImport(XMPPFramework)
import XMPPFramework
#endif

public protocol XMPPStanzaContentEncryptionProfile {
    func addAffixElemenets(to envelope: XMLElement, for message: XMPPMessage) -> XMLElement
    func encryptEnvelopeXML(_ envelopeXML: String, for message: XMPPMessage, completion: @escaping (XMPPMessage, XMLElement?) -> Void)
    func decryptEnvelopeXML(from message: XMPPMessage, completion: @escaping (String?) -> Void)
    func verifyAffixElements(in envelope: XMLElement, from message: XMPPMessage) -> Bool
}

@objc public protocol XMPPStanzaContentEncryptionDelegate: NSObjectProtocol {
    @objc optional func stanzaContentEncryption(_ encryption: XMPPStanzaContentEncryption, didReceiveEnvelope: XMLElement, in message: XMPPMessage)
    @objc optional func stanzaContentEncryption(_ encryption: XMPPStanzaContentEncryption, didFailToReceiveEnvelopeIn message: XMPPMessage)
}

extension GCDMulticastDelegate: XMPPStanzaContentEncryptionDelegate {}

/// A module implementing XMPP stanza content encryption specification as defined in [XEP-0420 version 0.4.1](https://xmpp.org/extensions/attic/xep-0420-0.4.1.html).
public class XMPPStanzaContentEncryption: XMPPModule {
    private let profile: XMPPStanzaContentEncryptionProfile
    
    public init(profile: XMPPStanzaContentEncryptionProfile, dispatchQueue: DispatchQueue? = nil) {
        self.profile = profile
        super.init(dispatchQueue: dispatchQueue)
    }
    
    public func sendEncryptedMessage(withSensitiveContent sensitiveContent: [XMLElement], to: XMPPJID, messageType: XMPPMessage.MessageType? = nil, elementId: String? = nil) {
            
    }
}

extension XMPPStanzaContentEncryption: XMPPStreamDelegate {
    
}
