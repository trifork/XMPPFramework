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
        performBlock {
            let outgoingMessage = XMPPMessage(messageType: messageType, to: to, elementID: elementId)
            
            // TODO: Allow modifying sensitiveContent via multidelegation
            
            // In order to send an encrypted message without leaking extension elements, the sender prepares the message by placing the sensitive extension elements inside a <content/> element and that inside an <envelope/> element.
            let envelope = XMPPElement.makeStanzaContentEncryptionEnvelope()
            envelope.withStanzaContentEncryptionEnvelopeContent { content in
                for sensitiveElement in sensitiveContent {
                    guard let name = sensitiveElement.name, sensitiveElement.xmlns != nil else {
                        // Elements in the <content/> element MUST be identified using an element name and namespace.
                        assertionFailure("Encountered element without name or namespace in <content/> element")
                        continue
                    }
                    content.addChild(sensitiveElement)
                }
            }
            
            // Depending on the encryption-specific SCE-profile, some affix elements are added as child elements of the <envelope/> element.
            let finalEnvelope = self.profile.addAffixElemenets(to: envelope, for: outgoingMessage)
            
            // The <envelope/> element is then serialized into XML and encrypted using the SCE-specific profile of the encryption mechanism in place.
            self.profile.encryptEnvelopeXML(finalEnvelope.xmlString, for: outgoingMessage) { finalOutgoingMessage, encrypted in
                guard let encrypted else { return }
                
                // The result is appended to the message.
                finalOutgoingMessage.addChild(encrypted)
                
                // Since the outer message element does not contain a <body/> element the sender appends an unencrypted <store/> hint as specified in Message Processing Hints (XEP-0334) [7].
                finalOutgoingMessage.addStorageHint(.store)
                
                // The message can then be sent to the recipient.
                self.performBlock { self.xmppStream?.send(finalOutgoingMessage) }
            }
        }
    }
}

extension XMPPStanzaContentEncryption: XMPPStreamDelegate {
    public func xmppStream(_ sender: XMPPStream, willSend message: XMPPMessage) -> XMPPMessage? {
        // Unencrypted <envelope/> elements are NOT ALLOWED as child elements of the stanza and MUST be dropped.
        assert(message.element(forName: "envelope") == nil, "Encountered unencrypted <envelope/> child element in outgoing message")
        message.removeElements(forName: "envelope")
        
        return message
    }
    
}
