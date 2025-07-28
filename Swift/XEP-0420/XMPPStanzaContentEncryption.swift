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
    /// - Note: The implementation may modify the provided message before invoking the completion handler, for example to assign some stanza identifier for later processing.
    func encryptEnvelopeXML(_ envelopeXML: String, for message: XMPPMessage, completion: @escaping (XMLElement?) -> Void)
    /// - Note:
    /// The implementation may modify the provided message, for example to assign some stanza identifier for later processing.
    /// However, in order to maintain message processing pipeline consistency, any modifications have to be performed before returning from the method.
    func decryptEnvelopeXML(from message: XMPPMessage, completion: @escaping (String?) -> Void)
    func verifyAffixElements(in envelope: XMLElement, from message: XMPPMessage) -> Bool
}

@objc public protocol XMPPStanzaContentEncryptionDelegate: NSObjectProtocol {
    @objc optional func stanzaContentEncryption(_ encryption: XMPPStanzaContentEncryption, didDecryptEnvelope: XMLElement, from message: XMPPMessage)
    @objc optional func stanzaContentEncryption(_ encryption: XMPPStanzaContentEncryption, didFailToDecryptEnvelopeFrom message: XMPPMessage)
}

extension GCDMulticastDelegate: XMPPStanzaContentEncryptionDelegate {}

/// A module implementing XMPP stanza content encryption specification as defined in [XEP-0420 version 0.4.1](https://xmpp.org/extensions/attic/xep-0420-0.4.1.html).
public class XMPPStanzaContentEncryption: XMPPModule {
    private let profile: XMPPStanzaContentEncryptionProfile
    private var serverProcessedElements = XMPPStanzaContentEncryptionServerProcessedElements()
    
    public var serverProcessedElementsList: [XMPPStanzaContentEncryptionServerProcessedElements.Entry] {
        get { serverProcessedElements.list }
        set { serverProcessedElements.list = newValue }
    }
    
    public init(profile: XMPPStanzaContentEncryptionProfile, dispatchQueue: DispatchQueue? = nil) {
        self.profile = profile
        super.init(dispatchQueue: dispatchQueue)
    }
    
    // https://xmpp.org/extensions/xep-0420.html#sending
    public func sendEncryptedMessage(_ message: XMPPMessage, withSensitiveContent sensitiveContent: [XMLElement]) {
        performBlock(async: true) {
            // TODO: Allow modifying sensitiveContent via multidelegation
            
            // In order to send an encrypted message without leaking extension elements, the sender prepares the message by placing the sensitive extension elements inside a <content/> element and that inside an <envelope/> element.
            let envelope = XMPPElement.makeStanzaContentEncryptionEnvelope()
            let content = XMLElement(name: "content")
            for sensitiveElement in sensitiveContent {
                guard sensitiveElement.name != nil, sensitiveElement.xmlns != nil else {
                    // Elements in the <content/> element MUST be identified using an element name and namespace.
                    assertionFailure("Encountered element without name or namespace in <content/> element")
                    continue
                }
                content.addChild(sensitiveElement)
            }
            envelope.addChild(content)
            
            // Depending on the encryption-specific SCE-profile, some affix elements are added as child elements of the <envelope/> element.
            let finalEnvelope = self.profile.addAffixElemenets(to: envelope, for: message)
            
            // The <envelope/> element is then serialized into XML and encrypted using the SCE-specific profile of the encryption mechanism in place.
            self.profile.encryptEnvelopeXML(finalEnvelope.xmlString, for: message) { encrypted in
                guard let encrypted else { return }
                
                // The result is appended to the message.
                message.addChild(encrypted)
                
                // Since the outer message element does not contain a <body/> element the sender appends an unencrypted <store/> hint as specified in Message Processing Hints (XEP-0334) [7].
                message.addStorageHint(.store)
                
                // The message can then be sent to the recipient.
                self.performBlock(async: true) { self.xmppStream?.send(message) }
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
    
    public func xmppStream(_ sender: XMPPStream, willReceive message: XMPPMessage) -> XMPPMessage? {
        // The recipient of the message decrypts its encrypted payload.
        profile.decryptEnvelopeXML(from: message) { envelopeXML in
            self.performBlock {
                if let envelopeXML, let decryptedEnvelope = self.receiveEncryptedMessage(message, withEnvelopeXML: envelopeXML) {
                    // The result is the <envelope/> element containing the <content/> element and the affix elements as direct child elements.
                    self.multicast.invoke(ofType: XMPPStanzaContentEncryptionDelegate.self) { multicast in
                        multicast.stanzaContentEncryption?(self, didDecryptEnvelope: decryptedEnvelope, from: message)
                    }
                } else {
                    self.multicast.invoke(ofType: XMPPStanzaContentEncryptionDelegate.self) { multicast in
                        multicast.stanzaContentEncryption?(self, didFailToDecryptEnvelopeFrom: message)
                    }
                }
            }
        }

        serverProcessedElements.removeIgnoredElementsOutsideEnvelope(fromMessage: message)
        
        return message
    }
    
    // https://xmpp.org/extensions/xep-0420.html#receiving
    private func receiveEncryptedMessage(_ encryptedMessage: XMPPMessage, withEnvelopeXML envelopeXML: String) -> XMLElement? {
        // The recipient MUST verify that the decrypted <envelope/> element contains valid XML before processing it any further. Invalid XML must be rejected.
        guard let decryptedEnvelope = try? XMLElement(xmlString: envelopeXML), decryptedEnvelope.isStanzaContentEncryptionEnvelope else {
            return nil
        }
        
        // Depending on the affix profiles specified by the used encryption protocol, the affix elements are verified to prevent certain attacks from taking place.
        guard profile.verifyAffixElements(in: decryptedEnvelope, from: encryptedMessage) else {
            return nil
        }
        
        // Afterwards, the extension elements inside the <content/> element are checked against the permitted list and any disallowed elements are discarded.
        serverProcessedElements.removeDisallowedElements(fromEnvelope: decryptedEnvelope)
        
        // The following is not implemented as it contradicts section 11. Implementation Notes, which calls to handle encrypted elements explicitly:
        // As a last step, the original unencrypted stanza is recreated by replacing the <envelope/> element of the stanza with the elements inside of the <content/> element.
        
        return decryptedEnvelope
    }
}

public struct XMPPStanzaContentEncryptionServerProcessedElements {
    public struct Entry {
        public let xmlns: String
        public let elementNames: [String]
        
        public init(xmlns: String, elementNames: [String] = []) {
            self.xmlns = xmlns
            self.elementNames = elementNames
        }
    }
    
    var list = [
        // Message Processing Hints are addressed to the server and MUST therefore be accessible in plaintext.
        Entry(xmlns: "urn:xmpp:hints"),
        // Sending clients MUST NOT include Stanza-ID elements inside the <envelope/> element, as this would prevent the server from filtering it.
        Entry(xmlns: XMPPStanzaIdXmlns, elementNames: [XMPPStanzaIdElementName, XMPPOriginIdElementName]),
        // The server MUST be able to access the <addresses/> and <address/> elements in order to do message routing, so they MUST NOT be encrypted.
        Entry(xmlns: "http://jabber.org/protocol/address"),
    ]
    
    func removeDisallowedElements(fromEnvelope envelope: XMLElement) {
        // After verifying the integrity of the <envelope/> element, the recipient needs to make sure that no server-processed elements are found inside of it
        envelope.element(forName: "content")?.removeAllElements(where: { isServerProcessed($0) })
    }
    
    func removeIgnoredElementsOutsideEnvelope(fromMessage message: XMPPMessage) {
        // Furthermore the receiving client MUST ignore any extension elements considered as sensitive which are found outside of the <envelope/> element, especially as direct unencrypted child elements of the enclosing stanza.
        message.removeAllElements(where: { isSensitive($0) })
    }
    
    // There are certain extension elements which are required to be available to the server in order to do message routing and processing
    // Additionally there are some elements that MUST be filtered by the server.
    // Allowing for those elements to be included in, and parsed from the encrypted payload would allow a malicious client to perform a number of attacks.
    private func isServerProcessed(_ element: XMLElement) -> Bool {
        list.contains(where: { $0.xmlns == element.xmlns && ($0.elementNames.contains(where: { $0 == element.name }) || $0.elementNames.isEmpty) })
    }
    
    // Contrary to this, other elements are considered sensitive and MUST NOT be available in plaintext outside the <envelope/> element.
    private func isSensitive(_ element: XMLElement) -> Bool {
        // The specification does enforce any specific format for encrypted content elements which are not considered sensitive themselves
        // This implementation allows any element named "encrypted" regardless of namespace
        !isServerProcessed(element) && element.name != "encrypted"
    }
}

private extension XMLElement {
    func removeAllElements(where shouldBeRemoved: (XMLElement) -> Bool) {
        guard let childrenIndices = children?.indices else { return }
        for childIndex in childrenIndices.reversed() {
            guard let element = child(at: UInt(childIndex)) as? XMLElement, shouldBeRemoved(element) else { continue }
            removeChild(at: UInt(childIndex))
        }
    }
}
