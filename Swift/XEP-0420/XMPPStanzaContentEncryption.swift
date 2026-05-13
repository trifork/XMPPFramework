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
    func encryptEnvelopeXML(_ envelopeXML: String, for message: XMPPMessage, completion: @escaping (XMLElement?) -> Void)
    func decryptEnvelopeXML(from message: XMPPMessage, completion: @escaping (String?) -> Void)
    func verifyAffixElements(in envelope: XMLElement, from message: XMPPMessage) -> Bool
}

@objc public protocol XMPPStanzaContentEncryptionDelegate: NSObjectProtocol {
    @objc optional func xmppStanzaContentEncryption(_ encryption: XMPPStanzaContentEncryption, didReceiveEncryptedMessage encryptedMessage: XMPPMessage)
}

extension GCDMulticastDelegate: XMPPStanzaContentEncryptionDelegate {}

/// A module implementing XMPP stanza content encryption specification as defined in [XEP-0420 version 0.4.1](https://xmpp.org/extensions/attic/xep-0420-0.4.1.html).
public class XMPPStanzaContentEncryption: XMPPModule {
    private let encryptedElementsNamespace: String
    
    public init(encryptedElementsNamespace: String, dispatchQueue: DispatchQueue? = nil) {
        self.encryptedElementsNamespace = encryptedElementsNamespace
        super.init(dispatchQueue: dispatchQueue)
    }
}

// Override hooks
public extension XMPPStanzaContentEncryption {
    
    /// - Note: Applications that rely on server processed elements not mentioned in the XEP will need to override this logic.
    @objc func shouldIgnoreElementOutsideEnvelope(_ elementOutsideEnvelope: XMLElement) -> Bool {
        elementOutsideEnvelope.xmlns != encryptedElementsNamespace && !elementOutsideEnvelope.isServerProcessed
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
        // Furthermore the receiving client MUST ignore any extension elements considered as sensitive which are found outside of the <envelope/> element, especially as direct unencrypted child elements of the enclosing stanza.
        message.removeElementsRecursive(withPredicate: shouldIgnoreElementOutsideEnvelope(_:))
        return message
    }
    
    public func xmppStream(_ sender: XMPPStream, didReceive message: XMPPMessage) {
        if !message.elements(forXmlns: encryptedElementsNamespace).isEmpty {
            // The recipient of the message decrypts its encrypted payload.
            multicast.invoke(ofType: XMPPStanzaContentEncryptionDelegate.self) { multicast in
                // This should eventually lead to XMPPStanzaContentEncryptionProfileDelegate callback invocation
                multicast.xmppStanzaContentEncryption!(self, didReceiveEncryptedMessage: message)
            }
        }
    }
}

extension XMPPStanzaContentEncryption: XMPPStanzaContentEncryptionProfileDelegate {
    public func xmppStanzaContentEncryptionProfile(_ profile: XMPPStanzaContentEncryptionProfileAbs, didPrepareEncryptedElement encryptedElement: XMLElement, for message: XMPPMessage) {
        guard let xmppStream else {
            assertionFailure("Stream not ready to send")
            return
        }
        
        // The result is appended to the message.
        message.addChild(encryptedElement)
        
        // Since the outer message element does not contain a <body/> element the sender appends an unencrypted <store/> hint as specified in Message Processing Hints (XEP-0334) [7].
        message.addStorageHint(.store)
        
        // The message can then be sent to the recipient.
        xmppStream.send(message)
    }
}

private extension XMLElement {
    func removeElementsRecursive(withPredicate shouldBeRemoved: (XMLElement) -> Bool) {
        guard let childrenIndices = children?.indices else { return }
        for childIndex in childrenIndices.reversed() {
            guard let element = child(at: UInt(childIndex)) as? XMLElement else { continue }
            guard shouldBeRemoved(element) else {
                element.removeElementsRecursive(withPredicate: shouldBeRemoved)
                continue
            }
            removeChild(at: UInt(childIndex))
        }
    }
}
