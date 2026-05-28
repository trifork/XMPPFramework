//
//  XMLElement+XEP_0420.swift
//  XMPPFramework
//
//  Created by Piotr Wegrzynek on 16/07/2025.
//

#if canImport(XMPPFramework)
import XMPPFramework
#endif

extension XMLElement {
    // https://xmpp.org/extensions/xep-0420.html#example-5
    public static func makeStanzaContentEncryptionEnvelope(sensitiveElements: [XMLElement]) -> XMLElement {
        // In order to send an encrypted message without leaking extension elements, the sender prepares the message by placing the sensitive extension elements inside a <content/> element and that inside an <envelope/> element.
        let envelope = XMLElement(name: "envelope", xmlns: "urn:xmpp:sce:1")
        let content = XMLElement(name: "content")
        for sensitiveElement in sensitiveElements {
            guard sensitiveElement.name != nil, sensitiveElement.xmlns != nil else {
                // Elements in the <content/> element MUST be identified using an element name and namespace.
                assertionFailure("Encountered element without name or namespace in <content/> element")
                continue
            }
            content.addChild(sensitiveElement)
        }
        envelope.addChild(content)
        return envelope
    }
    
    /// - Note: Applications that rely on server processed elements not mentioned in the XEP need to apply their own element filtering on top of what unpacking does.
    public func filteredStanzaContentEncryptionEnvelopeContent() -> [XMLElement]? {
        guard isStanzaContentEncryptionEnvelope, let contentChildren = element(forName: "content")?.children else { return [] }
        // After verifying the integrity of the <envelope/> element, the recipient needs to make sure that no server-processed elements are found inside of it
        return contentChildren.compactMap {
            $0 as? XMLElement
        } .filter {
            !$0.isServerProcessed
        }
    }
}

// In order to prevent certain attacks, different affix elements MAY be added as direct child elements of the <envelope/> element.
extension XMLElement {
    // Prevent known ciphertext and message length correlation attacks.
    public func addStanzaContentEncryptionRandomPaddingAffix() {
        addChild(XMLElement(name: "rpad", stringValue: StanzaContentEncryptionPaddingGenerator.randomPadding()))
    }
    
    // Prevent replay attacks using old messages.
    public func addStanzaContentEncryptionTimestampAffix(with date: Date) {
        let affix = XMLElement(name: "time")
        affix.addAttribute(withName: "stamp", stringValue: date.xmppDateTimeString)
        addChild(affix)
    }
    
    // Prevent spoofing of the recipient.
    public func addStanzaContentEncryptionRecipientAffix(with jid: XMPPJID) {
        let affix = XMLElement(name: "to")
        affix.addAttribute(withName: "jid", stringValue: jid.bare)
        addChild(affix)
    }
    
    // Prevent spoofing of the sender.
    public func addStanzaContentEncryptionSenderAffix(with jid: XMPPJID) {
        let affix = XMLElement(name: "from")
        affix.addAttribute(withName: "jid", stringValue: jid.bare)
        addChild(affix)
    }
}

extension XMLElement {
    // Receiving clients MUST check whether the difference between the timestamp and the sending time derived from the stanza itself lays within a reasonable margin.
    // The client SHOULD use the content of the timestamp element when displaying the send date of the message
    public func verifyStanzaContentEncryptionTimestamp(expecting expectedDate: Date, withMargin verificationMargin: TimeInterval = 10) -> Bool {
        guard let affix = stanzaContentEncryptionAffix(named: "time"),
              let stamp = affix.attributeStringValue(forName: "stamp"),
              let actualDate = Date.from(xmppDateTimeString: stamp) else {
            return false
        }
        return abs(actualDate.timeIntervalSince(expectedDate)) <= verificationMargin
    }
    
    // Receiving clients MUST check if the JID matches the to attribute of the enclosing stanza and otherwise alert the user/reject the message
    public func verifyStanzaContentEncryptionRecipient(expecting expectedJID: XMPPJID) -> Bool {
        guard let affix = stanzaContentEncryptionAffix(named: "to"),
              let jid = affix.attributeStringValue(forName: "jid"),
              let actualJID = XMPPJID(string: jid) else {
            return false
        }
        return actualJID.isEqual(to: expectedJID, options: .bare)
    }
    
    // Receiving clients MUST check if the value matches the from attribute of the enclosing stanza and otherwise alert the user/reject the message
    public func verifyStanzaContentEncryptionSender(expecting expectedJID: XMPPJID) -> Bool {
        guard let affix = stanzaContentEncryptionAffix(named: "from"),
              let jid = affix.attributeStringValue(forName: "jid"),
              let actualJID = XMPPJID(string: jid) else {
            return false
        }
        return actualJID.isEqual(to: expectedJID, options: .bare)
    }
    
    private func stanzaContentEncryptionAffix(named affixName: String) -> XMLElement? {
        // XML schema for the extension is undefined as of specification version 0.4.1
        // This implementation requires each verified affix element to appear exactly once in an envelope
        let matchingAffixes = elements(forName: affixName)
        guard matchingAffixes.count == 1, let affix = matchingAffixes.first else {
            return nil
        }
        return affix
    }
}

extension XMLElement {
    var isStanzaContentEncryptionEnvelope: Bool {
        name == "envelope" && xmlns == "urn:xmpp:sce:1"
    }
    
    // There are certain extension elements which are required to be available to the server in order to do message routing and processing
    // Additionally there are some elements that MUST be filtered by the server.
    // Allowing for those elements to be included in, and parsed from the encrypted payload would allow a malicious client to perform a number of attacks.
    // Contrary to this, other elements are considered sensitive and MUST NOT be available in plaintext outside the <envelope/> element.
    var isServerProcessed: Bool {
        // Message Processing Hints are addressed to the server and MUST therefore be accessible in plaintext.
        if xmlns == "urn:xmpp:hints" {
            return true
        }
        // Sending clients MUST NOT include Stanza-ID elements inside the <envelope/> element, as this would prevent the server from filtering it.
        if xmlns == XMPPStanzaIdXmlns, [XMPPStanzaIdElementName, XMPPOriginIdElementName].contains(name) {
            return true
        }
        // The server MUST be able to access the <addresses/> and <address/> elements in order to do message routing, so they MUST NOT be encrypted.
        if xmlns == "http://jabber.org/protocol/address" {
            return true
        }
        // The server needs to be able to provide stanza error information
        if name == "error", ["jabber:client", "jabber:server"].contains(xmlns) {
            return true
        }
        return false
    }
}

private struct StanzaContentEncryptionPaddingGenerator: Sequence, IteratorProtocol {
    static func randomPadding() -> String {
        String(StanzaContentEncryptionPaddingGenerator())
    }
    
    private static let alphabet: [Character] = {
        let printableASCIICharacterCodes = 33...126
        let xmlUnsafeCharacters = CharacterSet(charactersIn: #""'<>&"#)
        return printableASCIICharacterCodes.compactMap { code in
            guard let scalar = UnicodeScalar(code), !xmlUnsafeCharacters.contains(scalar) else {
                return nil
            }
            return Character(scalar)
        }
    }()
    
    private var remaining = Int.random(in: 0...200)
    
    mutating func next() -> Character? {
        guard remaining > 0, let randomCharacter = Self.alphabet.randomElement() else {
            return nil
        }
        remaining -= 1
        return randomCharacter
    }
}
