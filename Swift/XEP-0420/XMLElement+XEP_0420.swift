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
    public static func makeStanzaContentEncryptionEnvelope() -> XMLElement {
        XMLElement(name: "envelope", xmlns: "urn:xmpp:sce:1")
    }
    
    public var isStanzaContentEncryptionEnvelope: Bool {
        name == "envelope" && xmlns == "urn:xmpp:sce:1"
    }
    
    public func withStanzaContentEncryptionEnvelopeContent<T>(_ body: (_ content: XMLElement) throws -> T) rethrows -> T {
        let content: XMLElement
        if let existingContent = element(forName: "content") {
            content = existingContent
        } else {
            content = XMLElement(name: "content")
            addChild(content)
        }
        return try body(content)
    }
}

// In order to prevent certain attacks, different affix elements MAY be added as direct child elements of the <envelope/> element.
extension XMLElement {
    // Prevent known ciphertext and message length correlation attacks.
    public func addStanzaContentEncryptionRandomPaddingAffix() {
        addChild(XMLElement(name: "rpad", stringValue: String(StanzaContentEncryptionPaddingGenerator())))
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
        for affix in elements(forName: "time") {
            guard let stamp = affix.attributeStringValue(forName: "stamp"),
                  let actualDate = Date.from(xmppDateTimeString: stamp),
                  abs(actualDate.timeIntervalSince(expectedDate)) <= verificationMargin else {
                return false
            }
        }
        return true
    }
    
    // Receiving clients MUST check if the JID matches the to attribute of the enclosing stanza and otherwise alert the user/reject the message
    public func verifyStanzaContentEncryptionRecipient(expecting expectedJID: XMPPJID) -> Bool {
        for affix in elements(forName: "to") {
            guard let jid = affix.attributeStringValue(forName: "jid"),
                  let actualJID = XMPPJID(string: jid),
                  actualJID.isEqual(to: expectedJID, options: .bare) else {
                return false
            }
        }
        return true
    }
    
    // Receiving clients MUST check if the value matches the from attribute of the enclosing stanza and otherwise alert the user/reject the message
    public func verifyStanzaContentEncryptionSender(expecting expectedJID: XMPPJID) -> Bool {
        for affix in elements(forName: "from") {
            guard let jid = affix.attributeStringValue(forName: "jid"),
                  let actualJID = XMPPJID(string: jid),
                  actualJID.isEqual(to: expectedJID, options: .bare) else {
                return false
            }
        }
        return true
    }
}

private struct StanzaContentEncryptionPaddingGenerator: Sequence, IteratorProtocol {
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
