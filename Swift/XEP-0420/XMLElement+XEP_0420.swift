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
    public var isStanzaContentEncryptionEnvelope: Bool {
        name == "envelope" && xmlns == "urn:xmpp:sce:1"
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
