#define LOG_MODULE PacketLogModuleDnsLayer

#include "DnsResource.h"
#include "EndianPortable.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif
#include <pcapplusplus/Logger.h>
#include <pcapplusplus/ProtocolType.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <cstdio>
#include <string.h>

namespace visor::lib::dns {

IDnsResource::IDnsResource(DnsLayer *dnsLayer, size_t offsetInLayer)
    : m_DnsLayer(dnsLayer)
    , m_OffsetInLayer(offsetInLayer)
    , m_NextResource(NULL)
{
    char decodedName[256];
    m_NameLength = decodeName((const char *)getRawData(), decodedName);
    if (m_NameLength > 0) {
        m_DecodedName = decodedName;
        m_DecodedNameLower = m_DecodedName;
        std::transform(m_DecodedNameLower.begin(), m_DecodedNameLower.end(), m_DecodedNameLower.begin(),
            [](unsigned char c) { return std::tolower(c); });
    }
}

IDnsResource::IDnsResource(uint8_t *emptyRawData)
    : m_DnsLayer(NULL)
    , m_OffsetInLayer(0)
    , m_NextResource(NULL)
    , m_DecodedName("")
    , m_DecodedNameLower("")
    , m_NameLength(0)
    , m_ExternalRawData(emptyRawData)
{
}

uint8_t *IDnsResource::getRawData() const
{
    if (m_DnsLayer == NULL)
        return m_ExternalRawData;

    return m_DnsLayer->m_Data + m_OffsetInLayer;
}

size_t IDnsResource::decodeName(const char *encodedName, char *result, int iteration)
{
    size_t encodedNameLength = 0;
    size_t decodedNameLength = 0;
    char *resultPtr = result;
    resultPtr[0] = 0;

    // Fills buf with a concise DNS header context for error log lines.
    // Uses snprintf into a stack buffer — no heap allocation, no fmt::format.
    char _err_buf[192];
    auto log_err = [&](const char *msg) {
        if (m_DnsLayer == nullptr || m_DnsLayer->m_Data == nullptr) {
            snprintf(_err_buf, sizeof(_err_buf), "decodeName: %s; dns_hdr: <null dns layer>", msg);
        } else if (m_DnsLayer->m_DataLen < sizeof(dnshdr)) {
            snprintf(_err_buf, sizeof(_err_buf), "decodeName: %s; dns_hdr: <too short>", msg);
        } else {
            const auto *hdr = m_DnsLayer->getDnsHeader();
            const char *transport_str = "unknown";
            if (const auto *prev = m_DnsLayer->getPrevLayer(); prev != nullptr) {
                if (prev->getProtocol() == pcpp::UDP) transport_str = "UDP";
                else if (prev->getProtocol() == pcpp::TCP) transport_str = "TCP";
            }
            const char *qr_str = hdr->queryOrResponse == 0 ? "query"
                               : hdr->queryOrResponse == 1 ? "response"
                               : "invalid";
            const char *opcode_str;
            switch (hdr->opcode) {
                case 0:  opcode_str = "QUERY";   break;
                case 1:  opcode_str = "IQUERY";  break;
                case 2:  opcode_str = "STATUS";  break;
                case 4:  opcode_str = "NOTIFY";  break;
                case 5:  opcode_str = "UPDATE";  break;
                default: opcode_str = "RESERVED"; break;
            }
            const char *rcode_str;
            switch (hdr->responseCode) {
                case 0:  rcode_str = "NOERROR";   break;
                case 1:  rcode_str = "FORMERR";   break;
                case 2:  rcode_str = "SERVFAIL";  break;
                case 3:  rcode_str = "NXDOMAIN";  break;
                case 4:  rcode_str = "NOTIMP";    break;
                case 5:  rcode_str = "REFUSED";   break;
                case 6:  rcode_str = "YXDOMAIN";  break;
                case 7:  rcode_str = "YXRRSET";   break;
                case 8:  rcode_str = "NXRRSET";   break;
                case 9:  rcode_str = "NOTAUTH";   break;
                case 10: rcode_str = "NOTZONE";   break;
                default: rcode_str = "UNASSIGNED"; break;
            }
            snprintf(_err_buf, sizeof(_err_buf),
                "decodeName: %s; dns_hdr: transport=%s qr=%s opcode=%s rcode=%s qd=%u an=%u ns=%u ar=%u",
                msg, transport_str, qr_str, opcode_str, rcode_str,
                be16toh(hdr->numberOfQuestions), be16toh(hdr->numberOfAnswers),
                be16toh(hdr->numberOfAuthority), be16toh(hdr->numberOfAdditional));
        }
        PCPP_LOG_ERROR(_err_buf);
    };

    if (m_DnsLayer == nullptr || m_DnsLayer->m_Data == nullptr) {
        log_err("null dns layer");
        return 0;
    }

    size_t curOffsetInLayer = (uint8_t *)encodedName - m_DnsLayer->m_Data;
    if (curOffsetInLayer >= m_DnsLayer->m_DataLen) {
        log_err("name offset past end of packet");
        return 0;
    }

    if (iteration > 20) {
        log_err("max recursion depth exceeded");
        return 0;
    }

    uint8_t wordLength = encodedName[0];

    // A string to parse
    while (wordLength != 0) {
        // Re-validate the current pointer position at the top of every iteration before
        // reading any byte from it — closes the gap where a label walk or pointer follow
        // could leave encodedName pointing outside the packet buffer.
        curOffsetInLayer = (uint8_t *)encodedName - m_DnsLayer->m_Data;
        if (curOffsetInLayer >= m_DnsLayer->m_DataLen) {
            log_err("name pointer walked past end of packet");
            return 0;
        }
        wordLength = encodedName[0];
        if (wordLength == 0) {
            break;
        }

        // A pointer to another place in the packet
        if ((wordLength & 0xc0) == 0xc0) {
            if (curOffsetInLayer + 2 > m_DnsLayer->m_DataLen || encodedNameLength >= 255) {
                log_err("pointer out-of-bounds or name too long");
                return 0;
            }

            uint16_t offsetInLayer = (wordLength & 0x3f) * 256 + (0xFF & encodedName[1]);
            if (offsetInLayer < sizeof(dnshdr) || offsetInLayer >= m_DnsLayer->m_DataLen) {
                log_err("name pointer outside valid range");
                return 0;
            }
            // RFC 9267 §2: pointer must point backward to prevent forward-reference loops
            if (offsetInLayer >= curOffsetInLayer) {
                log_err("name pointer is not backward");
                return 0;
            }

            char tempResult[256];
            memset(tempResult, 0, 256);
            size_t ret = decodeName((const char *)(m_DnsLayer->m_Data + offsetInLayer), tempResult, iteration + 1);
            if (ret == 0) {
                log_err("recursive call failed");
                return 0;
            }

            int i = 0;
            while (tempResult[i] != 0 && decodedNameLength < 255) {
                resultPtr[0] = tempResult[i++];
                resultPtr++;
                decodedNameLength++;
            }

            resultPtr[0] = 0;

            // in this case the length of the pointer is: 1 byte for 0xc0 + 1 byte for the offset itself
            return encodedNameLength + 2;
        } else {
            // RFC 9267 §3: label length must be 1–63 per RFC 1035 §2.3.4
            if (wordLength > 63) {
                log_err("label length exceeds RFC 1035 maximum of 63");
                return 0;
            }
            // return if next word would be outside of the DNS layer or overflow the decoded
            // result buffer (result is char[256], so resultPtr must never advance past
            // result+254 before the trailing dot/NULL).
            if (curOffsetInLayer + wordLength + 1 > m_DnsLayer->m_DataLen
                || decodedNameLength + wordLength + 1 >= 255) {
                log_err("label out-of-bounds or name too long");
                return 0;
            }

            memcpy(resultPtr, encodedName + 1, wordLength);
            resultPtr += wordLength;
            resultPtr[0] = '.';
            resultPtr++;
            decodedNameLength += wordLength + 1;
            encodedName += wordLength + 1;
            encodedNameLength += wordLength + 1;

            curOffsetInLayer = (uint8_t *)encodedName - m_DnsLayer->m_Data;
            if (curOffsetInLayer >= m_DnsLayer->m_DataLen) {
                log_err("offset past end of packet after label");
                return 0;
            }
            // wordLength is re-read at the top of the next iteration
        }
    }

    // remove the last "."
    if (resultPtr > result) {
        result[resultPtr - result - 1] = 0;
    }

    // add the last '\0' to encodedNameLength; guard against writing at offset 255
    // (the buffer is char[256] so index 255 is the last valid byte)
    if (resultPtr - result < 255) {
        resultPtr[0] = 0;
    }
    encodedNameLength++;

    return encodedNameLength;
}


void IDnsResource::encodeName(const std::string &decodedName, char *result, size_t &resultLen)
{
    resultLen = 0;
    std::stringstream strstream(decodedName);
    std::string word;
    while (getline(strstream, word, '.')) {
        // pointer to a different hostname in the packet
        if (word[0] == '#') {
            // convert the number from string to int
            std::stringstream stream(word.substr(1));
            int pointerInPacket = 0;
            stream >> pointerInPacket;

            // verify it's indeed a number and that is in the range of [0-255]
            if (stream.fail() || pointerInPacket < 0 || pointerInPacket > 0xff) {
                PCPP_LOG_ERROR(("Error encoding the string '" + decodedName + "'").c_str());
                return;
            }

            // set the pointer to the encoded string result
            result[0] = (uint8_t)0xc0;
            result[1] = (uint8_t)pointerInPacket;
            result += 2;
            resultLen += 2;
            return; // pointer always comes last
        }

        result[0] = word.length();
        result++;
        memcpy(result, word.c_str(), word.length());
        result += word.length();
        resultLen += word.length() + 1;
    }

    result[0] = 0;
    resultLen++;
}

DnsType IDnsResource::getDnsType() const
{
    uint16_t dnsType{0};
    memcpy(&dnsType, (getRawData() + m_NameLength), sizeof(dnsType));
    return (DnsType)be16toh(dnsType);
}

void IDnsResource::setDnsType(DnsType newType)
{
    uint16_t newTypeAsInt = htobe16((uint16_t)newType);
    memcpy(getRawData() + m_NameLength, &newTypeAsInt, sizeof(uint16_t));
}

DnsClass IDnsResource::getDnsClass() const
{
    uint16_t dnsClass = *(uint16_t *)(getRawData() + m_NameLength + sizeof(uint16_t));
    return (DnsClass)be16toh(dnsClass);
}

void IDnsResource::setDnsClass(DnsClass newClass)
{
    uint16_t newClassAsInt = htobe16((uint16_t)newClass);
    memcpy(getRawData() + m_NameLength + sizeof(uint16_t), &newClassAsInt, sizeof(uint16_t));
}

bool IDnsResource::setName(const std::string &newName)
{
    char encodedName[256];
    size_t encodedNameLen = 0;
    encodeName(newName, encodedName, encodedNameLen);
    if (m_DnsLayer != NULL) {
        if (encodedNameLen > m_NameLength) {
            if (!m_DnsLayer->extendLayer(m_OffsetInLayer, encodedNameLen - m_NameLength, this)) {
                PCPP_LOG_ERROR("Couldn't set name for DNS query, unable to extend layer");
                return false;
            }
        } else if (encodedNameLen < m_NameLength) {
            if (!m_DnsLayer->shortenLayer(m_OffsetInLayer, m_NameLength - encodedNameLen, this)) {
                PCPP_LOG_ERROR("Couldn't set name for DNS query, unable to shorten layer");
                return false;
            }
        }
    } else {
        size_t size = getSize();
        char *tempData = new char[size];
        memcpy(tempData, m_ExternalRawData, size);
        memcpy(m_ExternalRawData + encodedNameLen, tempData, size);
        delete[] tempData;
    }

    memcpy(getRawData(), encodedName, encodedNameLen);
    m_NameLength = encodedNameLen;
    m_DecodedName = newName;
    m_DecodedNameLower = m_DecodedName;
    std::transform(m_DecodedNameLower.begin(), m_DecodedNameLower.end(), m_DecodedNameLower.begin(),
        [](unsigned char c) { return std::tolower(c); });

    return true;
}

void IDnsResource::setDnsLayer(DnsLayer *dnsLayer, size_t offsetInLayer)
{
    memcpy(dnsLayer->m_Data + offsetInLayer, m_ExternalRawData, getSize());
    m_DnsLayer = dnsLayer;
    m_OffsetInLayer = offsetInLayer;
    m_ExternalRawData = NULL;
}

std::basic_string_view<uint8_t> IDnsResource::getRawName() const
{
    if (m_NameLength == 0 || m_DnsLayer == nullptr || m_DnsLayer->m_Data == nullptr
        || m_OffsetInLayer >= m_DnsLayer->m_DataLen) {
        return {};
    }
    // scan starts at the domain name
    auto scan = std::basic_string_view<uint8_t>{m_DnsLayer->m_Data, m_DnsLayer->m_DataLen}
                    .substr(m_OffsetInLayer) // skip to the name offset
                    .substr(0, 255);         // enforce name length limit

    // find the end of the scan
    size_t pos = 0;
    while (pos < scan.size()) {
        if (scan[pos] == 0) {
            // root label at the end
            pos += 1;
            break;
        }

        uint8_t label = scan[pos];
        if ((label & 0xc0) == 0xc0) {
            // compression pointer: need one more byte
            if (pos + 2 > scan.size()) {
                return {};
            }
            pos += 2;
            break;
        }

        if ((label & 0xc0) != 0x00) {
            // malformed name
            return {};
        }

        // normal label: need the length byte plus all label bytes in bounds
        size_t label_end = pos + 1 + label;
        if (label_end >= scan.size()) {
            return {};
        }
        pos = label_end;
    }

    if (pos > scan.size()) {
        return {};
    }

    return scan.substr(0, pos);
}

uint32_t DnsResource::getTTL() const
{
    uint32_t ttl = *(uint32_t *)(getRawData() + m_NameLength + 2 * sizeof(uint16_t));
    return be32toh(ttl);
}

void DnsResource::setTTL(uint32_t newTTL)
{
    newTTL = htobe32(newTTL);
    memcpy(getRawData() + m_NameLength + 2 * sizeof(uint16_t), &newTTL, sizeof(uint32_t));
}

size_t DnsResource::getDataLength() const
{
    uint16_t dataLength{0};
    memcpy(&dataLength, (getRawData() + m_NameLength + 2 * sizeof(uint16_t) + sizeof(uint32_t)), sizeof(dataLength));
    return be16toh(dataLength);
}

DnsResourceDataPtr DnsResource::getData() const
{
    uint8_t *resourceRawData = getRawData() + m_NameLength + 3 * sizeof(uint16_t) + sizeof(uint32_t);
    size_t dataLength = getDataLength();

    switch (getDnsType()) {
    case DNS_TYPE_A: {
        return DnsResourceDataPtr(new IPv4DnsResourceData(resourceRawData, dataLength));
    }

    case DNS_TYPE_AAAA: {
        return DnsResourceDataPtr(new IPv6DnsResourceData(resourceRawData, dataLength));
    }

    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_DNAM:
    case DNS_TYPE_PTR: {
        return DnsResourceDataPtr(new StringDnsResourceData(resourceRawData, dataLength, const_cast<IDnsResource *>(static_cast<const IDnsResource *>(this))));
    }

    case DNS_TYPE_MX: {
        return DnsResourceDataPtr(new MxDnsResourceData(resourceRawData, dataLength, const_cast<IDnsResource *>(static_cast<const IDnsResource *>(this))));
    }

    default: {
        return DnsResourceDataPtr(new GenericDnsResourceData(resourceRawData, dataLength));
    }
    }
}

size_t DnsResource::getDataOffset() const
{
    return (size_t)(m_OffsetInLayer + m_NameLength + 3 * sizeof(uint16_t) + sizeof(uint32_t));
}

bool DnsResource::setData(IDnsResourceData *data)
{
    // convert data to byte array according to the DNS type
    size_t dataLength = 0;
    uint8_t dataAsByteArr[256];

    if (data == NULL) {
        PCPP_LOG_ERROR("Given data is NULL");
        return false;
    }

    switch (getDnsType()) {
    case DNS_TYPE_A: {
        if (!data->isTypeOf<IPv4DnsResourceData>()) {
            PCPP_LOG_ERROR("DNS record is of type A but given data isn't of type IPv4DnsResourceData");
            return false;
        }
        break;
    }

    case DNS_TYPE_AAAA: {
        if (!data->isTypeOf<IPv6DnsResourceData>()) {
            PCPP_LOG_ERROR("DNS record is of type AAAA but given data isn't of type IPv6DnsResourceData");
            return false;
        }
        break;
    }

    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_DNAM:
    case DNS_TYPE_PTR: {
        if (!data->isTypeOf<StringDnsResourceData>()) {
            PCPP_LOG_ERROR("DNS record is of type NS, CNAME, DNAM or PTR but given data isn't of type StringDnsResourceData");
            return false;
        }
        break;
    }

    case DNS_TYPE_MX: {
        if (!data->isTypeOf<MxDnsResourceData>()) {
            PCPP_LOG_ERROR("DNS record is of type MX but given data isn't of type MxDnsResourceData");
            return false;
        }
        break;
    }

    default: {
        // do nothing
    }
    }

    // convert the IDnsResourceData to byte array
    if (!data->toByteArr(dataAsByteArr, dataLength, this)) {
        PCPP_LOG_ERROR("Cannot convert DNS resource data to byte array, data is probably invalid");
        return false;
    }

    size_t dataLengthOffset = m_NameLength + (2 * sizeof(uint16_t)) + sizeof(uint32_t);
    size_t dataOffset = dataLengthOffset + sizeof(uint16_t);

    if (m_DnsLayer != NULL) {
        size_t curLength = getDataLength();
        if (dataLength > curLength) {
            if (!m_DnsLayer->extendLayer(m_OffsetInLayer + dataOffset, dataLength - curLength, this)) {
                PCPP_LOG_ERROR("Couldn't set data for DNS query, unable to extend layer");
                return false;
            }
        } else if (dataLength < curLength) {
            if (!m_DnsLayer->shortenLayer(m_OffsetInLayer + dataOffset, curLength - dataLength, this)) {
                PCPP_LOG_ERROR("Couldn't set data for DNS query, unable to shorten layer");
                return false;
            }
        }
    }

    // write data to resource
    memcpy(getRawData() + dataOffset, dataAsByteArr, dataLength);
    // update data length in resource
    dataLength = htobe16((uint16_t)dataLength);
    memcpy(getRawData() + dataLengthOffset, &dataLength, sizeof(uint16_t));

    return true;
}

uint16_t DnsResource::getCustomDnsClass() const
{
    uint16_t value = *(uint16_t *)(getRawData() + m_NameLength + sizeof(uint16_t));
    return be16toh(value);
}

void DnsResource::setCustomDnsClass(uint16_t customValue)
{
    memcpy(getRawData() + m_NameLength + sizeof(uint16_t), &customValue, sizeof(uint16_t));
}

}
