# coding: utf-8
from __future__ import unicode_literals, print_function
import csp
from pyasn1.type import univ, useful, char, tag
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc2459


class CertAttribute(object):
    """Атрибут запроса на сертификат

    в закодированном виде добавляется в запрос методом
    CertRequest.add_attribute()
    """
    def __init__(self, oid, values):
        """@todo: to be defined """
        self.oid = oid
        self.vals = [encoder.encode(v) for v in values]

    def add_to(self, req):
        n = req.add_attribute(self.oid)
        for v in self.vals:
            req.add_attribute_value(n, v)


class CertValidity(CertAttribute):
    """Атрибут для установки интервала действия серта в запросе"""

    def __init__(self, not_before, not_after):
        """@todo: to be defined """
        val = univ.Sequence()
        for i, x in enumerate((not_before, not_after)):
            val.setComponentByPosition(i, useful.UTCTime(bytes(x.strftime('%y%m%d%H%M%SZ'))))
        super(CertValidity, self).__init__(b'1.2.643.2.4.1.1.1.1.2', [val])


class CertExtensions(CertAttribute):
    """Атрибут для задания расширений сертификата"""

    def __init__(self, exts):
        """@todo: to be defined """
        val = univ.SequenceOf()
        for i, ext in enumerate(exts):
            val.setComponentByPosition(i, ext.asn)
        super(CertExtensions, self).__init__(csp.szOID_CERT_EXTENSIONS, [val])


class CertExtension(object):
    def __init__(self, oid, value, critical=False):
        """Общий класс для всех видов расширений

        :oid: OID расширения
        :value: значение в ASN.1

        """
        self.asn = rfc2459.Extension()
        self.asn.setComponentByName(b'extnID', univ.ObjectIdentifier(oid))
        self.asn.setComponentByName(b'critical', univ.Boolean(bool(critical)))
        self.asn.setComponentByName(b'extnValue', univ.OctetString(value))


class EKU(CertExtension):
    """Расширенное использование ключа"""

    def __init__(self, ekus):
        """Создание EKU

        :ekus: список OID-ов расш. использования

        """
        val = rfc2459.ExtKeyUsageSyntax()
        for i, x in enumerate(ekus):
            val.setComponentByPosition(i, rfc2459.KeyPurposeId(x))
        super(EKU, self).__init__(csp.szOID_ENHANCED_KEY_USAGE, encoder.encode(val))


class KeyUsage(CertExtension):
    """Расширенное использование ключа"""

    def __init__(self, mask):
        """Создание EKU

        :ekus: список OID-ов расш. использования

        """
        val = rfc2459.KeyUsage(bytes(','.join(mask)))
        super(KeyUsage, self).__init__(csp.szOID_KEY_USAGE, encoder.encode(val))


class Attributes(object):
    """Набор пар (тип, значение)"""

    def __init__(self, attrs):
        self.asn = rfc2459.Name()
        vals = rfc2459.RDNSequence()

        for (i, (oid, val)) in enumerate(attrs):
            pair = rfc2459.AttributeTypeAndValue()
            pair.setComponentByName('type', rfc2459.AttributeType(bytes(oid)))
            pair.setComponentByName('value',
                                    rfc2459.AttributeValue(
                                        univ.OctetString(encoder.encode(char.UTF8String(unicode(val).encode('utf-8'))))))

            pairset = rfc2459.RelativeDistinguishedName()
            pairset.setComponentByPosition(0, pair)

            vals.setComponentByPosition(i, pairset)

        self.asn.setComponentByPosition(0, vals)

    def encode(self):
        return encoder.encode(self.asn)


class SubjectAltName(CertExtension):
    """Расширенное использование ключа"""

    def __init__(self, altnames):
        """Создание AltName

        :ekus: список OID-ов расш. использования

        """
        val = rfc2459.SubjectAltName()
        for (i, (t, v)) in enumerate(altnames):
            gn = rfc2459.GeneralName()
            if t == 'directoryName':
                val = rfc2459.Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
            else:
                assert 0, 'Unsupported SubjectAltName type: {0}'.format(t)
            gn.setComponentByName(t, val)
            val.setComponentByPosition(i, gn)

        super(SubjectAltName, self).__init__(csp.szOID_KEY_USAGE, encoder.encode(val))
