import dns.resolver
import re


def getHost(domain):
    record = ""
    try:
        srv_records = dns.resolver.query(
            '_opencap._tcp.'+domain, dns.rdatatype.SRV)

        if len(srv_records) < 1:
            return "", False

        record = str(srv_records[0].target).rstrip('.')

    except:
        return "", False

    try:
        # get nameservers for target domain
        response = dns.resolver.query(domain, dns.rdatatype.NS)

        # we'll use the first nameserver in this example
        nsname = response.rrset[0]  # name
        response = dns.resolver.query(str(nsname), dns.rdatatype.A)
        nsaddr = response.rrset[0].to_text()  # IPv4

        # get DNSKEY for zone
        request = dns.message.make_query(
            domain, dns.rdatatype.DNSKEY, want_dnssec=True)

        # send the query
        response = dns.query.udp(request, nsaddr)
        if response.rcode() != 0:
            # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
            return record, False

        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
        answer = response.answer
        if len(answer) != 2:
            # SOMETHING WENT WRONG
            return record, False

        # the DNSKEY should be self signed, validate it
        name = dns.name.from_text(domain)
        try:
            dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
        except dns.dnssec.ValidationFailure:
            # BE SUSPICIOUS
            return record, False
        # WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR example.com
        return record, True

    except:
        return record, False


def validateUsername(username):
    username = username.lower()
    return username, bool(re.match(r"^[a-z0-9._-]{1,25}$", username))


def validateDomain(domain):
    return bool(re.match(r"^[a-z0-9.\-]+\.[a-z]{2,4}$", domain))


def validateAlias(alias):
    parts = alias.split("$")
    if len(parts) != 2:
        return "", ""

    username = parts[0]
    domain = parts[1]

    username, valid = validateUsername(username)
    if not valid:
        return "", ""

    if not validateDomain(domain):
        return "", ""

    return username, domain
