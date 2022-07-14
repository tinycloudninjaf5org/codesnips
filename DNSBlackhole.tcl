# DNS Blackhole
# This iRule interrogates all queries that arrive on the GTM listener.  If the query matches
# a list of prohibited FQDNs, a standardized response is given and the request is logged.  
# This response IP address could be a honeypot server or an LTM virtual server.
# Blackhole functionality can be used to prevent malware, virus C2 servers, adware, or other sites.
#
#
# Usage: 
#  1) apply to GTM listener virtual server that is defined at Local Traffic - Virtual Servers
#  2) create a string data group called "Blackhole_Class".  The FQDNs must start with a period.
#  3) update the answer static variable with the IP address to return
#
# Known Issues:
#  1) Only A and AAAA records are returned for blackhole requests. The response for other request
#     types will be logged and returned with no answer.
#


when RULE_INIT {
    # Set IPV4 address that is returned for Blackhole matches for A records
    set static::blackhole_reply_IPV4 "10.1.1.26"
    # Set IPV6 address that is returned for Blackhole matches for AAAA records
    set static::blackhole_reply_IPV6 "2001:19b8:101:2::f5f5:1d"
    # Set TTL used for all Blackhole replies
    set static::blackhole_ttl "300"
}

when DNS_REQUEST {
    # debugging statement see all questions and request details
        # log -noname local0. "Client: [IP::client_addr] Question:[DNS::question name] Type:[DNS::question type] Class:[DNS::question class] Origin:[DNS::origin]"

    # Blackhole_Match is used to track when a Query matches the blackhole list
    # Ensure it is always set to 0 or false at beginning of the DNS request
    set Blackhole_Match 0

    # Blackhole_Type is used to track why this FQDN was added to the Blackhole_Class
    set Blackhole_Type ""

    # When the FQDN from the DNS Query is checked against the Blackhole class, the FQDN must start with a 
    # period.  This ensures we match a FQDN and all names to the left of it.  This prevents against
    # malware that dynamically prepends characters to the domain name in order to bypass exact matches 
    if {!([DNS::question name] == ".")} {
        set fqdn_name .[DNS::question name]
    }

    if { [class match $fqdn_name ends_with Blackhole] } {
    # Client made a DNS request for a Blackhole site.
    set Blackhole_Match 1
    set Blackhole_Type [class match -value $fqdn_name ends_with Blackhole ]

    # Prevent processing by GTM, DNS Express, BIND and GTM Listener's pool.  
    # Want to ensure we don't request a prohibited site and allow their server to identify or track the GTM source IP.
    DNS::return
    } 
}

when DNS_RESPONSE {
    # debugging statement to see all questions and request details
    # log -noname local0. "Request: $fqdn_name Answer: [DNS::answer] Origin:[DNS::origin] Status: [DNS::header rcode] Flags: RD [DNS::header rd] RA [DNS::header ra]"

    if { $Blackhole_Match } {
        # This DNS request was for a Blackhole FQDN. Take different actions based on the request type.
        switch [DNS::question type] {
            "A" {
                # Clear out any DNS responses and insert the custom response.  RA header = recursive answer
                DNS::answer clear
                DNS::answer insert "[DNS::question name]. $static::blackhole_ttl [DNS::question class] [DNS::question type] $static::blackhole_reply_IPV4"
                DNS::header ra "1"

                # log example:  Apr  3 14:54:23 local/tmm info tmm[4694]:
                #     Blackhole: 10.1.1.148#4902 requested foo.com query type: A class IN A-response: 10.1.1.60
                log -noname local0. "Blackhole: [IP::client_addr]#[UDP::client_port] requested [DNS::question name] query type: [DNS::question type] class [DNS::question class] A-response: $static::blackhole_reply_IPV4 BH type: $Blackhole_Type"
            }
            "AAAA" {
                # Clear out any DNS responses and insert the custom response.  RA header = recursive answer
                DNS::answer clear
                DNS::answer insert "[DNS::question name]. $static::blackhole_ttl [DNS::question class] [DNS::question type] $static::blackhole_reply_IPV6"
                DNS::header ra "1"

                # log example:  Apr  3 14:54:23 local/tmm info tmm[4694]:
                #     Blackhole: 10.1.1.148#4902 requested foo.com query type: A class IN AAAA-response: 2001:19b8:101:2::f5f5:1d
                log -noname local0. "Blackhole: [IP::client_addr]#[UDP::client_port] requested [DNS::question name] query type: [DNS::question type] class [DNS::question class] AAAA-response: $static::blackhole_reply_IPV6 BH type: $Blackhole_Type"
            }
            default {
                # For other record types, e.g. MX, NS, TXT, etc, provide a blank NOERROR response
                DNS::last_act reject

                # log example:  Apr  3 14:54:23 local/tmm info tmm[4694]:
                #     Blackhole: 10.1.1.148#4902 requested foo.com query type: A class IN unable to respond
                log -noname local0. "Blackhole: [IP::client_addr]#[UDP::client_port] requested [DNS::question name] query type: [DNS::question type] class [DNS::question class] unable to respond  BH type: $Blackhole_Type"
            }
      }
    }
}
