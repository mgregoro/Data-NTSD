use strict;
use warnings;
package Data::NTSD;

# ABSTRACT: Perl interface for manipulation of ntSecurityDescriptor in Active Directory

use Class::Accessor;
use Data::NTSD::ByteStream;
use Data::NTSD::SID;
use Data::NTSD::ACL;

our $VERSION = 0.01;

our @ISA;
push(@ISA, 'Class::Accessor');

__PACKAGE__->mk_accessors(qw/
    bytestream header dacl sacl owner group
/);

# data order:
# revision(1), sbz1(1), control(2), owner_offset(4), group_offset(4), sacl_offset(4), dacl_offset(4), sacl, dacl, owner, group

sub new {
    my ($class, $arg) = @_;

    my $self = bless {}, $class;

    if (ref($arg) eq "HASH" && exists $arg->{base64}) {
        $self->{bytestream} = Data::NTSD::ByteStream->new($arg->{base64})->b64_decode;
    } else {
        $self->{bytestream} = Data::NTSD::ByteStream->new($arg);
    }

    $self->setup;
    return $self;
}

sub offsets {
    my ($self) = @_;
    my @offsets;
    foreach my $offset (qw/owner group sacl dacl/) {
        push(@offsets, $self->{header}->{"$offset\_offset"}) if $self->{header}->{"$offset\_offset"};
    }
    return sort {$a <=> $b} @offsets;
}

# convenience methods to get streams for each
sub dacl_bytestream { shift->get_bytestream('dacl') }
sub sacl_bytestream { shift->get_bytestream('sacl') }
sub group_bytestream { shift->get_bytestream('group') }
sub owner_bytestream { shift->get_bytestream('owner') }

sub _owner {
    return Data::NTSD::SID->new(shift->owner_bytestream);
}

sub _sacl {
    my ($self) = @_;
    return Data::NTSD::ACL->new($self->sacl_bytestream, $self);
}

sub _dacl {
    my ($self) = @_;
    return Data::NTSD::ACL->new($self->dacl_bytestream, $self);
}

sub _group {
    return Data::NTSD::ACL->new(shift->group_bytestream);
}

sub get_bytestream {
    my ($self, $type) = @_;

    my $start_byte = $self->{header}->{"$type\_offset"};
    my $end_byte;
    foreach my $offset ($self->offsets) {
        if ($offset > $start_byte) {
            $end_byte = $offset;
            last;
        }
    }

    # if there's no offset past this offset's end, then the last byte is the last byte in the security descriptor.
    unless ($end_byte) {
        $end_byte = length($self->bytestream);
    }

    return $self->bytestream->substr($start_byte, ($end_byte - $start_byte));
}

sub control_flags {
    my ($self) = @_;

    my $flags = [qw/
        SELF_RELATIVE RM_CONTROL_VALID SACL_PROTECTED DACL_PROTECTED SACL_AUTO_INHERITED DACL_AUTO_INHERITED
        SACL_COMPUTED_INHERITANCE_REQUIRED DACL_COMPUTED_INHERITANCE_REQUIRED DACL_TRUSTED SERVER_SECURITY
        SACL_DEFAULTED SACL_PRESENT DACL_DEFAULTED DACL_PRESENT GROUP_DEFAULTED OWNER_DEFAULTED
    /];

    my @has_flags;
    my $control_bits = $self->header->{control};
    for (my $i = 0; $i < 16; $i++) {
        if (substr($control_bits, $i, 1) == 1) {
            push(@has_flags, $flags->[$i]);
        }
    }

    return \@has_flags;
}

# reconstruct our bytestream from our component parts.
sub serialize {
    my ($self) = @_;

    # we should have all of the up to date bytestreams, let's glue them together.
    # header is 20 bytes
    # putting it back in the documented order owner, group, sacl, dacl

    my $offset = 20;
    my $h = pack('CCB16I<', $self->header->{revision}, $self->header->{sbz1}, $self->header->{control}, $offset);
    
    my $payload_bytes;
    foreach my $method (qw/owner group sacl dacl/) {
        my $obj = $self->$method;

        $offset += length($obj->bytestream);
        
        # add this for all but the last, there's no next offset.
        $h .= pack('I<', $offset) unless length($h) == 20;

        $payload_bytes .= $obj->bytestream;
    }

    $self->{bytestream} = Data::NTSD::ByteStream->new($h . $payload_bytes);
}

sub setup {
    my ($self) = @_;
    $self->parse_header;

    # instantiate all of our goodies inside of us, so we know how to serialize them later.
    $self->{group} = $self->_group;
    $self->{owner} = $self->_owner;
    $self->{sacl} = $self->_sacl;
    $self->{dacl} = $self->_dacl;
}

sub parse_header {
    my ($self) = @_;

    $self->{header} = {
        revision => unpack('C', $self->bytestream->substr(0, 1)),
        sbz1 => unpack('C', $self->bytestream->substr(1, 1)),
        control => unpack('B16', $self->bytestream->substr(2, 2)),
        owner_offset => unpack('I<', $self->bytestream->substr(4, 4)),
        group_offset => unpack('I<', $self->bytestream->substr(8, 4)),
        sacl_offset => unpack('I<', $self->bytestream->substr(12, 4)),
        dacl_offset => unpack('I<', $self->bytestream->substr(16, 4)),
    };
}

1;
