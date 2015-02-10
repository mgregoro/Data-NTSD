package Data::NTSD::Structure;

# Base class for ACL, ACE and SID

use Class::Accessor;

our @ISA;
push(@ISA, 'Class::Accessor');

__PACKAGE__->mk_accessors(qw/
    bytestream header
/);

sub read_and_advance {
    my ($self, $pos, $len, $fmt) = @_;
    return (unpack($fmt, $self->bytestream->substr($pos, $len)), $pos + $len);
}

sub parse_uuid {
    my ($self, $bytes) = @_;
    
    use bytes;

    my $chunks = [ 
        $bytes->substr(0, 4),
        $bytes->substr(4, 2),
        $bytes->substr(6, 2),
        $bytes->substr(8, 2),
        $bytes->substr(10, 6),
    ];

    return {
        array => [
            unpack('I<', $chunks->[0]),
            unpack('S<', $chunks->[1]),
            unpack('S<', $chunks->[2]),
            unpack('Q', $chunks->[3] . $chunks->[4]),
        ],
        string => join('-',
            join('', map { sprintf("%02x", ord($_)) } split(//, reverse($chunks->[0]))),
            join('', map { sprintf("%02x", ord($_)) } split(//, reverse($chunks->[1]))),
            join('', map { sprintf("%02x", ord($_)) } split(//, reverse($chunks->[2]))),
            join('', map { sprintf("%02x", ord($_)) } split(//, $chunks->[3])),
            join('', map { sprintf("%02x", ord($_)) } split(//, $chunks->[4])),   
        ),
    }
}

# method or function call...
sub uuid_string_to_bytes {
    my ($self, $uuid) = @_;

    $uuid = $self unless ref $self;

    # convert to GUID order
    my @segments = split(/-/, $uuid);
    for (0..2) {
        my $segment;
        while ($segments[$_] =~ /([0-9a-fA-F]{2})/g) {
            $segment = $1 . $segment;
        }
        $segments[$_] = $segment;
    }

    return Data::NTSD::ByteStream->new(
        pack('H2' x 16, 
            map { ($_ =~ /([0-9a-fA-F]{2})/g) } join('', @segments)
        )
    );
}

1;