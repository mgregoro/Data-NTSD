package Data::NTSD::SID;

use Data::NTSD::ByteStream;
use Mojo::Base 'Data::NTSD::Structure';

__PACKAGE__->mk_accessors(qw/
    sid_string identifier_authority identifier_authority_array
    identifier_authority_int sub_authority_array
/);


sub new {
    my ($class, $arg) = @_;

    my $self = bless {}, $class;

    if (ref($arg) eq "Data::NTSD::ByteStream") {
        $self->{bytestream} = $arg;
    } elsif (ref($arg) eq "HASH" && exists $arg->{base64}) {
        $self->{bytestream} = Data::NTSD::ByteStream->new($arg->{base64})->b64_decode;
    } else {
        $self->{bytestream} = Data::NTSD::ByteStream->new($arg);
    }

    $self->setup;
    return $self;
}

sub create {
    my ($class, $string) = @_;

    my ($s, $one, $authority, @sub_authorities) = split(/-/, $string);

    unless ($s eq "S" && $one == 1) {
        die "SID must begin with S-1-\n";
    }

    my $self = bless {}, $class;

    $self->{header} = {
        revision => 1,
        sub_authority_count => scalar(@sub_authorities),
    };

    $self->{identifier_authority} = "{0,0,0,0,0,$authority}";
    $self->{identifier_authority_array} = [0, 0, 0, 0, 0, $authority];
    $self->{identifier_authority_int} = $authority;

    $self->{sub_authority_array} = \@sub_authorities;

    $self->{sid_string} = "S-1-" . $self->{identifier_authority_int} . "-" . join('-', @sub_authorities);

    # now generate the bytestream..
    my $bytes = pack('C' x 8, $self->{header}->{revision}, $self->{header}->{sub_authority_count}, @{$self->{identifier_authority_array}});

    # pack in the sub authorities
    $bytes .= pack('I<' x scalar(@sub_authorities), @sub_authorities);

    $self->{bytestream} = Data::NTSD::ByteStream->new($bytes);

    return $self;
}

sub setup {
    my ($self) = @_;

    $self->{header} = {
        revision => unpack('C', $self->bytestream->substr(0, 1)),
        sub_authority_count => unpack('C', $self->bytestream->substr(1, 1)),
    };

    my @identifier_authority;
    my $pos = 2;
    for (my $i = 0; $i < 6; $i++) {
        $identifier_authority[$i] = unpack('C', $self->bytestream->substr($pos, 1));
        unless ($identifier_authority[$i]) {
            $identifier_authority[$i] = 0;
        }
        $pos++;
    }

    $self->{identifier_authority} = "{" . join(',', @identifier_authority) . "}";
    $self->{identifier_authority_array} = \@identifier_authority;
    $self->{identifier_authority_int} = int(join('', @identifier_authority));

    my @sub_authority;
    for (my $i = 0; $i < $self->{header}->{sub_authority_count}; $i++) {
        push(@sub_authority, unpack('I<', $self->bytestream->substr($pos, 4)));
        $pos += 4;
    }

    $self->{sub_authority_array} = \@sub_authority;

    $self->{sid_string} = "S-1-" . $self->{identifier_authority_int} . "-" . join('-', @sub_authority);
}

1;