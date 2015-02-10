package Data::NTSD::ACL;

use Data::NTSD::Constants;
use Data::NTSD::ByteStream;
use Data::NTSD::ACE;
use Mojo::Base 'Data::NTSD::Structure';

__PACKAGE__->mk_accessors(qw/
    aces ntsd
/);

sub new {
    my ($class, $arg, $ntsd) = @_;

    my $self = bless {ntsd => $ntsd}, $class;

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

sub setup {
    my ($self) = @_;

    $self->{header} = {
        revision => unpack('C', $self->bytestream->substr(0, 1)),
        sbz1 => unpack('C', $self->bytestream->substr(1, 1)),
        acl_size => unpack('S<', $self->bytestream->substr(2, 2)),
        ace_count => unpack('S<', $self->bytestream->substr(4, 2)),
        sbz2 => unpack('S<', $self->bytestream->substr(6, 2)),
    };

    # scan for ACEs...
    my $pos = 8;
    $self->{aces} = [];
    for (my $i = 0; $i < $self->{header}->{ace_count} && $pos < $self->{header}->{acl_size}; $i++) {
        # read header to get the bytestream.
        my $ace_header = {};
        
        ($ace_header->{ace_type}, $pos) = $self->read_and_advance($pos, 1, 'C');
        ($ace_header->{ace_flags}, $pos) = $self->read_and_advance($pos, 1, 'C');
        ($ace_header->{ace_size}, $pos) = $self->read_and_advance($pos, 2, 'S<');

        my $payload_len = ($ace_header->{ace_size} - 4);
        $pos += $payload_len;

        my $ace_payload = $self->bytestream->substr($pos - $ace_header->{ace_size}, $ace_header->{ace_size});
        push(@{$self->{aces}}, Data::NTSD::ACE->new($ace_header, $ace_payload));
    }
}

sub add_ace {
    my ($self, $ace) = @_;

    my $ace_obj;
    if (ref($ace) eq 'Data::NTSD::ACE') {
        $ace_obj = $ace;
    } elsif (ref($ace) eq "HASH") {
        $ace_obj = Data::NTSD::ACE->create($ace);
    }

    my $i = 0;
    if (my $kind = $ace_obj->kind) {
        foreach my $ace (@{$self->{aces}}) {
            if ($i == 0 && $ace->kind eq "GRANT" && $kind eq "DENY") {
                # first ace is a GRANT, denies go first, add it here.
                splice(@{$self->{aces}}, $i, 0, $ace_obj);
                last;
            } elsif ($i == (scalar(@{$self->{aces}}) - 1) && $ace->kind eq "DENY" && $kind eq "GRANT") {
                # last ace is a DENY, grants go last, add it here.
                splice(@{$self->{aces}}, $i, 0, $ace_obj);
                last;
            } elsif ($ace->kind eq $kind) {
                # we can put it among those like it
                splice(@{$self->{aces}}, $i, 0, $ace_obj);
                last;
            }
            $i++;
        }
    } else {
        warn "[error]: @{[$ace_obj->type]} has no 'kind' specified, don't know how to put this ACE in canonical order.  shoving at the end\n";
        push(@{$self->{aces}}, $ace_obj);
    }

    # make sure our bytestream stays up to date...
    $self->serialize;
}

sub remove_ace {
    my ($self, $ace) = @_;

    my $ace_obj;
    if (ref($ace) eq 'Data::NTSD::ACE') {
        $ace_obj = $ace;
    } elsif (ref($ace) eq "HASH") {
        $ace_obj = Data::NTSD::ACE->create($ace);
    }

    my ($i, $removed) = (0, 0);
    foreach my $ace (@{$self->{aces}}) {
        if ($ace_obj->bytestream eq $ace->bytestream) {
            splice(@{$self->{aces}}, $i, 1);
            $removed++;
        }
        $i++;
    }

    # update the bytestream.
    $self->serialize if $removed;
}

sub has_ace {
    my ($self, $ace) = @_;

    my $ace_obj;
    if (ref($ace) eq 'Data::NTSD::ACE') {
        $ace_obj = $ace;
    } elsif (ref($ace) eq "HASH") {
        $ace_obj = Data::NTSD::ACE->create($ace);
    }

    foreach my $ace (@{$self->{aces}}) {
        if ($ace_obj->bytestream eq $ace->bytestream) {
            return 1;
        }
    }

    return undef;
}

sub revision {
    my ($self) = @_;

    my @v4_types = (
        ACCESS_ALLOWED_OBJECT_ACE_TYPE, 
        ACCESS_DENIED_OBJECT_ACE_TYPE, 
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE,
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    );

    my $revision = 0x02;

    ACE: foreach my $ace (@{$self->aces}) {
        foreach my $v4_type (@v4_types) {
            if ($ace->{ace_type} == $v4_type) {
                $revision = 0x04;
                last ACE;
            }
        }
    }

    return $revision;
}

sub serialize {
    my ($self) = @_;

    # get all of the data for the ACEs
    my $ace_bytes;
    foreach my $ace (@{$self->aces}) {
        $ace_bytes .= $ace->bytestream;
    }

    # we need the bytestream of this.
    $ace_bytes = Data::NTSD::ByteStream->new($ace_bytes);

    # update our internal data structure
    my $h = $self->header;
    $h->{ace_count} = scalar(@{$self->{aces}});
    $h->{acl_size} = length($ace_bytes) + 8;
    $h->{revision} = $self->revision;

    $self->{bytestream} = Data::NTSD::ByteStream->new(
        pack('CCS<S<S<', $h->{revision}, $h->{sbz1}, $h->{acl_size}, $h->{ace_count}, $h->{sbz2}) . $ace_bytes
    );

    # if we're inside a security descriptor, serialize it for them with the new changes.
    if (ref($self->ntsd) eq "Data::NTSD") {
        $self->ntsd->serialize;
    }
}

sub ace_count {
    my ($self) = @_;
    return $self->{header}->{ace_count};
}

sub acl_size {
    my ($self) = @_;
    return $self->{header}->{acl_size};
}

1;