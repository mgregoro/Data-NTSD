package Data::NTSD::ACE;

use Data::NTSD::SID;
use Data::NTSD::ByteStream;
use Data::NTSD::Constants;
use Mojo::Base 'Data::NTSD::Structure';

__PACKAGE__->mk_accessors(qw/
    type ace_type entry kind ace_flags
/);

my $ace_types = [
    # ACCESS_ALLOWED_ACE_TYPE
    {
        name => 'ACCESS_ALLOWED_ACE_TYPE',
        kind => 'GRANT',
        parser => sub {
            my ($self, $bs) = @_;
            return {
                mask => unpack('I<', $bs->substr(0, 4)),
                sid => Data::NTSD::SID->new($bs->substr(4, (length($bs) - 4))),
            };
        },
        generator => sub {},
    },

    # ACCESS_DENIED_ACE_TYPE
    {
        name => 'ACCESS_DENIED_ACE_TYPE',
        kind => 'DENY',
        parser => sub {},
        generator => sub {},
    },
    # SYSTEM_AUDIT_ACE_TYPE 
    {
        name => 'SYSTEM_AUDIT_ACE_TYPE',
        parser => sub {},
        generator => sub {},
    },
    # SYSTEM_ALARM_ACE_TYPE
    {
        name => 'SYSTEM_ALARM_ACE_TYPE',
        parser => sub {},
        generator => sub {},
    },
    # ACCESS_ALLOWED_COMPOUND_ACE_TYPE
    {
        name => 'ACCESS_ALLOWED_COMPOUND_ACE_TYPE',
        parser => sub {},
        generator => sub {},
    },
    # ACCESS_ALLOWED_OBJECT_ACE_TYPE
    {
        name => 'ACCESS_ALLOWED_OBJECT_ACE_TYPE',
        kind => 'GRANT',
        parser => \&_allow_deny_ace_object_type_parser,
        generator => \&_allow_deny_ace_object_type_generator,
    },
    # ACCESS_DENIED_OBJECT_ACE_TYPE
    {
        name => 'ACCESS_DENIED_OBJECT_ACE_TYPE',
        kind => 'DENY',
        parser => \&_allow_deny_ace_object_type_parser,
        generator => \&_allow_deny_ace_object_type_generator,
    },
    undef, # SYSTEM_AUDIT_OBJECT_ACE_TYPE
    undef, # SYSTEM_ALARM_OBJECT_ACE_TYPE
    undef, # ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    undef, # ACCESS_DENIED_CALLBACK_ACE_TYPE
    undef, # ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    undef, # ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    undef, # SYSTEM_AUDIT_CALLBACK_ACE_TYPE
    undef, # SYSTEM_ALARM_CALLBACK_ACE_TYPE
    undef, # SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
    undef, # SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    undef, # SYSTEM_MANDATORY_LABEL_ACE_TYPE
    undef, # SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
    undef, # SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
];

sub new {
    my ($class, $header, $bytestream) = @_;

    my $self = bless {
        header => $header,
        bytestream => $bytestream,
    }, $class;

    $self->setup;
    return $self;
}

sub create {
    my ($class, $hr) = @_;

    # default ace_flags to 0...
    unless ($hr->{ace_flags}) {
        $hr->{ace_flags} = 0;
    }

    # also with the internal flags...
    unless ($hr->{flags}) {
        $hr->{flags} = 0;
    }

    my $self = bless {}, $class;
    ($self->{header}, $self->{bytestream}) = $ace_types->[$hr->{ace_type}]->{generator}->($self, $hr);

    $self->setup;
    return $self;
}

sub setup {
    my ($self) = @_;

    $self->{ace_type} = $self->header->{ace_type};

    # parse all the aces!
    if (defined($ace_types->[$self->header->{ace_type}])) {
        # dispatch to the "parser" defined above for this ace_type
        $self->{entry} = $ace_types->[$self->header->{ace_type}]->{parser}->(
            $self, 
            $self->bytestream->substr(4, length($self->bytestream) - 4)
        );

        # get the name out of that type's definition too
        $self->{type} = $ace_types->[$self->header->{ace_type}]->{name};

        # and what kind DENY/GRANT of ACE are we?
        $self->{kind} = $ace_types->[$self->header->{ace_type}]->{kind};
    }
}

sub object_type {
    my ($self) = @_;
    return $self->entry->{object_type};
}

sub inherited_object_type {
    my ($self) = @_;
    return $self->entry->{inherited_object_type};
}

sub mask {
    my ($self) = @_;
    return $self->entry->{mask};
}

sub flags {
    my ($self) = @_;
    return $self->entry->{flags};
}

sub sid {
    my ($self) = @_;
    return $self->entry->{sid};
}

#
# Parser / Generator implementations
#

sub _allow_deny_ace_object_type_generator {
        my ($self, $hr) = @_;
        my $bs;

        if ($hr->{object_type} && !($hr->{flags} & ACE_OBJECT_TYPE_PRESENT)) {
            # an object_type was provided, let's set up the flags automatically.
            $hr->{flags} += ACE_OBJECT_TYPE_PRESENT;
        }

        if ($hr->{inherited_object_type} && !($hr->{flags} & ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
            # an inherited_object_type was provided, let's set up the flags automatically!
            $hr->{flags} += ACE_INHERITED_OBJECT_TYPE_PRESENT;
        }

        # add the mask and flags to the bytestream
        $bs .= pack('I<I<', $hr->{mask}, $hr->{flags});

        # if present, add the object_type
        if ($hr->{flags} & ACE_OBJECT_TYPE_PRESENT) {
            $bs .= $self->uuid_string_to_bytes($hr->{object_type});
        }

        # same for inherited_object_type
        if ($hr->{flags} & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            $bs .= $self->uuid_string_to_bytes($hr->{inherited_object_type});
        }

        unless (ref($hr->{sid}) eq "Data::NTSD::SID") {
            # they didn't pass us a SID object, assume it's a string (fatal error if it isn't a SID string)
            $hr->{sid} = Data::NTSD::SID->create($hr->{sid});
        }

        $bs .= $hr->{sid}->bytestream;

        # okay now we have everything but the size for the header, which we can generate now..
        my $header = {
            # size must be cleanly divisible by 4.  microsoft says so.
            ace_size => length($bs) + 4 + ((length($bs) + 4) % 4), 
            ace_type => $hr->{ace_type},

            # ace_flags are the outer flags.  "flags" in this are specific to this ACE TYPE.
            ace_flags => $hr->{ace_flags}, 
        };

        $bs = Data::NTSD::ByteStream->new(
            pack("CCS<", 
                $header->{ace_type},
                $header->{ace_flags}, 
                $header->{ace_size}, 
            ) . $bs
        );

        return ($header, $bs);
}

sub _allow_deny_ace_object_type_parser {
        my ($self, $bs) = @_;
        my $hr = {
            mask => unpack('I<', $bs->substr(0, 4)),
            flags => unpack('I<', $bs->substr(4, 4)),
        };

        my $pos = 8;
        if ($hr->{flags}) {
            if ($hr->{flags} & ACE_OBJECT_TYPE_PRESENT) {
                my $uuid = $self->parse_uuid($bs->substr($pos, 16));
                $pos += 16;

                $hr->{object_type} = $uuid->{string};
            }

            if ($hr->{flags} & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
                my $uuid = $self->parse_uuid($bs->substr($pos, 16));
                $pos += 16;

                # pull these out!
                $hr->{inherited_object_type} = $uuid->{string};
            }
        }

        $hr->{sid} = Data::NTSD::SID->new($bs->substr($pos, (length($bs) - 4)));
        return $hr;
}

1;