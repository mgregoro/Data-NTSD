use strict;
use warnings;
package Data::NTSD::ByteStream;
use Mojo::Base 'Mojo::ByteStream';

sub substr {
    my ($self, $offset, $length) = @_;

    return $self->new(substr($self, $offset, $length));
}

1;
