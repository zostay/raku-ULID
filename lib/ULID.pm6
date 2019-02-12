use v6;

unit module ULID:auth<github:zostay>:ver<0.0.0>;

class GLOBAL::X::ULID is Exception {
    has $.message;
}

# See https://www.crockford.com/wrmg/base32.html
# 32 letters, 0 .. 9, A .. Z except I, L, O, U
constant @crockford-out = grep <I L O U>.none, flat '0' .. '9', 'A' .. 'H', 'J', 'K', 'M', 'N', 'P' .. 'T', 'V' .. 'Z';

constant @bitmasking = (
     3, 0b11111000, 0, 0b00000000,
    -2, 0b00000111, 6, 0b11000000,
     1, 0b00111110, 0, 0b00000000,
    -4, 0b00000001, 4, 0b11110000,
    -1, 0b00001111, 7, 0b10000000,
     2, 0b01111100, 0, 0b00000000,
    -3, 0b00000011, 5, 0b11100000,
     0, 0b00011111, 0, 0b00000000,
).rotor(4);

constant @bitmasking-offsets = 0, 3, 6, 1, 4, 0;

my sub crockford(Blob:D $bin --> Seq:D) {
    # These exceptions should never be thrown
    die "cannot encode empty blob"
        unless $bin.elems > 0;
    die "expected blob8, but got something else"
        unless $bin.elems == $bin.bytes;

    my $total-bits = $bin.bytes * 8;
    my $pad-bits   = (5 - $total-bits % 5) % 5;

    # say "Input = $bin.perl()";
    # say "Bits = $total-bits, Padding = $pad-bits";

    my @bitmasks   = @bitmasking.rotate(@bitmasking-offsets[$pad-bits]);
    my @bytes      = @$bin;

    @bytes.unshift(0) if $pad-bits;

    my $index = 1;
    my $segment = 0;
    gather {
        loop {
            my ($mss, $msm, $lss, $lsm) = @bitmasks[ $segment++ % @bitmasking ];
            my $ubits = ((@bytes[$index - 1] +& $msm) +> $mss)
                    +| ((@bytes[$index]     +& $lsm) +> $lss);

            # printf "%s %08b <- %08b +& %08b +> %2d +| %08b +& %08b +> %2d\n",
            #     @crockford-out[ $ubits ],
            #     $ubits,
            #     @bytes[$index - 1], $msm, $mss,
            #     @bytes[$index], $lsm, $lss,
            #     ;

            take @crockford-out[ $ubits ];

            $index++ if $lss || !$mss;
            last if $index >= @bytes;
        }

        # There's one more 5-bit to grab, but it's the easy one
        take @crockford-out[ @bytes[*-1] +& 0b00011111 ];
    }
}

constant @time-bytes =
    0xFF0000000000, 40,
    0x00FF00000000, 32,
    0x0000FF000000, 24,
    0x000000FF0000, 16,
    0x00000000FF00,  8,
    0x0000000000FF,  0,
    ;

our sub ulid-now(--> Int:D) is export(:time) {
    my $now         = now;
    my ($unix-secs) = $now.to-posix;
    Int(($unix-secs + ($now - $now.floor)) * 1000);
}

our sub ulid-time(Int:D $now --> Seq:D) is export(:parts) {
    my @bytes = @time-bytes.map(-> $m, $s { $now +& $m +> $s });
    crockford(Blob.new(@bytes));
}

my sub random-number($x) { $x.rand.floor }

constant $zero = Blob.new: 0 xx 10;
my $previous-time = 0;
my $previous-random;
our sub ulid-random(
    Int:D $now,
    :&random-function = &random-number,
    Bool:D :$monotonic = False,
    --> Seq:D
) is export(:parts) {
    my $random-blob;

    if $monotonic && $now == $previous-time {
        my $nudging = True;
        $random-blob = Blob.new: @($previous-random).reverse.map({
            if $nudging {
                if $_ < 0xFF {
                    $nudging--;
                    $_ + 1;
                }
                else {
                    0x00;
                }
            }
            else {
                $_
            }
        }).reverse;

        if $random-blob eq $zero {
            die X::ULID.new(message => "monotonic ULID overflow");
        }
    }
    else {
        $random-blob = Blob.new: (^10).map({ 0x100.&random-function });
    }

    $previous-time   = $now;
    $previous-random = $random-blob;

    crockford($random-blob);
}

our proto ulid(|) is export(:DEFAULT, :ulid) { * }

multi ulid(Bool:D :$str!, |c --> Str:D) { $str ?? samewith(|c).join !! samewith(|c) }

multi ulid(
    Int:D() $now       = ulid-now,
    Bool:D :$monotonic = False,
    :&random-function  = &random-number,
    --> Seq:D
) {
    flat ulid-time($now), ulid-random($now, :$monotonic, :&random-function)
}
