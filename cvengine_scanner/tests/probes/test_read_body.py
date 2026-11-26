"""``transport.read_body``: the bounded body reader every in-process HTTP probe uses, frozen against its specification.

Some embedded servers answer gzip or deflate although the probe asked for identity. The reader decodes those, caps the decoded output at
``max_bytes``, bounds the compressed input at ``max_bytes + COMPRESSED_SLACK``, and reports the first ``WIRE_HEAD`` received bytes.
"""
import gzip
import os
import zlib
from unittest import TestCase

from cvengine_scanner.probes import transport

DOC = b'<!doctype html><title>Relay console</title><p>Model RX-7 firmware 2.4.1</p>' * 3


class Reply:
    """A stand-in for ``http.client.HTTPResponse`` holding a fixed body: records every ``read`` size, can split the body into
    preset piece sizes and can answer ``None`` instead of bytes."""

    def __init__(self, body, encoding=None, pieces=None, none_reads=False):
        self.body, self.pos, self.encoding = body, 0, encoding
        self.pieces, self.none_reads, self.asked, self.header_calls = list(pieces or []), none_reads, [], []

    def getheader(self, *args):
        self.header_calls.append(args)
        return self.encoding if args[0].lower() == 'content-encoding' else None

    def read(self, *args):
        self.asked.append(args)
        size = args[0]
        if self.pieces:
            size = min(size, self.pieces.pop(0))
        piece = self.body[self.pos:self.pos + size]
        self.pos += len(piece)
        if self.none_reads and not piece:
            return None
        return piece

    @property
    def consumed(self):
        return self.pos


def bare_deflate(data):
    packer = zlib.compressobj(level=6, wbits=-15)
    return packer.compress(data) + packer.flush()


def padded_deflate(data, empty_blocks):
    """A valid bare deflate stream that decodes to ``data`` but starts with ``empty_blocks`` empty stored blocks of five bytes each
    (a non-final stored block of length 0), so its compressed size is large while its decoded size is tiny."""
    return b'\x00\x00\x00\xff\xff' * empty_blocks + bare_deflate(data)


class FixedValuesTests(TestCase):
    def test_constants(self):
        self.assertEqual(transport.COMPRESSED_SLACK, 4096)
        self.assertEqual(transport.WIRE_HEAD, 16)

    def test_header_is_asked_for_by_its_name_only(self):
        reply = Reply(DOC)
        transport.read_body(reply, 50)
        self.assertEqual(reply.header_calls, [('Content-Encoding',)])


class IdentityTests(TestCase):
    def test_no_header_identity_and_empty_value_read_once_at_the_cap(self):
        for encoding in (None, '', '  ', 'identity', 'IDENTITY', ' Identity\t'):
            reply = Reply(DOC, encoding)
            self.assertEqual(transport.read_body(reply, 1000), DOC, encoding)
            self.assertEqual(reply.asked, [(1000,)], encoding)

    def test_cap_and_wire_head(self):
        wire = {}
        self.assertEqual(transport.read_body(Reply(DOC), 40, wire=wire), DOC[:40])
        self.assertEqual(wire, {'head': DOC[:16]})
        wire = {}
        self.assertEqual(transport.read_body(Reply(b'tiny'), 40, wire=wire), b'tiny')
        self.assertEqual(wire, {'head': b'tiny'})
        wire = {}
        self.assertEqual(transport.read_body(Reply(b''), 40, wire=wire), b'')
        self.assertEqual(wire, {'head': b''})

    def test_none_from_read_is_empty(self):
        wire = {}
        self.assertEqual(transport.read_body(Reply(b'', none_reads=True), 40, wire=wire), b'')
        self.assertEqual(wire, {'head': b''})

    def test_cap_is_normalised_to_a_non_negative_int(self):
        for cap, asked in ((-5, 0), (0, 0), ('12', 12), (7.9, 7)):
            reply = Reply(DOC)
            self.assertEqual(transport.read_body(reply, cap), DOC[:asked], cap)
            self.assertEqual(reply.asked, [(asked,)], cap)


class DecodeTests(TestCase):
    def test_gzip_zlib_and_bare_deflate_decode_whatever_the_header_case(self):
        cases = [('gzip', gzip.compress(DOC)), (' GZIP ', gzip.compress(DOC)), ('deflate', zlib.compress(DOC)),
                 ('Deflate', bare_deflate(DOC)), ('deflate\n', zlib.compress(DOC, 9)), ('deflate', bare_deflate(b'x'))]
        for encoding, body in cases:
            expected = b'x' if body == bare_deflate(b'x') else DOC
            self.assertEqual(transport.read_body(Reply(body, encoding), 5000), expected, encoding)

    def test_wire_head_holds_the_compressed_bytes_as_received(self):
        body = gzip.compress(DOC)
        wire = {}
        transport.read_body(Reply(body, 'gzip'), 5000, wire=wire)
        self.assertEqual(wire, {'head': body[:16]})
        self.assertEqual(wire['head'][:2], b'\x1f\x8b')

    def test_wire_head_is_set_once_from_the_first_piece_even_when_short(self):
        body = gzip.compress(DOC)
        wire = {}
        self.assertEqual(transport.read_body(Reply(body, 'gzip', pieces=[5, 3, 100]), 5000, wire=wire), DOC)
        self.assertEqual(wire, {'head': body[:5]})

    def test_pieces_of_any_size_decode_the_same(self):
        body = zlib.compress(DOC)
        for split in ([2] + [1] * len(body), [2, 1, 7], [len(body)]):
            self.assertEqual(transport.read_body(Reply(body, 'deflate', pieces=list(split)), 5000), DOC, split)

    def test_header_check_uses_only_the_first_piece(self):
        # a zlib stream whose first piece is one byte cannot pass the two byte header test, so it is read as bare deflate and fails
        with self.assertRaises(ValueError):
            transport.read_body(Reply(zlib.compress(DOC), 'deflate', pieces=[1]), 5000)

    def test_cap_reached_exactly_or_with_room_returns_the_whole_page(self):
        for cap in (len(DOC), len(DOC) + 1, len(DOC) * 10):
            self.assertEqual(transport.read_body(Reply(gzip.compress(DOC), 'gzip'), cap), DOC, cap)

    def test_a_large_page_is_truncated_at_the_cap_not_an_error(self):
        page = os.urandom(30_000)
        self.assertEqual(transport.read_body(Reply(gzip.compress(page), 'gzip'), 1234), page[:1234])

    def test_bytes_after_the_stream_end_are_ignored(self):
        self.assertEqual(transport.read_body(Reply(gzip.compress(DOC) + b'trailing junk', 'gzip'), 5000), DOC)
        self.assertEqual(transport.read_body(Reply(gzip.compress(DOC) + gzip.compress(b'second member'), 'gzip'), 5000), DOC)
        self.assertEqual(transport.read_body(Reply(zlib.compress(DOC) + b'\x00' * 50, 'deflate'), 5000), DOC)

    def test_zero_cap_reads_nothing(self):
        reply, wire = Reply(gzip.compress(DOC), 'gzip'), {}
        self.assertEqual(transport.read_body(reply, 0, wire=wire), b'')
        self.assertEqual((reply.asked, wire), ([], {}))

    def test_an_empty_compressed_body_is_empty(self):
        for encoding in ('gzip', 'deflate'):
            wire = {}
            self.assertEqual(transport.read_body(Reply(b'', encoding), 100, wire=wire), b'', encoding)
            self.assertEqual(wire, {}, encoding)
            self.assertEqual(transport.read_body(Reply(b'', encoding, none_reads=True), 100), b'', encoding)


class LimitTests(TestCase):
    """Decompression bombs and oversized compressed input stop at fixed limits."""

    def test_gzip_bomb_stops_at_the_decoded_cap_and_the_input_bound(self):
        bomb = gzip.compress(b'\0' * 50_000_000, compresslevel=9)
        self.assertLess(len(bomb), 100_000)
        reply = Reply(bomb, 'gzip')
        out = transport.read_body(reply, 64 * 1024)
        self.assertEqual(out, b'\0' * (64 * 1024))
        self.assertLessEqual(reply.consumed, 64 * 1024 + transport.COMPRESSED_SLACK)

    def test_deflate_bombs_stop_at_the_cap(self):
        for body in (zlib.compress(b'Z' * 8_000_000, 9), bare_deflate(b'Z' * 8_000_000)):
            self.assertEqual(transport.read_body(Reply(body, 'deflate'), 777), b'Z' * 777)

    def test_every_compressed_read_is_explicit_and_at_most_4096(self):
        reply = Reply(gzip.compress(os.urandom(50_000)), 'gzip')
        transport.read_body(reply, 60_000)
        self.assertTrue(reply.asked)
        for args in reply.asked:
            self.assertEqual(len(args), 1)
            self.assertIsInstance(args[0], int)
            self.assertTrue(0 < args[0] <= 4096, args)

    def test_reads_never_ask_beyond_the_input_bound(self):
        body = padded_deflate(b'short', 3000)  # about 15 KB of compressed input for five decoded bytes
        self.assertGreater(len(body), 100 + transport.COMPRESSED_SLACK)
        reply = Reply(body, 'deflate')
        with self.assertRaisesRegex(ValueError, '^incomplete compressed probe response$'):
            transport.read_body(reply, 100)
        self.assertEqual(reply.consumed, 100 + transport.COMPRESSED_SLACK)
        self.assertEqual(sum(args[0] for args in reply.asked), 100 + transport.COMPRESSED_SLACK)
        # with a cap large enough the same stream decodes
        self.assertEqual(transport.read_body(Reply(body, 'deflate'), 20_000), b'short')


class ErrorTests(TestCase):
    def test_garbage_is_invalid_and_chained_to_the_zlib_error(self):
        for encoding, body in (('gzip', b'this is not a gzip stream'), ('deflate', b'\x78\x9c\xff\xff\xff\xff\xff')):
            with self.assertRaisesRegex(ValueError, '^invalid compressed probe response$') as caught:
                transport.read_body(Reply(body, encoding), 100)
            self.assertIsInstance(caught.exception.__cause__, zlib.error)

    def test_a_cut_stream_is_incomplete(self):
        for encoding, body in (('gzip', gzip.compress(os.urandom(5000))[:300]), ('deflate', zlib.compress(os.urandom(5000))[:300])):
            with self.assertRaisesRegex(ValueError, '^incomplete compressed probe response$'):
                transport.read_body(Reply(body, encoding), 10_000)

    def test_other_encodings_are_refused_before_any_read(self):
        for encoding in ('br', 'zstd', 'compress', 'x-gzip', 'gzip, br', 'deflate,gzip', 'chunked'):
            reply = Reply(gzip.compress(DOC), encoding)
            with self.assertRaisesRegex(ValueError, '^unsupported probe content encoding$'):
                transport.read_body(reply, 100)
            self.assertEqual(reply.asked, [], encoding)
