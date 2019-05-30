 #!/usr/bin/env python

import struct

CONTROL_ACCEPT = 0x01
CONTROL_START = 0x02
CONTROL_STOP = 0x03

CONTROL_FIELD_CONTENT_TYPE = 0x01

MAX_CONTROL_FRAME_LENGTH = 512

be32 = struct.Struct('!i')

class ContentTypeMismatch(Exception):
    pass

class DecodingError(Exception):
    pass

class EncodingError(Exception):
    pass

def decode_control_start_data(data):
    if len(data) >= 4:
        if be32.unpack(data[0:4])[0] == CONTROL_FIELD_CONTENT_TYPE:
            if len(data) >= 8:
                len_content_type = be32.unpack(data[4:8])[0]
                if len(data) != len_content_type + 8:
                    raise DecodingError
                return data[8:]

class reader(object):
    def __init__(self, fileobj, wanted_content_type=None):
        self.stopped = False
        self.fileobj = fileobj
        self.wanted_content_type = wanted_content_type
        self.stream_content_type = None
        self.read_control_start()

    def __iter__(self):
        return self

    def read_be32(self):
        return be32.unpack(self.fileobj.read(4))[0]

    def read_control_start(self):
        escape = self.read_be32()
        if escape != 0:
            raise DecodingError
        len_control_frame = self.read_be32()
        if len_control_frame > 0:
            control_frame = self.fileobj.read(len_control_frame)
            if len(control_frame) != len_control_frame:
                raise DecodingError
            control_frame_type = be32.unpack(control_frame[0:4])[0]
            if control_frame_type != CONTROL_START:
                raise DecodingError
            if len(control_frame) > 4:
                self.stream_content_type = decode_control_start_data(control_frame[4:])
            if self.wanted_content_type != None:
                if self.wanted_content_type != self.stream_content_type:
                    #raise ContentTypeMismatch, 'want content_type %r, but stream has content_type %r' % (self.wanted_content_type, self.stream_content_type)
                    pass

    def read_control_stop(self):
        len_control_frame = self.read_be32()
        if len_control_frame >= 4:
            control_frame = self.fileobj.read(len_control_frame)
            if len(control_frame) != len_control_frame:
                raise DecodingError
            control_frame_type = be32.unpack(control_frame[0:4])[0]
            if control_frame_type == CONTROL_STOP:
                return True
            else:
                return False

    def __next__(self):
        if self.stopped:
            raise StopIteration
        while True:
            len_frame = self.read_be32()
            if len_frame == 0:
                if self.read_control_stop():
                    self.stopped = True
                    raise StopIteration
            else:
                break
        return self.fileobj.read(len_frame)

class writer(object):
    def __init__(self, fileobj, content_type=None):
        self.fileobj = fileobj
        self.content_type = content_type
        self.write_control_start()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __del__(self):
        self.close()

    def write_be32(self, i):
        self.fileobj.write(be32.pack(i))

    def write_control_start(self):
        control_frame = be32.pack(CONTROL_START)
        if self.content_type:
            control_frame += be32.pack(CONTROL_FIELD_CONTENT_TYPE)
            control_frame += be32.pack(len(self.content_type))
            control_frame += self.content_type

        # Escape sequence.
        self.write_be32(0)

        # Length of control frame.
        if len(control_frame) > MAX_CONTROL_FRAME_LENGTH:
            raise EncodingError
        self.write_be32(len(control_frame))

        # The control frame.
        self.fileobj.write(control_frame)

    def write_control_stop(self):
        control_frame = be32.pack(CONTROL_STOP)

        # Escape sequence.
        self.write_be32(0)

        # Length of control frame.
        self.write_be32(len(control_frame))

        # The control frame.
        self.fileobj.write(control_frame)

    def close(self):
        try:
            if not self.closed:
                self.write_control_stop()
                self.fileobj.close()
                self.closed = True
        except:
            self.closed = True
            raise

    def write_data(self, data):
        self.write_be32(len(data))
        self.fileobj.write(data)
