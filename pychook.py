import marshal
import struct
import cStringIO

interned_strs = []

class file_writer():
	def __init__(self, writer):
		self.writer = writer

	def write_int32(self, val):
		buff = chr(val & 0xFF) + chr((val & 0xFF00) >> 8) + chr((val & 0xFF0000) >> 16) + chr((val & 0xFF000000) >> 24)
		self.writer.write(buff)

	def write_int64(self, val):
		buff = chr(val & 0xFF) + chr((val & 0xFF00) >> 8) + chr((val & 0xFF0000) >> 16) + chr((val & 0xFF000000) >> 24) \
				+ chr((val & 0xFF00000000) >> 32) + chr((val & 0xFF0000000000) >> 40) + chr((val & 0xFF0000000000) >> 48) + chr((val & 0xFF000000000000) >> 56)
		self.writer.write(buff)

	def write_double(self, val):
		self.write(struct.pack('d', self.val))
	
	def write(self, data):
		self.writer.write(data)

	def close(self):
		self.writer.close()

class pyc_none():
	def __init__(self, f):
		pass

	def get_value(self):
		return None

	def get_type(self):
		return 'N'

	def dump(self, writer):
		writer.write(self.get_type())

class pyc_strref():
	def __init__(self, f):
		self.val = f.read_int32()
	
	def get_value(self):
		return self.val

	def get_str(self):
		return interened_strs[self.val]

	def get_type(self):
		return 'R'

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_int32(self.val)

class pyc_int():
	def __init__(self, f):
		self.val = f.read_int32()
	
	def get_value(self):
		return self.val

	def get_type(self):
		return 'i'

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_int32(self.val)

class pyc_int64():
	def __init__(self, f):
		self.val = f.read_int64()

	def get_val(self):
		return self.val

	def get_type(self):
		return 'I'

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_int64(self.val)

class pyc_binary_float():
	def __init__(self, f):
		self.val = f.read_double()

	def get_value(self):
		return self.val

	def get_type(self):
		return 'g'
	
	def dump(self, writer):
		writer.write(self.get_type())
		writer.write(struct.pack('d', self.val))

class pyc_binary_complex():
	def __init__(self, f):
		self.real = f.read_double()
		self.imag = f.read_double()

	def get_value(self):
		return (self.real, self.imag)

	def get_type(self):
		return 'y'

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_float(self.real)
		writer.write_float(self.imag)


class pyc_str():
	def __init__(self, f, interned=False):
		length = f.read_int32()
		self.val = f.read(length)
		self.interned = interned
		if self.interned:
			interned_strs.append(self)

	def set_value(self, value):
		self.val = value

	def get_value(self):
		return self.val
	
	def get_type(self):
		if not self.interned:
			return 's'
		else:
			return 't'

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_int32(len(self.val))
		writer.write(self.val)

class pyc_tuple():
	def __init__(self, f):
		count = f.read_int32()
		self.values = []
		for i in range(count):
			self.values.append(f.unmarshal())

	def append(self, v):
		self.values.append(v)

	def get_len(self):
		return len(self.values)

	def get_value(self):
		return tuple(self.values)

	def get_type(self):
		return '('

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_int32(len(self.values))
		for v in self.values:
			v.dump(writer)

class pyc_code():
	def __init__(self, f):
		self.argcount = f.read_int32()
		self.nlocals = f.read_int32()
		self.stacksize = f.read_int32()
		self.flags = f.read_int32()
		self.code = f.unmarshal()
		self.consts = f.unmarshal()
		self.names = f.unmarshal()
		self.varnames = f.unmarshal()
		self.freevars = f.unmarshal()
		self.cellvars = f.unmarshal()
		self.filename = f.unmarshal()
		self.name = f.unmarshal()
		self.firstlineno = f.read_int32()
		self.lnotab = f.unmarshal()

	def hook_func(self, f):
		func_data = cStringIO.StringIO(marshal.dumps(f.func_code))
		func_data.seek(1) # skip the first byte of the file
		c = pyc_code(file_reader(func_data))
		self.hook(c)

	def hook(self, c):
		self.consts.append(c)
		func_index = self.consts.get_len() -1
		self.code.set_value('\x64' + chr(func_index & 0xFF) + chr((func_index & 0xFF00) >> 8) + '\x84\x00\x00\x83\x00\x00\x01' + self.code.get_value())
	
	def get_function(self, name):
		start = name.split('.', 1)[0]
		tail = None
		if len(name) > len(start):
			tail = name[len(start) + 1:]
	
		for c in self.consts.get_value():
			if c.get_type() == 'c':
				if c.get_name() == start:
					if tail == None:
						return c
					else:
						return c.get_function(tail)

	def get_name(self):
		return self.name.get_value()
	
	def get_type(self):
		return 'c'

	def dump(self, writer):
		writer.write(self.get_type())
		writer.write_int32(self.argcount)
		writer.write_int32(self.nlocals)
		writer.write_int32(self.stacksize)
		writer.write_int32(self.flags)
		self.code.dump(writer)
		self.consts.dump(writer)
		self.names.dump(writer)
		self.varnames.dump(writer)
		self.freevars.dump(writer)
		self.cellvars.dump(writer)
		self.filename.dump(writer)
		self.name.dump(writer)
		writer.write_int32(self.firstlineno)
		self.lnotab.dump(writer)

class file_reader():
	object_types = { 'i': pyc_int,
			'I': pyc_int64,
			'g': pyc_binary_float,
			'y': pyc_binary_complex,
			'(': pyc_tuple,
			's': pyc_str,
			'c': pyc_code,
			'R': pyc_strref,
			'N': pyc_none }

	def __init__(self, reader):
		self.reader = reader

	def unmarshal(self):
		t = self.reader.read(1)[0]
		
		# special case for interned strings, gotta make it nicer
		if t == 't':
			return file_reader.object_types['s'](self, interned=True)
		return file_reader.object_types[t](self)

	def read_int32(self):
		buff = self.reader.read(4)
		return ord(buff[0]) | ord(buff[1]) << 8 | ord(buff[2]) << 16 | ord(buff[3]) << 24

	def read_int64(self):
		buff = self.reader.read(8)
		return ord(buff[0]) | ord(buff[1]) << 8 | ord(buff[2]) << 16 | ord(buff[3]) << 24 | ord(buff[4]) << 32 | ord(buff[5]) << 40 | ord(buff[6]) << 48 | ord(buff[7]) << 56

	def read_double(self):
		return struct.unpack('d', self.read(8))[0]

	def read(self, length):
		return self.reader.read(length)

	def close(self):
		self.reader.close()


class PyBinary():
	def __init__(self, filename):
		self.filename = filename
		f = file_reader(open(filename, 'rb'))
		self.magic = f.read_int32()
		self.timestamp = f.read_int32()
		self.code = f.unmarshal()
		f.close()

	def dump_to_file(self, filename):
		w = file_writer(open(filename, 'wb'))
		w.write_int32(self.magic)
		w.write_int32(self.timestamp)
		self.code.dump(w)
		w.close()

	def save(self):
		self.dump_to_file(self.filename)
