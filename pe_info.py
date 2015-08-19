#coding: gbk

from collections import namedtuple
from collections import OrderedDict
import struct, os

IMAGE_DOS_HEADER_DEF = OrderedDict([
	('e_magic',     'H'),                # Magic number
	('e_cblp',      'H'),                # Bytes on last page of file
	('e_cp',        'H'),                # Pages in file
	('e_crlc',      'H'),                # Relocations
	('e_cparhdr',   'H'),                # Size of header in paragraphs
	('e_minalloc',  'H'),                # Minimum extra paragraphs needed
	('e_maxalloc',  'H'),                # Maximum extra paragraphs needed
	('e_ss',        'H'),                # Initial (relative) SS value
	('e_sp',        'H'),                # Initial SP value
	('e_csum',      'H'),                # Checksum
	('e_ip',        'H'),                # Initial IP value
	('e_cs',        'H'),                # Initial (relative) CS value
	('e_lfarlc',    'H'),                # File address of relocation table
	('e_ovno',      'H'),                # Overlay number
	('e_res',       '8s'),               # Reserved words(4 WORD = 8 bytes)
	('e_oemid',     'H'),                # OEM identifier (for e_oeminfo)
	('e_oeminfo',   'H'),                # OEM information, e_oemid specific
	('e_res2',      '20s'),              # Reserved words(10 WORD = 20 bytes)
	('e_lfanew',    'L'),                # File address of new exe header
])
IMAGE_DOS_HEADER = namedtuple('IMAGE_DOS_HEADER', IMAGE_DOS_HEADER_DEF.keys())


IMAGE_FILE_HEADER_DEF = OrderedDict([
	('Machine',		'H'),    #014C-IMAGE_FILE_MACHINE_I386
	('NumberOfSections',	'H'),    #PE������-0007����
	('TimeDateStamp',	'I'),    #ʱ���
	('PointerToSymbolTable','I'),    #ָ����ű�
	('NumberOfSymbols',	'I'),    #���ű�����
	('SizeOfOptionalHeader','H'),    #��չPEͷ��С
	('Characteristics',	'H'),	#�ļ�����0102-IMAGE_FILE_32BIT_MACHINE|IMAGE_FILE_EXECUTABLE_IMAGE
])
IMAGE_FILE_HEADER = namedtuple('IMAGE_FILE_HEADER', IMAGE_FILE_HEADER_DEF.keys())

IMAGE_DATA_DIRECTORY_DEF = OrderedDict([
	('VirtualAddress',	'I'),
	('Size',		'I'),
])
Image_DATA_DIRECTORY = namedtuple('IMAGE_DATA_DIRECTORY', IMAGE_DATA_DIRECTORY_DEF.keys())

IMAGE_OPTIONAL_HEADER_DEF = OrderedDict([
	#Standard fields.
	('Magic',                      'H'),    #010B-IMAGE_NT_OPTIONAL_HDR32_MAGIC
	('MajorLinkerVersion',         'B'),    #0A-���������汾��
	('MinorLinkerVersion',         'B'),    #00-������С�汾��
	('SizeOfCode',                 'I'),    #0000008A(138)-����ڴ�С
	('SizeOfInitializedData',      'I'),    #0000004C(76)-�ѳ�ʼ�����ݴ�С
	('SizeOfUninitializedData',    'I'),    #00000000(0)-Ϊ��ʼ�����ݴ�С
	('AddressOfEntryPoint',        'I'),    #000110AA������ڵ�ַ
	('BaseOfCode',                 'I'),    #00001000����λ���ַ
	('BaseOfData',                 'I'),    #00001000���ݶλ���ַ

	# NT additional fields.
	('ImageBase',                  'I'),    #������ػ���ַ00400000
	('SectionAlignment',           'I'),    #�ڶ���0001000(4096)
	('FileAlignment',              'I'),    #�ļ�����0000200(512)
	('MajorOperatingSystemVersion','H'),    #����ϵͳ���汾��0005
	('MinorOperatingSystemVersion','H'),    #����ϵͳС�汾��0001
	('MajorImageVersion',          'H'),    #�������汾��0000
	('MinorImageVersion',          'H'),    #����С�汾��0000
	('MajorSubsystemVersion',      'H'),    #��ϵͳ���汾��0005
	('MinorSubsystemVersion',      'H'),    #��ϵͳС�汾��0001
	('Win32VersionValue',          'I'),    #0
	('SizeOfImage',                'I'),    #�����С00022000
	('SizeOfHeaders',              'I'),    #ͷ��С0400
	('CheckSum',                   'I'),    #0
	('Subsystem',                  'H'),    #03-IMAGE_SUBSYSTEM_WINDOWS_CUI
	('DllCharacteristics',         'H'),    #8140IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE        
	('SizeOfStackReserve',         'I'),    #ջ��ʼ����С010000
	('SizeOfStackCommit',          'I'),    #ջ�ύ��С01000
	('SizeOfHeapReserve',          'I'),    #�ѳ�ʼ����С010000
	('SizeOfHeapCommit',           'I'),    #���ύ��С01000
	('LoaderFlags',                'I'),    #0
	('NumberOfRvaAndSizes',        'I'),    #10(16)
	#IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//����Ŀ¼��
])

IMAGE_OPTIONAL_HEADER = namedtuple('IMAGE_OPTIONAL_HEADER', IMAGE_OPTIONAL_HEADER_DEF.keys())

class PEInfo(object):
	def __init__(self, filename):
		self.DosHeader = None
		self.Signature = None
		self.FileHeader = None
		self.OptHeader = None
		# EXPORT table, IMPORT table, RESOURCE table, EXCEPTION table
		# CERTIFICATE table, BASE-RELOCATION table, DEBUG Directory
		# Architecture Specified Data, GLOBAL POINTER Register
		# TLS table, LOAD CONFIGURATION table, BOUND IMPORT table
		# IMPORT Address table, DELAY IMPORT Descriptors, CLI Header, Reserved
		self.DataDirectory = []

		self.build(filename)

	def build(self, filename):
		print '----------------------------------------------------------'
		try:
			f = open(filename)
		except:
			return

		try:
			#read dos header
			fmt = '@' + ''.join(IMAGE_DOS_HEADER_DEF.values())
			fmt_size = struct.calcsize(fmt)
			buf = f.read(fmt_size)
			data = struct.unpack(fmt, buf)
			self.DosHeader = IMAGE_DOS_HEADER._make(data)
			print 'dos header', self.DosHeader

			#read signature
			f.seek(self.DosHeader.e_lfanew, os.SEEK_SET)
			fmt = '@4s'
			fmt_size = struct.calcsize(fmt)
			buf = f.read(fmt_size)
			self.Signature = struct.unpack(fmt, buf)
			print 'signature', self.Signature

			#read file header
			fmt = '@' + ''.join(IMAGE_FILE_HEADER_DEF.values())
			fmt_size = struct.calcsize(fmt)
			buf = f.read(fmt_size)
			data = struct.unpack(fmt, buf)
			self.FileHeader = IMAGE_FILE_HEADER._make(data)
			print 'file header', self.FileHeader

			#read opt header
			fmt = '@' + ''.join(IMAGE_OPTIONAL_HEADER_DEF.values())
			fmt_size = struct.calcsize(fmt)
			buf = f.read(self.FileHeader.SizeOfOptionalHeader)
			data = struct.unpack(fmt, buf[:fmt_size])
			self.OptionalHeader = IMAGE_OPTIONAL_HEADER._make(data)
			print 'opt header', self.OptionalHeader

			cur = fmt_size

			for i in xrange(self.OptionalHeader.NumberOfRvaAndSizes):
				fmt = '@' + ''.join(IMAGE_DATA_DIRECTORY_DEF.values())
				fmt_size = struct.calcsize(fmt)
				data = struct.unpack(fmt, buf[cur:(cur+fmt_size)])
				dd = Image_DATA_DIRECTORY._make(data)
				self.DataDirectory.append(dd)
				cur = cur + fmt_size
				print 'Data Dir:', dd

			f.close()
		except Exception, e:
			raise e


#############################################
print os.environ['SystemRoot']
info = PEInfo('nvd3dum.350.12.org.dll')
info = PEInfo('nvd3dum.350.12.csoxr.dll')
info = PEInfo('nvd3dum.353.62.org.dll')
info = PEInfo('nvd3dum.353.62.csoxr.dll')
