#!/usr/bin/python3
import json, sys, os, time, shutil, logging, pwd, signal
from subprocess import Popen, PIPE, STDOUT
from threading import Thread
from select import epoll, EPOLLIN, EPOLLHUP
from systemd.journal import JournalHandler
from hashlib import sha512
try:
	import psutil
except:
	print('psutil is not installed. Mocking best effort replacement.')
	## Time to monkey patch in all the stats as if the real psutil existed.

	class mem():
		def __init__(self, free, percent=-1):
			self.free = free
			self.percent = percent

	class disk():
		def __init__(self, size, free, percent):
			self.size = size
			self.free = free
			self.percent = percent

	class iostat():
		def __init__(self, interface, bytes_sent=0, bytes_recv=0):
			self.interface = interface
			self.bytes_recv = int(bytes_recv)
			self.bytes_sent = int(bytes_sent)
		def __repr__(self, *args, **kwargs):
			return f'iostat@{self.interface}[bytes_sent: {self.bytes_sent}, bytes_recv: {self.bytes_recv}]'

	class psutil():
		def cpu_percent(interval=0):
			## This just counts the ammount of time the CPU has spent. Find a better way!
			with cmd("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'") as output:
				for line in output:
					return float(line.strip().decode('UTF-8'))
		
		def virtual_memory():
			with cmd("grep 'MemFree: ' /proc/meminfo | awk '{free=($2)} END {print free}'") as output:
				for line in output:
					return mem(float(line.strip().decode('UTF-8')))

		def disk_usage(partition):
			disk_stats = os.statvfs(partition)
			free_size = disk_stats.f_bfree * disk_stats.f_bsize
			disk_size = disk_stats.f_blocks * disk_stats.f_bsize
			percent = (100/disk_size)*disk_free
			return disk(disk_size, free_size, percent)

		def net_if_addrs():
			interfaces = {}
			for root, folders, files in os.walk('/sys/class/net/'):
				for name in folders:
					interfaces[name] = {}
			return interfaces

		def net_io_counters(pernic=True):
			data = {}
			for interface in psutil.net_if_addrs().keys():
				with cmd("grep '{interface}:' /proc/net/dev | awk '{{recv=$2}}{{send=$10}} END {{print send,recv}}'".format(interface=interface)) as output:
					for line in output:
						data[interface] = iostat(interface, *line.strip().decode('UTF-8').split(' ',1))
			return data

log = logging.getLogger('dumper')
log.addHandler(JournalHandler())
log.setLevel(logging.INFO)

## Parse command-line arguments:
args = {}
positionals = []
for arg in sys.argv[1:]:
	if '--' == arg[:2]:
		if '=' in arg:
			key, val = [x.strip() for x in arg[2:].split('=')]
		else:
			key, val = arg[2:], True
		if type(val) == str:
			if val.isnumeric(): val = int(val)
			elif val.lower() in ('true', 'yes'): val = True
			elif val.lower() in ('false', 'no'): val = False
		args[key] = val
	else:
		positionals.append(arg)

def check_config_changes():
	if not 'monitor_config' in args or args['monitor_config'] == False: return None

	with open(args['monitor_config'], 'r') as fh:
		try:
			new_conf = json.load(fh)
		except json.decoder.JSONDecodeError as e:
			log.info("Malformed JSON format on configuration: {} (in: {})".format(e, args['monitor_config']))
			return None

	snapshot = args.copy()
	#print('snapshot:', json.dumps(snapshot, indent=4))
	#print('args:', json.dumps(args, indent=4))
	#if 'config' not in snapshot and 'config' in args: snapshot['config'] = args['config']
	#if 'monitor_config' in snapshot and 'monitor_config' not in args: del(snapshot['monitor_config'])
	if dict_diff(new_conf, snapshot):
		for key in new_conf:
			args[key] = new_conf[key]
		return True

def gen_uid():
	return sha512(os.urandom(256)).hexdigest()

def dict_diff(d1, d2):
	result = {}
	for item in d1:
		if item not in d2:
			result[item] = d1[item]
		elif type(d1[item]) == dict:
			tmp = dict_diff(d1[item], d2[item])
			if(tmp):
				result[item] = tmp
		elif d1[item] != d2[item]:
			result[item] = d1[item]
	if result:
		return result

def human_size(b):
	human_sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
	for index, size in enumerate(human_sizes):
		if b/1024 > 1.0:
			b /= 1024
		else:
			break
	return '{}{}'.format(b, human_sizes[index])

def clear_old_pcaps(from_mtime):
	base, filename = os.path.split(args['output'])
	for root, folders, pcaps in os.walk(base):
		for pcap in pcaps:
			if 'capture_{interface}'.format(**args) in pcap:
				file_info = os.stat(os.path.join(root, pcap))
				if file_info.st_mtime > from_mtime:
					log.info('Freeing up {} ({}) with a mod time of {} (We started at {}).'.format(pcap, human_size(file_info.st_size), file_info.st_mtime, from_mtime))
					os.remove(os.path.join(root, pcap))
		break

def sig_handler(signal, frame):
	for UID in list(workers.keys()):
		if workers[UID].worker:
			workers[UID].worker.terminate()
			workers[UID].join()
			del workers[UID]
	exit(0)

## Create a neat handle to execute system commands
class cmd(Popen):
	def __init__(self, c, shell=True):
		self.c = c
		self.shell = shell
		self.stdout = None
		self.stdin = None
		self.stderr = None
		self.line_buffer = b''
		self.poller = epoll()

	## Make it work like a context manager.. for ez of use.
	def __enter__(self, *args, **kwargs):
		super(cmd, self).__init__(self.c, shell=self.shell, stdout=PIPE, stderr=STDOUT, stdin=PIPE)
		self.poller.register(self.stdout.fileno(), EPOLLIN | EPOLLHUP)
		return self

	def __exit__(self, *args, **kwargs):
		if self.stdout and self.stdin:
			self.stdin.close()
			self.stdout.close()

	def __iter__(self, *args, **kwargs):
		if not self.stdin:
			# Not opened yet
			return None

		
		for fileno, event in self.poller.poll(0.1):
			data = self.stdout.read(1)
			if len(data) <= 0 and self.poll() is not None:
				return None
			self.line_buffer += data

			if b'\r' in self.line_buffer:
				yield self.line_buffer[:self.line_buffer.find(b'\r')+1]
				self.line_buffer = self.line_buffer[self.line_buffer.find(b'\r')+1:]
			elif b'\n' in self.line_buffer:
				yield self.line_buffer[:self.line_buffer.find(b'\n')+1]
				self.line_buffer = self.line_buffer[self.line_buffer.find(b'\n')+1:]

class tcpdump(Thread):
	def __init__(self, config):
		super(tcpdump, self).__init__()
		self.config = config
		self.last_notification = time.time()
		self.runtime = time.time()
		self.worker = None
		self.start()

	def run(self):
		if not self.config['profile'] in self.config['profiles']:
			raise KeyError(f"Selected profile {self.config['profile']} is not configured.")

		filters = ' '.join(self.config['profiles'][self.config['profile']]['parameters'])
		filters += ' {}'.format(' and '.join(self.config['profiles'][self.config['profile']]['filters']))
		filters = filters.format(**self.config)
		with cmd(f"tcpdump {filters}") as self.worker:
			while self.worker.poll() is None and time.time()-self.runtime < self.config['runtime']:
				for line in self.worker:
					# Every 15min, log how many packets we got
					# or if the line is something other than "Got X"
					if line[:4] != b'Got ' or time.time() - self.last_notification > 60*15:
						log.info(line.strip().decode('UTF-8'))
						self.last_notification = time.time()

signal.signal(signal.SIGINT, sig_handler)
## And add some defaults if they are missing
if 'config' in args and os.path.isfile(args['config']):
#	conf_file = args['config']
#	with open(conf_file, 'r') as conf:
#		args = json.load(conf)
	args['monitor_config'] = args['config']
	check_config_changes()
if not 'config' in args:
	args['config'] = {
		"profile" : "default",
		"profiles" : {
			"default" : {
				"parameters" : ["-i {interface}", "-s 0", "-w {output}", "-vv", "-G 3600", "-z gzip", "-Z {cwd_owner}"],
				"filters" : [
					"not arp",
					"not broadcast"
				]
			}
		}
	}

if not 'instances' in args: args['instances'] = 1
if not 'interface' in args: args['interface'] = sorted([x for x in psutil.net_if_addrs().keys() if not x == 'lo'])[0]
if not 'partition' in args: args['partition'] = '/'
if not 'runtime' in args: args['runtime'] = 60*60 # Default to 1h
if not 'output' in args: args['output'] = f'./capture_{args["interface"]}_%Y-%m-%d_%H:%M:%S.pcap'
if not 'cwd_owner' in args: args['cwd_owner'] = pwd.getpwuid(os.stat(os.path.split(args['output'])[0]).st_uid)[0]
if not 'profile' in args: args['profile'] = None
if not 'reserved' in args: args['reserved'] = 10
if not 'flushlimit' in args: args['flushlimit'] = 5

## Low odds if you're using a date format on the file.
## But we'll keep backing up file instead of overwriting just in case.
if os.path.isfile(args['output']):
	base, filename = os.path.split(args['output'])
	shutil.copy2(args['output'], os.path.join(base, time.strftime('%Y-%m-%d_%H:%M')+'_'+filename))

if 'help' in args:
	print("""
    Here's a short introduction:
        --interface=<name> - Which NIC to get network traffic from

        --output=<filename> - Outputs all traffic capture to this filename

        --config=<filename> - Load a config file and monitor for changes, reloads automatically.

        --monitor_config=True - Monitor for configuration changes or not (Default True/Yes)

        --partition=/ - Monitor for free space, pauses capture when we go below --reserved

        --reserved=10 - Will pause capture when below 10% (default)

        --flushlimit=5 - Will flush old pcap's when disk space is below 5% (default)

        --profile=<profile name> - Which profile to run in the config
                                   (This option overrides "profile" in the config)

        --instances=1 - How many threads should we run? (Default is 1)

    Example usage:
        python dumper.py --output=./capture_eno1_%Y-%m-%d_%H:%M:%S_pcap --interface=eno1 --partition=/ --reserved=10 --flushlimit=5 --config=/etc/dumper.json""")
	exit(1)

start_time = time.time() # Used to keep track of which pcap's we're allowed to remove/modify.
workers = {}
logged = False
while 1:
	disk_free = psutil.disk_usage(args['partition']).percent
	if disk_free < args['flushlimit']:
		clear_old_pcaps(start_time)
	
	if disk_free < args['reserved']:
		if not logged:
			log.info("Running low on disk space, pausing full packet capture.")
			logged = time.time()
		elif time.time() - logged > 60*15: # Every 15m, remind DEV's that we're low on disk space
			log.info("Still low on disk space, full packet capture is still paused.")
			logged = time.time()
		for UID in list(workers.keys()):
			if workers[UID].worker:
				workers[UID].worker.terminate()
				workers[UID].join()
				del workers[UID]
	else:
		logged = False
		if check_config_changes():
			log.info("Configuration changed, gracefully terminating and restarting all old packet captures.")
			for UID in list(workers.keys()):
				if workers[UID].worker:
					workers[UID].worker.terminate()
					workers[UID].join()
					del workers[UID]

		if len(workers) < args['instances']:
			## Currently only supports one interface over multiple threads.
			## Will implement thread-specific interfaces later on.
			if args['instances'] <= 1:
				workers[0] = tcpdump(args)
			else:
				for t in range(args['instances']):
					conf = args.copy()
					path, filename = os.path.split(conf['output'])
					conf['output'] = os.path.join(path, f'{t}_{filename}')
					workers[gen_uid()] = tcpdump(conf)

	for UID in list(workers.keys()):
		if workers[UID].isAlive() == False:
			workers[UID].join()
			del workers[UID]

	time.sleep(1)