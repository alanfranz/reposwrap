# -*- coding: utf-8 -*-

# user serviceable
LISTEN_PORT=12000
LISTEN_ADDRESS="127.0.0.1"
# local root directory for rpm repos
RPM_REPOS_ROOT = "/tmp/rpmrepos"
# remote directory for rpm repos. must be rsyncable destination
REMOTE_RPM_REPOS = "remote:/tmp/rpmrepos"
GPG_KEY_ID = "F0B6607E"
DEB_REPOS_ROOT = "/tmp/debrepos"
REMOTE_DEB_REPOS = "remote:/tmp/debrepo"

APTLY = "/usr/bin/aptly"
# end user serviceable

import time
import sys
import re
import os
import errno
import hashlib
from collections import defaultdict
from twisted.web import server, resource
from twisted.internet import reactor, endpoints
from twisted.python import log
from twisted.internet.task import deferLater, LoopingCall
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue, succeed, DeferredLock
from twisted.internet.error import ProcessDone
from twisted.internet.protocol import ProcessProtocol
from datetime import datetime, timedelta
from tempfile import NamedTemporaryFile

def ln_sf(file1, file2):
    try:
        os.symlink(file1, file2)
    except OSError, e:
        if e.errno == errno.EEXIST:
            os.remove(file2)
            os.symlink(file1, file2)

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: 
            raise

class ReentrantLock(log.Logger):
    """
    A deferred-based lock which is reentrant - i.e. if the
    object already holding it tries to acquire it again,
    it succeeds in doing so immediately.

    This is similar to Twisted's own DeferredLock,
    but is able to perform a quick-passthrough if 
    the very same client tries acquiring the lock.

    In all other cases, the client just gets queued up.

    Client will be used as dictionary key and should
    hence support __hash__ and __eq__.
    """
    _NO_CLIENT = object()

    def __init__(self, name="default"):
        self._waiting = defaultdict(list)
        self._locked = False
        self._client_holding_lock = self._NO_CLIENT
        self._name = name

    def logPrefix(self):
        return self._name

    def acquire(self, client):
        if client == self._client_holding_lock:
            log.msg("Client %s already owns lock, acquiring immediately" % client)
            assert self._locked, "%s holding lock but we're not locked??" % self._client_holding_lock
            wait_d = succeed(self)
        elif self._locked:
            log.msg("Client %s doesn't own lock and we're locked, waiting" % client)
            assert self._NO_CLIENT != self._client_holding_lock, "NO_CLIENT holding lock but we're locked??"
            wait_d = Deferred()
        else:
            log.msg("Client %s doesn't own lock and we're unlocked, acquiring" % client)
            assert self._NO_CLIENT == self._client_holding_lock, "Somebody %s holding lock but we are not locked??" % self._client_holding_lock
            self._locked = True
            self._client_holding_lock = client
            wait_d = succeed(self)

        self._waiting[client].append(wait_d)
        return wait_d


    def release(self, client):
        assert client == self._client_holding_lock, "%s asking for release but %s is holding the lock" % (client, self._client_holding_lock)
        self._waiting[client].pop()
        if not self._waiting[client]:
            # all clients are done. We should trigger a new waiting client, in any.
            # we delete the empty list as well, to prevent memory leaks. It will be recreated if necessary.
            log.msg("Client %s is releasing lock" % client)
            del self._waiting[client]
            for waiting_client, deferreds in self._waiting.iteritems():
                if deferreds:
                    log.msg("Lock ownership is being transferred to %s" % waiting_client)
                    self._client_holding_lock = waiting_client
                    for wait_d in deferreds:
                        if not wait_d.called:
                            wait_d.callback(self)
                        else:
                            #this should not happen AFAICU
                            log.msg("Waiting deferred already called?")
                    break
            else:
                log.msg("No more clients waiting for this lock, unlocking.")
                self._client_holding_lock = self._NO_CLIENT
                self._locked = False
        else:
            log.msg("Lock for client %s has still %s acquisitings" % (client, len(self._waiting[client])))

# TODO: some way to acquire a low-priority lock.
class LockDispatcher(object):
    def __init__(self):
        self._locks = {}

    def lockFor(self, what):
        return self._locks.setdefault(what, ReentrantLock(what))


lockDispatcher = LockDispatcher()
FTP_SYNC_LOCK = "FTP_SYNC_LOCK"
@inlineCallbacks
def two_step_rsync(local_source_dir, ssh_destination):
    assert os.path.isdir(local_source_dir), "local source dir not found"

    if not local_source_dir.endswith("/"):
        local_source_dir = local_source_dir + "/"

    if not ssh_destination.endswith("/"):
        ssh_destination = ssh_destination + "/"

    yield async_check_output(["rsync", "-avrz", "--include", "*/", "--include", "*.deb", "--include", "*.rpm", "--exclude", "*", local_source_dir, ssh_destination])
    yield async_check_output(["rsync", "-avrz", "--delete-after", local_source_dir, ssh_destination])
    returnValue(None)



# bad global object!
class SyncFtp(object):
    def __init__(self):
        self._latest_sync = datetime(1970,1,1)
        self._latest_new = datetime(1970,1,2)

    def something_new(self):
        self._latest_new = datetime.utcnow()

    @inlineCallbacks
    def perform_ftp_sync(self):
        if (self._latest_new - self._latest_sync).total_seconds() > 0:
            lock = lockDispatcher.lockFor(FTP_SYNC_LOCK)
            yield lock.acquire(client="ftpsync")
            try:
                log.msg("Now syncing!")
                self._latest_sync = datetime.utcnow()
                yield two_step_rsync(DEB_REPOS_ROOT, REMOTE_DEB_REPOS)
                log.msg("APT syncing done, going on with YUM.")
                yield two_step_rsync(RPM_REPOS_ROOT, REMOTE_RPM_REPOS)
                log.msg("FTP sync completed")
            finally:
                lock.release(client="ftpsync")
            returnValue(None)
        log.msg("Nothing worth syncing.")
        returnValue(None)

sync_ftp = SyncFtp()

class SubprocessProtocol(ProcessProtocol):
    outBuffer = ""
    errBuffer = ""

    def connectionMade(self):
        self.d = Deferred()

    def outReceived(self, data):
        self.outBuffer += data

    def errReceived(self, data):
        self.errBuffer += data

    def processEnded(self, reason):
        if reason.check(ProcessDone):
            self.d.callback(self.outBuffer)
        else:
            log.msg(self.outBuffer)
            log.err(self.errBuffer)
            self.d.errback(reason)

def async_check_output(args, ireactorprocess=None):
    """
    :type args: list of str
    :type ireactorprocess: :class: twisted.internet.interfaces.IReactorProcess
    :rtype: Deferred
    """
    if ireactorprocess is None:
        from twisted.internet import reactor
        ireactorprocess = reactor

    pprotocol = SubprocessProtocol()
    ireactorprocess.spawnProcess(pprotocol, args[0], args, env=None)
    return pprotocol.d

class PackageDispatcher(object):
    def __init__(self):
        self._rpm = RPMAdder()
        self._deb = DEBAdder()
        
    def add_package(self, prefix, distribution, version, filename, data):
        if filename.lower().endswith(".rpm"):
            return self._rpm.add_package(prefix, distribution, version, filename, data)
        if filename.lower().endswith(".deb"):
            return self._deb.add_package(prefix, distribution, version, filename, data)

        raise ValueError, "Unsupported package type"

class DEBAdder(object):
    DISTRO_VERSIONS = {
        "ubuntu": ("precise", "trusty", "utopic", "vivid", "wily", "xenial"),
        "debian": ("squeeze", "wheezy", "jessie", "sid")
    }

    @inlineCallbacks
    def add_package(self, prefix, distribution, version, filename, data):
        if not version in self.DISTRO_VERSIONS.get(distribution, []):
            raise ValueError, "Unsupported distribution/version: %s %s" % (distribution, version)
        if not filename.lower().endswith(".deb"):
            raise ValueError, "Wrong filename %s" % filename

        lock = lockDispatcher.lockFor("aptly")
        yield lock.acquire(client="DEBAdder")
        try:
            log.msg("Now adding DEB package")
            repo_id = "{0}-{1}".format(version, prefix)

            try:
                yield async_check_output([APTLY, "repo", "show", repo_id])
            except:
                log.msg("Repo should be created")
                yield async_check_output([APTLY, "repo", "create", repo_id])

            tmp = NamedTemporaryFile(suffix="{0}".format(filename))
            tmp.write(data)
            tmp.flush()


            yield async_check_output([APTLY, "repo", "add", repo_id, tmp.name])
            snapshot = "{0}-{1}".format(repo_id, time.time())
            yield async_check_output([APTLY, "snapshot", "create", snapshot, "from", "repo", repo_id])

            distro_prefix = "{0}/{1}".format(prefix, distribution)
            try:
                yield async_check_output([APTLY, "publish", "snapshot", "--distribution={0}".format(version), snapshot, distro_prefix])
            except:
                log.msg("Snapshot already published")
                yield async_check_output([APTLY, "publish", "switch", version, distro_prefix, snapshot]) 
            returnValue("")
        finally:
            lock.release(client="DEBAdder")

def hashstring(data):
    hasher = hashlib.md5()
    hasher.update(data)
    return hasher.hexdigest()


def hashfile(filename, blocksize=65536):
    afile = open(filename, "rb")
    hasher = hashlib.md5()
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()

# we should add a pseudo-lock if uploading at the same time for the same distro/version
# or maybe just synchronize globally - no more than one upload at a given time?
class RPMAdder(object):
    DISTRO_VERSIONS = {
        "centos": ("5", "6", "7"),
        "fedora": ("20", "21", "22", "23", "24", "rawhide")
    }

    SYMLINK_TO = {
        ("centos", "5"): ("5Client", "5Server"),
        ("centos", "6"): ("6Client", "6Server"),
        ("centos", "7"): ("7Client", "7Server")
        }

    def __init__(self):
        mkdir_p(RPM_REPOS_ROOT)

    @inlineCallbacks
    def add_package(self, prefix, distribution, version, filename, data):
        if not version in self.DISTRO_VERSIONS.get(distribution, []):
            raise ValueError, "Unsupported distribution/version: %s %s" % (distribution, version)
        if not filename.lower().endswith(".rpm"):
            raise ValueError, "Wrong filename %s" % filename

        lock = lockDispatcher.lockFor("{0} {1} {2}".format(prefix, distribution, version))
        yield lock.acquire(client="RPMAdder")
        try:
            log.msg("Now adding RPM package")
            target_dir = os.path.abspath(os.path.join(RPM_REPOS_ROOT, prefix, distribution, version, "x86_64"))
            mkdir_p(target_dir)
            
            symlinks = self.SYMLINK_TO.get((distribution, version))
            if symlinks:
                for link in symlinks:
                    symlink_dest_dir = os.path.split(os.path.split(target_dir)[0])[0]
                    symlink_dest = os.path.join(symlink_dest_dir, link)
                    if not os.path.exists(symlink_dest):
                        ln_sf(version, symlink_dest)
            
            full_filename = os.path.join(target_dir, filename)
            if os.path.exists(full_filename):
                if hashfile(full_filename) != hashstring(data):
                    raise ValueError, "Trying to change existing file, operation is unsupported"
                log.msg("Identical file found already, doing nothing")
                returnValue("")

            with open(full_filename, "wb") as f:
                f.write(data)
                f.flush()
            update = "--update" if os.path.exists(os.path.join(target_dir, "repodata", "repomd.xml")) else ""
            yield async_check_output(["createrepo", update, target_dir])
            yield async_check_output(["/usr/bin/gpg", "--yes", "-u", GPG_KEY_ID, "--detach-sign", "--armor", "{0}/repodata/repomd.xml".format(target_dir)])
            returnValue("")
        finally:
            lock.release(client="RPMAdder")

VALID_NAMES_PATTERN = re.compile("^[\w\-.]+$")
class Splitter(resource.Resource):
    isLeaf = True


    def __init__(self):
        resource.Resource.__init__(self)
        self._dispatcher = PackageDispatcher()

    @inlineCallbacks
    def _addPackage(self, lock, prefix, distribution, version, filename, content, request):
        try:
            sync_ftp.something_new()
            yield self._dispatcher.add_package(prefix, distribution, version, filename, content)
            request.setResponseCode(200)
        except Exception, e:
            request.setResponseCode(400)
            log.err(e)
        finally:
            lock.release(client="Splitter")
            request.finish()

   
    def render_POST(self, request):
        path = request.path.strip("/")
        if path.count("/") != 3:
            raise ValueError("Wrong path: %s" % path)
        log.msg(path)
        prefix, distribution, version, filename = path.split("/")
        for elem in (prefix, distribution, version, filename):
            if not VALID_NAMES_PATTERN.match(elem):
                raise ValueError("Invalid name")

        if not (filename.lower().endswith(".deb") or filename.lower().endswith(".rpm")):
            raise ValueError("Supporting rpm and deb only.")

        content = request.content.read()
        lock = lockDispatcher.lockFor(FTP_SYNC_LOCK)
        d = lock.acquire(client="Splitter")
        d.addCallback(self._addPackage, prefix, distribution, version, filename, content, request)
        return server.NOT_DONE_YET

def ftp_sync_schedule():
    lc = LoopingCall(sync_ftp.perform_ftp_sync)
    lc.start(300)

log.startLogging(sys.stdout)
endpoints.serverFromString(reactor, "tcp:port={0}:interface={1}".format(LISTEN_PORT, LISTEN_ADDRESS)).listen(server.Site(Splitter()))
reactor.callWhenRunning(ftp_sync_schedule)
reactor.run()
