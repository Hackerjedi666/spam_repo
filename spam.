from twisted.internet import reactor, protocol
from twisted.conch.ssh import keys, factory
from twisted.cred import checkers, portal
from twisted.conch import avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import userauth, connection, session, common
from zope.interface import implements
from scapy.all import *
from twisted.conch.ssh.transport import SSHServerTransport
from zope.interface import implementer
from twisted.cred.portal import IRealm
from twisted.conch.interfaces import IConchUser
from twisted.conch.interfaces import ISession
from twisted.conch.interfaces import IConchUser, ISession

class HoneyPotProtocol(connection.SSHConnection):
    def __init__(self, options):
        self.options = options
        self.services = {
            b'ssh-userauth': userauth.SSHUserAuthServer,
            b'ssh-connection': session.SSHSession
        }

    def serviceStarted(self):
        self.requestService(
            HoneyPotTransport(self.options, self.services)
        )
class HoneyPotTransport(SSHServerTransport):
    def __init__(self, options, services):
        self.options = options
        self.services = services

    def requestService(self, service):
        name = service.name
        if name not in self.services:
            self.sendDisconnect(
                common.DISCONNECT_SERVICE_NOT_AVAILABLE,
                b'Service not available'
            )
            return
        self.services[name](self.options, service).requestService()

    def connectionLost(self, reason):
        connection.SSHServerTransport.connectionLost(self, reason)


class HoneyPotFactory(factory.SSHFactory):
    def __init__(self, options):
        self.options = options
        self.privateKeys = {
            'ssh-rsa': keys.Key.fromString(data=config.private_key)
        }
        self.publicKeys = {
            'ssh-rsa': keys.Key.fromString(data=config.public_key)
        }
        self.portal = portal.Portal(HoneyPotRealm(options))

    def getPrivateKeys(self):
        return self.privateKeys.values()

    def getPublicKeys(self):
        return self.publicKeys

    def buildProtocol(self, addr):
        return HoneyPotProtocol(self.options)


@implementer(IRealm)
class HoneyPotRealm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        if IPerspective in interfaces:
            user = HoneyPotUser()
            avatar = HoneyPotAvatar(user)
            return interfaces[0], avatar, avatar.logout
        raise NotImplementedError()

@implementer(IConchUser)
class HoneyPotUser:
    def __init__(self, username):
        self.username = username

    def logout(self):
        pass

    def getTerminalSize(self, *args):
        return 80, 24


@implementer(ISession)
class HoneyPotAvatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({'session':session.SSHSession})

    def openShell(self, transport):
        serverProtocol = protocol.ServerFactory()
        serverProtocol.protocol = HoneyPotProtocol
        serverProtocol.transport = transport
        transport.factory = serverProtocol
        return transport

    def getPty(self, terminal, windowSize, attrs):
        return None

    def execCommand(self, protocol, cmd):
        print("Command: %s " % cmd)
        protocol.write("Command not found: %s\n" % cmd)
        return True

    def write(self, data):
        pass

    def closed(self):
        pass



class HoneyPotListener(protocol.Protocol):
    def __init__(self):
        pass

    def connectionMade(self):
        print("[+] Incoming connection from %s" % self.transport.getPeer().host)
        options = {}
        factory = HoneyPotFactory(options)
        reactor.listenTCP(22, factory)

    def dataReceived(self, data):
        packet = IP(data)
        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            print("[+] SSH packet detected from %s" % self.transport.getPeer().host)
        else:
            print("[-] Unknown packet detected from %s" % self.transport.getPeer().host)
            self.transport.loseConnection()


class HoneyPotListenerFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return HoneyPotListener()



def main():
    options = {}
    factory = HoneyPotFactory(options)
    reactor.listenTCP(2222, factory)
    print("[+] HoneyPot listening on port 2222...")
    reactor.run()

