import base64
import json
import re

from config import x2bool
from mumo_module import MumoModule

class ChannelMock:
    id: int
    name: str
    parent: int
    links: list[int]
    description: str
    temporary: bool
    position: int

class UserMock:
    session: int
    userid: int
    mute: bool
    deaf: bool
    suppress: bool
    prioritySpeaker: bool
    selfMute: bool
    selfDeaf: bool
    recording: bool
    channel: int
    name: str
    onlinesecs: int
    bytespersec: int
    version: int
    version2: int
    release: str
    os: str
    osversion: str
    identity: str
    context: str
    comment: str
    address: str
    tcponly: bool
    idlesecs: int
    udpPing: float
    tcpPing: float
    # extra
    parsedcontext: dict
    parsedidentity: dict
    is_linked: bool


class MumbleServerMock:
    ''' mock the MumbleServer.ice module '''
    ChannelMap: dict[int, ChannelMock]
    def getChannels(self) -> dict[int, ChannelMock]: pass
    def id(self) -> int: pass
    def getUsers(self) -> dict[int, UserMock]: pass
    def removeChannel(self, channel_id: int): pass
    def addChannel(self, name: str, parent: int) -> int: pass
    def setChannelState(self, channel: ChannelMock): pass
    def getChannelState(self, channel_id: int) -> ChannelMock: pass
    # MumoModule.ACL
    def setACL(self, channel_id: int, acl: list): pass
    def setState(self, user: UserMock): pass
    def kickUser(self, session: int, reason: str): pass
    def removeUserFromGroup(self, channelid: int, session: int, group_name: str): pass
    def addUserToGroup(self, channelid: int, session: int, group_name: str): pass

class tmproximity(MumoModule):
    murmur: 'MumbleServerMock'
    channels_by_name: dict[int, str]
    channels_by_id: dict[int, str]

    def __init__(self, name, manager, configuration=None):
        MumoModule.__init__(self, name, manager, configuration)
        self.murmur = manager.getMurmurModule()
        self.channels_by_name = dict()
        self.channels_by_id = dict()

    def connected(self):
        cfg = self.cfg()
        manager = self.manager()
        log = self.log()
        log.debug("Register for Server callbacks")

        servers = set()
        servers.add(1)
        # for i in range(cfg.tmproximity.gamecount):
        #     try:
        #         servers.add(cfg["g%d" % i].mumble_server)
        #     except KeyError:
    #         log.error("Invalid configuration. Game configuration for 'g%d' not found.", i)
        #         return

        self.sessions = {}  # {serverid:{sessionid:laststate}}
        manager.subscribeServerCallbacks(self, servers)
        manager.subscribeMetaCallbacks(self, servers)

        meta = manager.getMeta()
        all_servers = meta.getBootedServers()
        log.debug(f"all_servers: {all_servers}")
        main_server: MumbleServerMock = all_servers[0]
        server_id = main_server.id()
        chans = main_server.getChannels()
        log.debug(f"chans: {chans}")
        for chan in chans.values():
            if chan.id > 0:
                main_server.removeChannel(chan.id)
            # if chan.name in self.channels_by_name:
            #     log.info(f"Removing channel {chan.name} with id {chan.id}")
            # else:
            #     self.channels_by_name[chan.name] = chan.id
            #     self.channels_by_id[chan.id] = chan.name
            #         _chan = main_server.getChannelState(chan.id)
            #         _chan.temporary = True
            #         main_server.setChannelState(_chan)
        self.channels_by_id[0] = "left"
        self.channels_by_name["left"] = 0




    def disconnected(self):
        pass

    def get_channel_from_ctx(self, server: MumbleServerMock, ctx):
        if ctx in self.channels_by_name:
            _id = self.channels_by_name[ctx]
            try:
                chan = server.getChannelState(_id)
                return _id
            except:
                del self.channels_by_name[ctx]
                del self.channels_by_id[_id]
        return self.create_channel(server, ctx)

    def create_channel(self, server: MumbleServerMock, ctx):
        _id = server.addChannel(ctx, 0)
        chan = server.getChannelState(_id)
        chan.temporary = True
        server.setChannelState(chan)
        self.channels_by_id[_id] = ctx
        self.channels_by_name[ctx] = _id
        self.set_prox_channel_acl(server, _id, ctx)
        return _id

    def set_prox_channel_acl(self, server: MumbleServerMock, channel_id, groupname: str):
        ACL = self.murmur.ACL
        EAT = self.murmur.PermissionEnter | self.murmur.PermissionTraverse  # Enter And Traverse
        W = self.murmur.PermissionWhisper  # Whisper
        S = self.murmur.PermissionSpeak  # Speak

        server.setACL(channel_id,
                        [ACL(applyHere=True,  # Deny everything
                            applySubs=True,
                            userid=-1,
                            group='all',
                            deny=EAT | W | S),
                        ACL(applyHere=True,  # Allow enter and traverse to players
                            applySubs=False,
                            userid=-1,
                            group=groupname,
                            allow=EAT | W | S)],
                        [], True)

    def check_empty_channel(self, server: MumbleServerMock, channel_id):
        if channel_id == 0:
            return
        users = server.getUsers()
        for user in users.values():
            if user.channel == channel_id:
                return
        if channel_id in self.channels_by_id:
            channel_name = self.channels_by_id[channel_id]
            del self.channels_by_name[channel_name]
            del self.channels_by_id[channel_id]
        try:
            server.removeChannel(channel_id)
        except:
            pass


    #
    # --- Module specific state handling code
    #
    def update_state(self, server: MumbleServerMock, oldstate: UserMock, newstate: UserMock):
        log = self.log()
        sid = server.id()

        log.debug("Updating state for user '%s' (%d|%d) on server %d", newstate.name, newstate.session, newstate.userid, sid)

        session = newstate.session
        newoldchannel = newstate.channel

        try:
            opc = oldstate.parsedcontext
            # ogcfgname = opc["gamename"]
            # ogcfg = opc["gamecfg"]
            # og = ogcfg.name
            opi = oldstate.parsedidentity
        except (AttributeError, KeyError):
            # og = None
            log.debug("User '%s' (%d|%d) on server %d getting default opi opc", newstate.name, newstate.session, newstate.userid, sid)
            opi = {}
            opc = {}

        if oldstate and oldstate.is_linked:
            oli = True
        else:
            oli = False

        try:
            npc = newstate.parsedcontext
            # ngcfgname = npc["gamename"]
            # ngcfg = npc["gamecfg"]
            # ng = ngcfg.name
            npi = newstate.parsedidentity
        except (AttributeError, KeyError):
            # ng = None
            log.debug("User '%s' (%d|%d) on server %d getting default npi npc", newstate.name, newstate.session, newstate.userid, sid)
            npi = {}
            npc = {}
            nli = False

        if newstate and newstate.is_linked:
            nli = True
        else:
            nli = False

        log.debug("User '%s' (%d|%d) on server %d old linked: %s new linked: %s", newstate.name, newstate.session, newstate.userid, sid, oli, nli)
        log.debug("User '%s' (%d|%d) on server %d old context: %s new context: %s", newstate.name, newstate.session, newstate.userid, sid, opc, npc)

        if not oli and nli:
            log.debug("User '%s' (%d|%d) on server %d now linked", newstate.name, newstate.session, newstate.userid,
                      sid)
            server.addUserToGroup(0, session, "linked")

        channame = "left"

        if opi and opc:
            newstate.channel = 0

        old_cn = oldstate.channel if oldstate else 0


        if npc and npi:
            log.debug("Updating user '%s' (%d|%d) on server %d in game %s: %s", newstate.name, newstate.session,
                      newstate.userid, sid, "ng or ngcfgname", str(npi))

            channame = f"{npc['channame']}"
            newstate.channel = self.get_channel_from_ctx(server, channame)

        if oli and not nli:
            log.debug("User '%s' (%d|%d) on server %d no longer linked", newstate.name, newstate.session, newstate.userid, sid)
            server.removeUserFromGroup(0, session, "linked")

        if 0 <= newstate.channel != newoldchannel:
            log.debug("Moving '%s' leaving %s to channel %s", newstate.name, old_cn, channame)
            # if ng is None:
            # else:
            #     log.debug("Moving '%s' @ %s to channel %s", newstate.name, "?", channame)
            server.addUserToGroup(newstate.channel, session, channame)
            server.setState(newstate)
            self.check_empty_channel(server, old_cn)
            if old_cn != 0 and old_cn in self.channels_by_id and old_cn != newstate.channel:
                server.removeUserFromGroup(old_cn, session, self.channels_by_id[old_cn])




    def handle(self, server, state):
        def verify(mdict, key, vtype):
            if not isinstance(mdict[key], vtype):
                raise ValueError("'%s' of invalid type" % key)

        cfg = self.cfg()
        log = self.log()
        sid = server.id()

        if len(state.context) > 0:
            state.context = base64.b64decode(state.context).decode("utf-8")
            if state.context.startswith("TM-Proximity-Chat"):
                state.context = state.context[18:]

        log.debug("Handling user '%s' (%d|%d) on server %d", state.name, state.session, state.userid, sid)
        log.debug("User context: %s and ident: %s", state.context.__repr__(), state.identity.__repr__())

        # Add defaults for our variables to state
        state.parsedidentity = {}
        state.parsedcontext = {}
        state.is_linked = False

        if sid not in self.sessions:  # Make sure there is a dict to store states in
            self.sessions[sid] = {}

        update = False
        if state.session in self.sessions[sid]:
            if state.identity != self.sessions[sid][state.session].identity or \
                    state.context != self.sessions[sid][state.session].context:
                # identity or context changed => update
                update = True
            else:  # id and context didn't change hence the old data must still be valid
                state.is_linked = self.sessions[sid][state.session].is_linked
                state.parsedcontext = self.sessions[sid][state.session].parsedcontext
                state.parsedidentity = self.sessions[sid][state.session].parsedidentity
        else:
            if state.identity or state.context:
                # New user with engaged plugin => update
                self.sessions[sid][state.session] = None
                update = True

        if not update:
            self.sessions[sid][state.session] = state
            return

        # The plugin will always prefix "TM|" to the context for the bf2 PA plugin
        # don't bother analyzing anything if it isn't there
        if state.context.startswith("TM|"):
            state.is_linked = True
            # if state.identity and len(splitcontext) == 1:
            #     # LEGACY: Assume broken Ice 3.2 which doesn't transmit context after \0
            #     splitcontext.append(
                    # '{"ipport":""}')  # Obviously this doesn't give full functionality but it doesn't crash either ;-)

        if state.is_linked and state.identity:
            context = state.context[3:]  # Remove the "TM|" prefix
            state.parsedcontext = parse_context(context)
            state.parsedidentity = parse_identity(state.identity)

        # Update state and remember it
        self.update_state(server, self.sessions[sid][state.session], state)
        self.sessions[sid][state.session] = state




    #
    # --- Server callback functions
    #

    def userDisconnected(self, server, state: UserMock, context=None):
        log = self.log()
        log.debug("User '%s' (%d|%d) on server %d disconnected", state.name, state.session, state.userid, server.id())
        try:
            sid = server.id()
            del self.sessions[sid][state.session]
        except KeyError:
            pass

    def userStateChanged(self, server: MumbleServerMock, state: UserMock, context=None):
        log = self.log()
        log.debug("User '%s' (%d|%d) on server %d changed state", state.name, state.session, state.userid, server.id())
        self.handle(server, state)

    def userConnected(self, server: MumbleServerMock, state: UserMock, context=None):
        log = self.log()
        log.debug("User '%s' (%d|%d) on server %d connected", state.name, state.session, state.userid, server.id())
        self.handle(server, state)

    def userTextMessage(self, server, user, message, current=None):
        pass

    def channelCreated(self, server, state, context=None):
        pass

    def channelRemoved(self, server, state, context=None):
        pass

    def channelStateChanged(self, server, state, context=None):
        pass

    #
    # --- Meta callback functions
    #

    def started(self, server, context=None):
        self.sessions[server.id()] = {}

    def stopped(self, server, context=None):
        self.sessions[server.id()] = {}


def parse_context(context: str) -> dict:
    # need exact and matching context, should match room name
    # server_hash|team
    parts = context.split("|")
    if len(parts) != 2:
        return dict(ctx="left", channame="left", g="left", parts=parts)
    # server|team
    name = "left" if len(parts[0]) == 0  else "|".join(parts[:2])
    # nonce = parts[2] if len(parts) > 2 else ""
    return dict(ctx=name, channame=name, g=name)

def parse_identity(identity: str) -> dict:
    parts = identity.split("|")
    name = parts[0] if len(parts) > 0 else ""
    login = parts[1] if len(parts) > 1 else ""
    nonce = parts[2] if len(parts) > 2 else ""
    return dict(id=identity, name=name, login=login, nonce=nonce)
