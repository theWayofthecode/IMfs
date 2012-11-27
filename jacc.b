implement JACC;

include "sys.m";
	sys: Sys;
include "libc.m";
	libc: Libc;
include "math.m";
	math: Math;
include "arg.m";
include "string.m";
	str: String;
include "dial.m";
	dial: Dial;
include "factotum.m";
	auth: Factotum;
include "keyring.m";
include "security.m";
include "pkcs.m";
include "asn1.m";
include "sslsession.m";
include "ssl3.m";
	ssl3: SSL3;
include "daytime.m";
	daytime: Daytime;
include "draw.m";
include "sh.m";
include "bufio.m";
include "xml.m";

include "jacc.m";
include "xmlpull.m";
	xp: Xmlpull;
	xmlpull: import xp;
	START_DOCUMENT, START_TAG, START_END_TAG, TEXT, TEXT_C, ATTR, END_TAG, END_TAG_S, END_TAG_N, END_DOCUMENT: import xp;

NAME: con "jacc - Jabber Client for Plan9";
VERSION: con "2nd ed";
OS: con "Plan 9 4th ed";

Jacc.xml(sock: ref Sys->FD): int
{
	return sys->fprint(sock, "<?xml version=\"1.0\"?>\n");
}

Jacc.login(sock: ref Sys->FD, serv: string): int
{
	return sys->fprint(sock, 
		"<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\"" +
		" xmlns=\"jabber:client\" to=\"%s\">\n", serv);
}

Jacc.user(sock: ref Sys->FD, user: string, pass: string, res: string): int
{
	return sys->fprint(sock, 
		"<iq type=\"set\" id=\"auth_1\">\n"+
		"<query xmlns=\"jabber:iq:auth\">\n"+
		"<username>%s</username>\n"+
		"<password>%s</password>\n"+
		"<resource>%s</resource>\n"+
		"</query>\n"+
		"</iq>\n", user, pass, res);
}

Jacc.version(sock: ref Sys->FD, from: string, tox: string, id: string): int
{
	return sys->fprint(sock, 
		"<iq from=\"%s\" type=\"result\" id=\"%s\" to=\"%s\">\n"+
		"<query xmlns=\"jabber:iq:version\">\n"+
		"<name>" +NAME+ "</name>\n"+
		"<version>" +VERSION+ "</version>\n"+
		"<os>" +OS+ "</os>\n"+
		"</query>\n"+
		"</iq>\n", from, id, tox);
}

Jacc.features(sock: ref Sys->FD, from: string, tox: string, id: string): int
{
	return sys->fprint(sock, 
		"<iq from=\"%s\" type=\"result\" to=\"%s\" id=\"%s\">\n"+
		"<query xmlns=\"http://jabber.org/protocol/disco#info\">\n"+
		"<identity category=\"client\" type=\"pc\"/>\n"+
		"<feature var=\"jabber:iq:time\"/>\n"+
		"<feature var=\"jabber:iq:version\"/>\n"+
		"<feature var=\"http://jabber.org/protocol/muc\"/>\n"+
		"</query>\n" + "</iq>\n", from, tox, id);
}

Jacc.time(sock: ref Sys->FD, from: string, tox: string, id: string): int
{
	now := daytime->now();
	loc := daytime->local(now);
	gmt := daytime->gmt(now);

	return sys->fprint(sock,
		"<iq from=\"%s\" type=\"result\" to=\"%s\" id=\"%s\">\n"+
		"<query xmlns=\"jabber:iq:time\">\n"+
		"<utc>%.4d%.2d%.2dT%.2d:%.2d:%.2d</utc>\n"+
		"<display>%s %s %.2d %.2d:%.2d:%.2d %.4d</display>\n"+
		"<tz>%s</tz>\n"+
		"</query>\n</iq>\n",
		from, tox, id, gmt.year+1900, gmt.mon+1, gmt.mday, gmt.hour, gmt.min, gmt.sec,
		getday(loc.wday), getmonth(loc.mon), loc.mday, loc.hour, loc.min, loc.sec, loc.year+1900, loc.zone);
}

Jacc.last(sock: ref Sys->FD, from: string, tox: string, id: string, d: int): int
{
	return sys->fprint(sock, "<iq from=\"%s\" type=\"result\" to=\"%s\" id=\"%s\">\n"+
		"<query xmlns=\"jabber:iq:last\" seconds=\"%d\"/>\n"+
		"</iq>\n", from, tox, id, d);
}

Jacc.register(sock: ref Sys->FD, serv: string, user: string, pass: string): int
{
	return sys->fprint(sock,
		"<iq type=\"set\" id=\"req\" to=\"%s\">\n"+
		"<query xmlns=\"jabber:iq:register\">\n"+
		"<username>%s</username>\n"+
		"<password>%s</password>\n"+
		"</query>\n"+
		"</iq>\n", serv, user, pass);
}

Jacc.vcardget(sock: ref Sys->FD, from: string, typex: string): int
{
	return sys->fprint(sock, "<iq %s=\"%s\" type=\"get\" id=\"v1\">\n"+
		"<vCard xmlns=\"vcard-temp\"/>\n"+
		"</iq>\n", typex, from);
}

Jacc.vcardset(sock: ref Sys->FD, from: string, fd: ref Sys->FD): int
{
	sys->fprint(sock, "<iq from=\"%s\" type=\"set\" id=\"v2\">\n"+
		"<vCard xmlns=\"vcard-temp\">\n", from);
	readwrite(sock, fd);
	return sys->fprint(sock, "</vCard>\n" + "</iq>\n");
}

Jacc.presence(sock: ref Sys->FD, stat: string, show: string, from: string, tox: string): int
{
	afrom := "";
	if(from != nil)
		afrom = "from=\""+from+"\"";
    
	atox := "";
	if(tox != nil)
		atox = "to=\""+tox+"\"";

	return sys->fprint(sock,
		"<presence %s %s>\n"+
		"<show>%s</show>\n"+
		"<status>%s</status>\n"+
		"<priority>9</priority>\n"+
		"</presence>\n", afrom, atox, show, stat);
}

Jacc.presencetype(sock: ref Sys->FD, from: string, tox: string, typex: string): int
{
	return sys->fprint(sock, "<presence type=\"%s\" from=\"%s\" to=\"%s\"/>\n", typex, from, tox);
}

Jacc.roster(sock: ref Sys->FD): int
{
	return sys->fprint(sock, "<iq type=\"get\" id=\"auth_2\">\n"+
		"<query xmlns=\"jabber:iq:roster\"/>\n" + "</iq>\n");
}

Jacc.message(sock: ref Sys->FD, from: string, tox: string, msg: string, typex: string): int
{
#	sys->fprint(sock, "<iq to='talk.google.com'" +
#	       "type='set'" + 
#	             " id='sess_1'>" + 
#		        "   <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>" +
#	     " </iq>");
	return sys->fprint(sock,
		"<message from=\"%s\" to=\"%s\" type=\"%s\">\n"+
		"<body>%s</body>\n"+
		"</message>\n", from, tox, typex, msg);
}

Jacc.addbuddy(sock: ref Sys->FD, jid: string, na: string, group: string): int
{
	grouptag := "<group>"+group+"</group>\n";
	if(na == nil){
		na = jid;

		i := libc->strchr(na, '@');
		if(i < 0)
			return -1;
		
		jid[i] = '\0';
		jid = jid[i++:];
		jid = na + "@" + jid;
	}
	
	return sys->fprint(sock, "<iq type=\"set\">\n"+
		 		 "<query xmlns=\"jabber:iq:roster\">\n"+
				 "<item jid=\"%s\" name=\"%s\"/>\n"+
				 "%s"+
				 "</query>\n"+
				 "</iq>\n", jid, na, grouptag);
}

Jacc.delbuddy(sock: ref Sys->FD, jid: string): int
{
	return sys->fprint(sock, "<iq type=\"set\">\n"+
		"<query xmlns=\"jabber:iq:roster\">\n"+
		"<item jid=\"%s\" subscription=\"remove\"/>\n"+
		"</query>\n"+
		"</iq>\n", jid);
}

Jacc.xmlns(sock: ref Sys->FD, who: string, t: string, id: string): int
{
	return sys->fprint(sock, "<iq type=\"get\" to=\"%s\" id=\"%s\">\n"+
		"<query xmlns=\"%s\"/>\n"+
		"</iq>\n", who, id, t);
}

printjid(user: string, serv: string, reso: string): string
{
	if(user == nil || serv == nil)
		return nil;

	dreso := "";
	if(reso != nil)
		dreso = "/" + reso;
	return sys->sprint("%s@%s%s", user, serv, dreso);
}

nomod(s: string)
{
	sys->fprint(sys->fildes(2), "jacc: cannot load %s: %r\n", s);
	raise "fail: bad module";
}

loadmods()
{
	sys = load Sys Sys->PATH;
	libc = load Libc Libc->PATH;
	math = load Math Math->PATH;
	str = load String String->PATH;
	dial = load Dial Dial->PATH;
	daytime = load Daytime Daytime->PATH;
	ssl3 = load SSL3 SSL3->PATH;
	ssl3->init();
	auth = load Factotum Factotum->PATH;
	auth->init();

	xp = load Xmlpull Xmlpull->PATH;
	if(xp == nil)
		nomod(Xmlpull->PATH);
	xp->init();
	pres_chan = chan of (string, string, string);
	msg_chan = chan of (string, string);
	vcard_chan = chan of string;
}



daytickerpid := jaccrecvpid := -1;

init(nil: ref Draw->Context, argv: list of string)
{
	server, user, passwd: string;
	me: ref jabberc;
	sock: ref Sys->FD;
	
	loadmods();

	me = ref jabberc;
	me.tls = 0;
	me.reg = 0;
	me.debug = 0;
	me.show = "Online";
	me.stat = "Online";
	me.reso = "Plan9";
	me.last = daytime->now();

	arg := load Arg Arg->PATH;
	arg->init(argv);
	arg->setusage("jacc [-dgit] [-r res] [-s tosrv] server");
	while((opt := arg->opt()) != 0)
		case opt {
		't' =>
			me.tls++;
		'r' =>
			me.reso = arg->arg();
		'g' =>
			me.reg++;
		'd' =>
			me.debug++;
		'i' =>
			doignore++;
		's' =>
			me.serv = arg->arg();
		* =>
			arg->usage();
		}

	argv = arg->argv();
	if(len argv < 1)
		arg->usage();

	server = hd argv;
	(user, passwd) = auth->getuserpasswd("proto=pass server="+server+" service=jabber");
	if(user == nil)
		fatal(sys->sprint("getuserpasswd: %r\n"));

	me.name = user;
	if(me.serv == nil)
		me.serv = server;
	me.jid = printjid(me.name, me.serv, me.reso);
	
	port := "5222";
	if(me.tls)
		port = "5223";

	addr := dial->netmkaddr(server, "tcp", port);
	(ok, c) := sys->dial(addr, nil);
	if(ok < 0)
		fatal(sys->sprint("dial: %r\n"));
	
	if(me.tls){
		err :=  "";
		(err, sock) = pushssl(c.dfd, addr);
		if(err != nil)
			fatal(sys->sprint("ssl->connect: err %s: %r\n", err));
	}
	
	spawn dayticker();
	spawn Jacc.recv(sock, me, passwd);
	Jacc.prog(sock, me);

	say(sys->sprint("killing pids %d %d\n", daytickerpid, jaccrecvpid));
	kill(daytickerpid, "kill");
	kill(jaccrecvpid, "kill");
}

killall()
{
	kill(daytickerpid, "kill");
	kill(jaccrecvpid, "kill");
}


cmdhelp := array[] of {
	("a", "/a [+-*]jid - authenticate jid"),
	("b", "/b - turn debugging on or off"),
	("c", "/c file - set vcard on server"),
	("d", "/d jid [feat] - do a discovery request"),
	("e", "/e jid - get time from jid"),
	("g", "/g jid - get agents information from jid"),
	("h", "/h - print out this help"),
	("i", "/i jid - get version of jid"),
	("l", "/l [query] - list the roster"),
	("m", "/m jid - send a message to jid"),
	("p", "/p [show] [stat] - set status and show"),
	("q", "/q - quit jacc"),
	("s", "/s [jid] - set active jid"),
	("t", "/t jid - get idle time of jid"),
	("u", "/u [+-]jid [alias] - manage roster"),
	("v", "/v [jid] - get vcard from jid"),
	("x", "/x [xmpp-xml] - send xmpp xml stanzas"),
};

jacchelp(tmstmp, arg: string)
{
	sys->print("%sHelp for jacc:\n", tmstmp);
	for(i:=0; i < len cmdhelp; i++){
		(opt, msg) := cmdhelp[i];
		if (arg == nil)
			sys->print("%s	%s\n", tmstmp, msg);
		else if(arg == opt){
			sys->print("%s	%s\n", tmstmp, msg);
			break;
		}
	}
}

getline(): string
{
	b := array[1024] of byte;
	i := 0;
	while(i < len b){
		if(sys->read(sys->fildes(0), b[i++:], 1) <= 0)
			break;
		if(b[i-1] == byte '\n')
			break;
	}
	return string b[0:i-1];
}

Jacc.prog(sock: ref Sys->FD, me: ref jabberc)
{
	tmstmp, arg, b, tox: string;

	user := "notnil";
	while(sock != nil && user != nil){
		me.last = daytime->now();
		tmstmp = mktmstmp('#');
		user = getline();
		if(user[0] != '/'){
			b = filterhin(user, 0);
			Jacc.message(sock, me.jid, tox, b, "chat");
			sys->print("%s\n", tmstmp);
			continue;
		}
		
		if(len user > 1)
		case(int user[1]){
		'h' or 'H' =>
			arg = getarg(user, 1, 0);
			jacchelp(tmstmp, arg);
		'q' or 'Q' =>
			sys->fprint(sock, "<presence from=\"%s\" type=\"unavailable\"/>", me.jid);
			sys->fprint(sock, "</stream:stream>");
			user = nil;
		's' or 'S' =>
			arg = getarg(user, 1, 0);
			sys->print("%s%s\n", tmstmp, tox);
			if(arg == nil)
				break;
			tox = me.rost.namer(nil, arg);
		'l' or 'L' =>
			arg = getarg(user, 1, 0);
			me.rost.print(arg, mktmstmp('#'));
		'm' or 'M' =>
			jid := getarg(user, 1, 0);
			if(jid == nil)
				break;
			msg := getarg(user, 2, 2);
			if(msg == nil)
				break;
			Jacc.message(sock, me.jid, me.rost.namer(nil, jid), msg, "normal");
		'p' or 'P' =>
			show := getarg(user, 1, 0);
			sys->print("%s %s %s\n", tmstmp, me.stat, me.show);
			if(show == nil)
				break;
			Jacc.presence(sock, nil, show, nil, nil);

			status := getarg(user, 2, 2);
			if(status == nil)
				break;
			Jacc.presence(sock, status, show, nil, nil);

			(me.stat, me.show) = (status, show);
			me.rost.status(me.jid, me.jid, show, status);
		'c' or 'C' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;

			fd := sys->open(arg, Sys->OREAD);
			if(fd != nil)
				Jacc.vcardset(sock, me.jid, fd);
		'v' or 'V' =>
			arg = getarg(user, 1, 0);
			if(arg == nil){
				Jacc.vcardget(sock, me.jid, "from");
				break;
			}
			Jacc.vcardget(sock, me.rost.namer(nil, arg), "to");
			sys->print("Vcard of: %s\n", me.rost.namer(nil, arg));
		'u' or 'U' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;

			if(arg[0] == int '-')
				Jacc.delbuddy(sock, me.rost.namer(arg[1:], arg[1:]));
			else{
				b = getarg(user, 2, 0);
				if(arg[0] == int '+')
					Jacc.addbuddy(sock, arg[1:], b, nil);
				else
					Jacc.addbuddy(sock, arg, b, nil);
			}
		'a' or 'A' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;

			case(int arg[0]){
			'+' =>
				Jacc.presencetype(sock, me.jid, me.rost.namer(nil, arg[1:]), "subscribed");
			'-' =>
				Jacc.presencetype(sock, me.jid, me.rost.namer(nil, arg[1:]), "unsubscribe");
			'*' =>
				Jacc.presencetype(sock, me.jid, me.rost.namer(nil, arg[1:]), "subscribe");
			* =>
				Jacc.presencetype(sock, me.jid, me.rost.namer(nil, arg), "subscribed");
			}
		'd' or 'D' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;

			b = getarg(user, 2, 2);
			if(b == nil)
				b = "info";

			disco := sys->sprint("http://jabber.org/protocol/disco#%s", b);
			Jacc.xmlns(sock, arg, disco, "disco0");
		'b' or 'B' =>
			me.debug = !me.debug;
			sys->print("%sDebug: %d\n", tmstmp, me.debug);
		't' or 'T' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;
			Jacc.xmlns(sock, me.rost.namer(nil, arg), "jabber:iq:last", "last0");
		'i' or 'I' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;
			Jacc.xmlns(sock, me.rost.namer(nil, arg), "jabber:iq:version", "version0");
		'e' or 'E' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;
			Jacc.xmlns(sock, me.rost.namer(nil, arg), "jabber:iq:time", "time0");
		'g' or 'G' =>
			arg = getarg(user, 1, 0);
			if(arg == nil)
				break;
			Jacc.xmlns(sock, me.rost.namer(nil, arg), "jabber:iq:agents", "agents0");
		'x' or 'X' =>
			arg = user[3:];
			if(arg == nil)
				break;
			sys->fprint(sock, "%s\n", arg);
		}
	}
 	me = nil;
}

Jacc.recv(sock: ref Sys->FD, me: ref jabberc, pass: string)
{
	x, b: ref xmlpull;
	id, tox, from, tmstmp: string;
	typex, va, xm: string;
	ac, p: ref Rostern;

	ready = 0;
	vcardstr: string;

	jaccrecvpid = sys->pctl(0, nil);
	st := NONE;
	ac = me.rost;

	if(Jacc.xml(sock) < 0)
		fatal("jacc: xml");
	if(Jacc.login(sock, me.serv) < 0)
		fatal("jacc: login");
	
	x = x.open(sock, Sys->ORDWR);
	while((b = x.next()) != nil && st != END){
		tmstmp = mktmstmp('#');
		if(x.na != nil)
			x.na = filterzur(x.na);
		if(x.va != nil)
			x.va = filterzur(x.va);
		case(int b.ev){
		START_DOCUMENT =>
			if(me.debug)
				sys->print("Start.\n");
			st = NONE;
		START_TAG =>
			if(me.debug)
				sys->print("Tag: %s\n", x.na);
			if(str->prefix("stream:stream", x.na)){
				st = STREAM;
				break;
			}
			if(str->prefix("stream:error", x.na)){
				st = ERROR;
				break;
			}
			if(st == ERROR){
				if(x.na != "text")
					sys->fprint(sys->fildes(2), "%serror: %s\n", tmstmp, x.na);
				break;
			}
			if(str->prefix("message", x.na)){
				st = MESSAGE;
				break;
			}
			if(str->prefix("presence", x.na)){
				id = nil;
				st = PRESENCE;
				break;
			}
			if(str->prefix("iq", x.na)){
				st = IQ;
				break;
			}
			if(str->prefix("vCard", x.na) && st == IQ){
				st = IQ_VCARD;
				break;
			}
			if(str->prefix("error", x.na) && st == IQ){
				st = IQ_ERROR;
				break;
			}
			if(str->prefix("body", x.na) && st == MESSAGE){
				st = MESSAGE_INNER;
				break;
			}
			if(str->prefix("html", x.na) && st == MESSAGE){
				st = MESSAGE_HTML;
				break;
			}
			if(str->prefix("status", x.na) && (st == PRESENCE || st == PRESENCE_SET)){
				st = PRESENCE_STATUS;
				break;
			}
			if(str->prefix("show", x.na) && (st == PRESENCE || st == PRESENCE_SET)){
				st = PRESENCE_SHOW;
				break;
			}
			if(str->prefix("error", x.na) && (st == PRESENCE || st == PRESENCE_SET)){
				st = PRESENCE_ERROR;
				break;
			}
			if(str->prefix("x", x.na) && st == PRESENCE){
				st = PRESENCE_X;
				break;
			}
			if(str->prefix("item", x.na) && st == ROSTER){
				if(me.rost == nil){
					me.rost = ref Rostern;
					ac = ref Rostern;
					me.rost.n = ac;
					me.rost.p = nil;
					me.rost.name = me.name;
					me.rost.jid = me.jid;
					me.rost.stat = me.stat;
					me.rost.show = me.show;
					me.rost.subsc = "self";
					me.rost.group = "self";
				}
				else{
					ac.n = ref Rostern;
					ac.n.p = ac;
					ac = ac.n;
					ac.n = nil;
				}
				st = ROSTER_INNER;
				break;
			}
			if(str->prefix("query", x.na) && st == IQ){
				st = IQ_INNER;
				break;
			}
			if(str->prefix("item", x.na) && st == IQ_INNER){
				st = IQ_ITEM;
				ac = ref Rostern;
				break;
			}
			if(str->prefix("group", x.na) && st == IQ_ITEM){
				st = IQ_GROUP;
				break;
			}
			if(str->prefix("group", x.na) && st == ROSTER_INNER){
				st = ROSTER_GROUP;
				break;
			}
			if(str->prefix("utc", x.na) && st == IQ_TIME){
				st = IQ_TIME_UTC;
				break;
			}
			if(str->prefix("tz", x.na) && st == IQ_TIME){
				st = IQ_TIME_TZ;
				break;
			}
			if(str->prefix("display", x.na) && st == IQ_TIME){
				st = IQ_TIME_DISPLAY;
				break;
			}
			if(str->prefix("item", x.na) && st == IQ_DISCO){
				st = IQ_DISCO_ITEM;
				break;
			}
			if(str->prefix("identity", x.na) && st == IQ_DISCO){
				sys->print("%sserver identity:\n", tmstmp);
				st = IQ_DISCO_IDENT;
				break;
			}
			if(str->prefix("feature", x.na) && st == IQ_DISCO){
				st = IQ_DISCO_FEATU;
				break;
			}
			if(str->prefix("empty", x.na) && st == IQ_DISCO){
				st = IQ_DISCO_EMPTY;
				break;
			}
			if(str->prefix("version", x.na) && st == IQ_VERSION){
				st = IQ_VERSION_VER;
				break;
			}
			if(str->prefix("os", x.na) && st == IQ_VERSION){
				st = IQ_VERSION_OS;
				break;
			}
			if(str->prefix("name", x.na) && st == IQ_VERSION){
				st = IQ_VERSION_NAME;
				break;
			}
			if(str->prefix("agent", x.na) && st == IQ_AGENTS){
				st = IQ_AGENTS_AGENT;
				break;
			}
			if(str->prefix("name", x.na) && st == IQ_AGENTS_AGENT){
				st = IQ_AGENTS_NAME;
				break;
			}
			if(str->prefix("description", x.na) && st == IQ_AGENTS_AGENT){
				st = IQ_AGENTS_DESC;
				break;
			}
			if(str->prefix("transport", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  This is a transport.\n", tmstmp);
				break;
			}
			if(str->prefix("groupchat", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  You can groupchat here.\n", tmstmp);
				break;
			}
			if(str->prefix("service", x.na) && st == IQ_AGENTS_AGENT){
				st = IQ_AGENTS_SERV;
				break;
			}
			if(str->prefix("register", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  You can register here.\n", tmstmp);
				break;
			}
			if(str->prefix("search", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  You can search here.\n", tmstmp);
				break;
			}
			if(st == IQ_VCARD){
				
				if(str->prefix("FN", x.na) 	||
				   str->prefix("GIVEN", x.na)	||
				   str->prefix("FAMILY", x.na)	||
				   str->prefix("MIDDLE", x.na)	||
				   str->prefix("PREFIX", x.na)	||
				   str->prefix("SUFFIX", x.na)	||
				   str->prefix("VERSION", x.na)	||
				   str->prefix("NICKNAME", x.na)||
				   str->prefix("PHOTO", x.na)	||
				   str->prefix("BDAY", x.na)	||
				   str->prefix("POBOX", x.na)	||
				   str->prefix("EXTADR", x.na)	||
				   str->prefix("STREET", x.na)	||
				   str->prefix("LOCALITY", x.na)||
				   str->prefix("REGION", x.na)	||
				   str->prefix("PCODE", x.na)	||
				   str->prefix("CTRY", x.na)	||
				   str->prefix("NUMBER", x.na)	||
				   str->prefix("USERID", x.na)	||
				   str->prefix("JABBERID", x.na)||
				   str->prefix("MAILER", x.na)	||
				   str->prefix("LAT", x.na)	||
				   str->prefix("LON", x.na)	||
				   str->prefix("TITLE", x.na)	||
				   str->prefix("ROLE", x.na)	||
				   str->prefix("AGENT", x.na)	||
				   str->prefix("ORGNAME", x.na)	||
				   str->prefix("ORGUNIT", x.na)	||
				   str->prefix("NOTE", x.na)	||
				   str->prefix("PRODID", x.na)	||
				   str->prefix("REV", x.na)	||
				   str->prefix("PHONETIC", x.na)||
				   str->prefix("DESC", x.na)	||
				   str->prefix("CRED", x.na)){
#					sys->print("%s%s = ", tmstmp, x.na);
					vcardstr = tmstmp + x.na[ : len x.na - 2] + "=";
					st = IQ_VCARD_INNER;
					break;
				}
					
				if(str->prefix("HOME", x.na)	||
				   str->prefix("WORK", x.na)	||
				   str->prefix("POSTAL", x.na)	||
				   str->prefix("PARCEL", x.na)	||
				   str->prefix("DOM", x.na)	||
				   str->prefix("INTL", x.na)	||
				   str->prefix("PREF", x.na)	||
				   str->prefix("VOICE", x.na)	||
				   str->prefix("FAX", x.na)	||
				   str->prefix("PAGER", x.na)	||
				   str->prefix("MSG", x.na)	||
				   str->prefix("CELL", x.na)	||
				   str->prefix("VIDEO", x.na)	||
				   str->prefix("BBS", x.na)	||
				   str->prefix("MODEM", x.na)	||
				   str->prefix("ISDN", x.na)	||
				   str->prefix("PCS", x.na)	||
				   str->prefix("INTERNET", x.na)||
				   str->prefix("X400", x.na)){
					sys->print("%s%s\n", tmstmp, x.na);
					break;
				}
				
			}
		START_END_TAG =>
			if(me.debug)
				sys->print("Startend: %s\n", x.na);
			if(str->prefix("empty", x.na) && st == IQ_DISCO){
				sys->print("%s <empty>\n", tmstmp);
				break;
			}
			if(str->prefix("transport", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  This is a transport.\n", tmstmp);
				break;
			}
			if(str->prefix("groupchat", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  You can groupchat here.\n", tmstmp);
				break;
			}
			if(str->prefix("register", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  You can register here.\n", tmstmp);
				break;
			}
			if(str->prefix("search", x.na) && st == IQ_AGENTS_AGENT){
				sys->print("%s  You can search here.\n", tmstmp);
				break;
			}
			if(st == ERROR || st == PRESENCE_ERROR || st == IQ_ERROR){
				sys->fprint(sys->fildes(2), "%serror: %s\n", tmstmp, x.na);
				break;
			}
		TEXT =>
			if(me.debug)
				sys->print("Text: %s\n", x.na);
			case(int st){
			MESSAGE_INNER =>
				typex = x.na;
			PRESENCE_SHOW =>
				if(typex == nil || !str->prefix("error", typex))
					if(me.rost.status(from, from, nil, x.na) != nil){
						sys->print("%s%s> %s\n", tmstmp, me.rost.namer(from, nil), x.na);
						sys->print("in if\n");
					}
					s := x.na;
					pres_chan <-= (from, s[ : len s - 2], nil);
			PRESENCE_STATUS =>
				if(typex == nil || !str->prefix("error", typex))
					if(me.rost.status(from, from, x.na, nil) != nil){
						sys->print("%s%s> %s\n", tmstmp, me.rost.namer(from, nil), x.na);
						sys->print("in if\n");
					}
					sys->print("status\n");
			PRESENCE_ERROR =>
				sys->print("%s%s# %s\n", tmstmp, me.rost.namer(from, nil), x.na);
				typex = nil;
				typex = "isdone";
			ROSTER_GROUP =>
				if(ac.group == nil)
					ac.group = x.na;
			IQ_GROUP =>
				if(ac.group == nil)
					ac.group = x.na;
			IQ_ERROR =>
				sys->print("%sIQ-Error: %s\n", tmstmp, x.na);
			IQ_VCARD_INNER =>{
#				sys->print("%s\n", x.na);
				vcardstr = vcardstr + x.na[ : len x.na - 2] + "\n";
				vcard_chan <-= vcardstr;
				vcardstr = nil;
			}
			IQ_VERSION_OS =>
				sys->print("%s  os = %s\n", tmstmp, x.na);
			IQ_VERSION_NAME =>
				sys->print("%s  name = %s\n", tmstmp, x.na);
			IQ_VERSION_VER =>
				sys->print("%s  version = %s\n", tmstmp, x.na);
			IQ_TIME_UTC =>
				sys->print("%sutc = %s\n", tmstmp, x.na);
			IQ_TIME_TZ =>
				sys->print("%stz = %s\n", tmstmp, x.na);
			IQ_TIME_DISPLAY =>
				sys->print("%sdisplay = %s\n", tmstmp, x.na);
			IQ_AGENTS_NAME =>
				sys->print("%s  name = %s\n", tmstmp, x.na);
			IQ_AGENTS_DESC =>
				sys->print("%s  description = %s\n", tmstmp, x.na);
			IQ_AGENTS_SERV =>
				sys->print("%s  service = %s\n", tmstmp, x.na);
			}
		ATTR =>
			if(me.debug)
				sys->print("Attr: %s = %s\n", x.na, x.va);
			case(int st){
			STREAM =>
				if(str->prefix("id", x.na)){
					say(sys->sprint("register %s@%s\n", me.name, me.serv));
					st = NONE;
					if(me.reg){
						Jacc.register(sock, me.serv, me.name, pass);
						break;
					}
					if(Jacc.user(sock, me.name, pass, me.reso) < 0){
						pass = nil;
						st = AUTH;
						break;
					}
				}
			MESSAGE =>
				if(str->prefix("from", x.na))
					from = x.va;
				if(str->prefix("to", x.na))
					tox = x.va;
				if(str->prefix("type", x.na))
					typex = x.va;
			PRESENCE =>
				if(str->prefix("from", x.na))
					from = x.va;
				if(str->prefix("type", x.na))
					typex = x.va;
			IQ =>
				if(str->prefix("id", x.na)){
					if(str->prefix("auth_1", x.va))
						Jacc.roster(sock);
					if(str->prefix("auth_2", x.va))
						st = ROSTER;
					if(str->prefix("disco0", x.va))
						st = IQ_DISCO;
					if(str->prefix("time0", x.va))
						st = IQ_TIME;
					if(str->prefix("agents0", x.va))
						st = IQ_AGENTS;
					if(str->prefix("last0", x.va))
						st = IQ_LAST;
					if(str->prefix("version0", x.va))
						st = IQ_VERSION;
					id = x.va;
				}
				if(str->prefix("from", x.na))
					from = x.va;
				if(str->prefix("to", x.na))
					tox = x.va;
				if(str->prefix("type", x.na))
					typex = x.va;
			ROSTER_INNER =>
				if(str->prefix("name", x.na)){
					ac.name = x.va;
					break;
				}
				if(str->prefix("jid", x.na)){
					ac.jid = x.va;
					break;
				}
			IQ_INNER =>
				if(str->prefix("xmlns", x.na)){
					xm = x.va;
				}
				if(str->prefix("name", x.na)){
					va = x.va;
				}
			IQ_ITEM =>
				if(str->prefix("subscription", x.na)){
					ac.subsc = x.va;
					break;
				}
				if(str->prefix("jid", x.na)){
					ac.jid = x.va;
					break;
				}
				if(str->prefix("name", x.na)){
					ac.name = x.va;
					break;
				}
			IQ_DISCO_IDENT =>
				sys->print("%s%s = %s\n", tmstmp, x.na, x.va);
			IQ_DISCO_FEATU =>
				sys->print("%s  %s\n", tmstmp, x.va);
			IQ_DISCO_ITEM =>
				if(str->prefix("name", x.na)){
					id = x.va;
				}
				if(str->prefix("jid", x.na)){
					tox = x.va;
				}
			IQ_AGENTS_AGENT =>
				if(str->prefix("jid", x.na))
					sys->print("%s%s:\n", tmstmp, x.va);
			IQ_LAST =>
				if(str->prefix("seconds", x.na))
					sys->print("%s%s> %ss away\n", tmstmp, me.rost.namer(nil, from), x.va);
			}
		END_TAG =>
			if(me.debug)
				sys->print("Endtag: %s\n", x.na);
			if(str->prefix("stream:stream", x.na)){
				st = END;
				break;
			}
			if(str->prefix("stream:error", x.na) && st == ERROR){
				st = NONE;
				break;
			}
			if(st == ERROR)
				break;
			if(str->prefix("message", x.na) && st == MESSAGE){
				if(typex != nil){
					afrom := "<nil>";
					if(from != nil)
						afrom = me.rost.namer(from, nil);

					atox := "<nil>";
					if(tox != nil)
						atox = me.rost.namer(tox, nil);

					# Q: is possible to recv msgs to != atox?
#					sys->print("%s%s %s\n", mktmstmp('+'), afrom, typex);
					typex = typex[ : len typex - 2]; #discard bad characters
					msg_chan <-= (from, mktmstmp('+')+":" + typex);
				}
				from = nil;
				tox = nil;
				typex = nil;
				st = NONE;
				break;
			}
			if(str->prefix("presence", x.na) && st == PRESENCE_SET){
				typex = nil;
				from = nil;
				st = NONE;
				break;
			}
			if(str->prefix("presence", x.na) && st == PRESENCE){
				presence_strcmp := 0;
				if(str->prefix("unavailable", typex) || str->prefix("error", typex)){
					if(me.rost.status(from, from, nil, "Offline") != nil)
						sys->print("%s%s> Offline\n", tmstmp, me.rost.namer(from, nil));
						pres_chan <-= (from, "offline", nil);
					presence_strcmp = 1;
				}
				if(str->prefix("probe", typex)){
					Jacc.presence(sock, me.stat, me.show, me.jid, from);
					presence_strcmp = 1;
				}
				if(str->prefix("subscribe", typex)){
					me.rost.status(from, from, nil, "Online");
#					sys->print("%s%s wants to subscribe\n", tmstmp, me.rost.namer(from, nil));
					presence_strcmp = 1;
				}
				if(str->prefix("unsuscribe", typex)){
					if(me.rost.status(from, from, nil, "Offline") != nil)
						sys->print("%s%s wants to unsubscribe\n", tmstmp, me.rost.namer(from, nil));
					presence_strcmp = 1;
				}
				if(str->prefix("suscribed", typex)){
					sys->print("%s%s has accepted the subscription request\n", tmstmp, me.rost.namer(from, nil));
					presence_strcmp = 1;
				}
				if(str->prefix("isdone", typex)){
					presence_strcmp = 1;
				}

				if(presence_strcmp){
					typex = nil;
					from = nil;
					st = NONE;
					break;
				}else{
					if(from != nil){
						me.rost.status(from, from, nil, "Online");
#						sys->print("%s%s> Online\n", tmstmp, me.rost.namer(from, nil));
						pres_chan <-= (from, "online", nil);
					}
				}				
			}
			if(str->prefix("iq", x.na) && (st == IQ || st == IQ_DISCO)){
				from = nil;
				tox = nil;
				id = nil;
				typex = nil;
				va = nil;
				xm = nil;
				st = NONE;
				break;
			}
			if(str->prefix("iq", x.na) && st == ROSTER){
				from = nil;
				tox = nil;
				id = nil;
				typex = nil;
				Jacc.presence(sock, me.stat, me.show, nil, nil);
				st = NONE;
				ready = 1;
				break;
			}
			if(str->prefix("vCard", x.na) && st == IQ_VCARD){
				st = IQ;
				break;
			}
			if(str->prefix("error", x.na) && st == IQ_ERROR){
				st = IQ;
				break;
			}
			if(str->prefix("body", x.na) && st == MESSAGE_INNER){
				st = MESSAGE;
				break;
			}
			if(str->prefix("html", x.na) && st == MESSAGE_HTML){
				st = MESSAGE;
				break;
			}
			if(str->prefix("status", x.na) && st == PRESENCE_STATUS){
				st = PRESENCE_SET;
				break;
			}
			if(str->prefix("show", x.na) && st == PRESENCE_SHOW){
				st = PRESENCE_SET;
				break;
			}
			if(str->prefix("x", x.na) && st == PRESENCE_X){
				st = PRESENCE;
				break;
			}
			if(str->prefix("error", x.na) && st == PRESENCE_ERROR){
				st = PRESENCE;
				break;
			}
			if(str->prefix("item", x.na) && st == ROSTER_INNER){
				if(!doignore)
					sys->print("%sAdded user: %s/%s/%s\n", tmstmp, ac.name, ac.jid, ac.group);
				st = ROSTER;
				break;
			}
			if(str->prefix("query", x.na) && (st == IQ_INNER || st == IQ_VERSION || st == IQ_TIME || st == IQ_LAST || st == IQ_AGENTS)){
				if(st == IQ_INNER){
					if(str->prefix("jabber:iq:version", xm)){
						if(tox != me.jid)
							break;
						else
							Jacc.version(sock, me.jid, from, id);
						break;
					}
					if(str->prefix("jabber:iq:last", xm))
						if(!(me.jid != tox))
							Jacc.last(sock, tox, from, id, daytime->now()-me.last);
					if(str->prefix("http://jabber.org/protocol/disco#info", xm))
						if(!(me.jid != tox))
							if(id != nil && id != "http://jabber.org/protocol/muc#rooms")
								Jacc.features(sock, tox, from, id);
					if(str->prefix("jabber:iq:time", xm))
						if(!(me.jid != tox))
							Jacc.time(sock, tox, from, id);
				}
				st = IQ;
				break;
			}
			if(str->prefix("item", x.na) && st == IQ_ITEM){
				st = IQ_INNER;
				if(ac != nil && ac.subsc != nil){
					if(str->prefix("remove", ac.subsc)){
						me.rost = me.rost.delname(ac.name, ac.jid);
						sys->print("%sremoved: %s\n", tmstmp, ac.jid);
						ac = nil;
						break;
					}
					if(str->prefix("both", ac.subsc) || str->prefix("to", ac.subsc) || str->prefix("from", ac.subsc) || str->prefix("none", ac.subsc) || str->prefix("ask", ac.subsc)){
						if(str->prefix("ask", ac.subsc))
							sys->print("%s%s asks for authorisation.\n", tmstmp, ac.jid);
						if((p = me.rost.search(ac.name, ac.jid)) == nil){
							ac.subsc = ac.subsc;
							me.rost.add(ac);
							if(!str->prefix("ask", ac.subsc))
								sys->print("%sadded: %s\n", tmstmp, ac.jid);
						}
						else{
							p.jid = nil;
							if(ac.jid != nil)
								p.jid = ac.jid;
							p.name = nil;
							if(ac.name != nil)
								p.name = ac.name;
							p.subsc = nil;
							if(ac.subsc != nil)
								p.subsc = ac.subsc;

							sys->print("%supdate: %s/%s\n", tmstmp, ac.name, ac.jid);
							ac = nil;
						}
					}
				}
				ac = nil;
				break;
			}
			if(str->prefix("group", x.na) && st == IQ_GROUP){
				st = IQ_ITEM;
				break;
			}
			if(str->prefix("group", x.na) && st == ROSTER_GROUP){
				st = ROSTER_INNER;
				break;
			}
			if(str->prefix("item", x.na) && st == IQ_DISCO_ITEM){
				sys->print("%s  %s | %s\n", tmstmp, tox, id);
				st = IQ_DISCO;
				break;
			}
			if(str->prefix("identity", x.na) && st == IQ_DISCO_IDENT){
				sys->print("%sfeatures:\n", tmstmp);
				st = IQ_DISCO;
				break;
			}
			if(str->prefix("feature", x.na) && st == IQ_DISCO_FEATU){
				st = IQ_DISCO;
				break;
			}
			if(str->prefix("empty", x.na) && st == IQ_DISCO_EMPTY){
				st = IQ_DISCO;
				break;
			}
			if(str->prefix("utc", x.na) && st == IQ_TIME_UTC){
				st = IQ_TIME;
				break;
			}
			if(str->prefix("tz", x.na) && st == IQ_TIME_TZ){
				st = IQ_TIME;
				break;
			}
			if(str->prefix("display", x.na) && st == IQ_TIME_DISPLAY){
				st = IQ_TIME;
				break;
			}
			if(str->prefix("version", x.na) && st == IQ_VERSION_VER){
				st = IQ_VERSION;
				break;
			}
			if(str->prefix("name", x.na) && st == IQ_VERSION_NAME){
				st = IQ_VERSION;
				break;
			}
			if(str->prefix("os", x.na) && st == IQ_VERSION_OS){
				st = IQ_VERSION;
				break;
			}
			if(str->prefix("agent", x.na) && st == IQ_AGENTS_AGENT){
				st = IQ_AGENTS;
				sys->print("%s\n", tmstmp);
				break;
			}
			if(str->prefix("name", x.na) && st == IQ_AGENTS_NAME){
				st = IQ_AGENTS_AGENT;
				break;
			}
			if(str->prefix("description", x.na) && st == IQ_AGENTS_DESC){
				st = IQ_AGENTS_AGENT;
				break;
			}
			if((str->prefix("transport", x.na) || str->prefix("groupchat", x.na) || str->prefix("register", x.na) || str->prefix("search", x.na)) && st == IQ_AGENTS_AGENT)
				break;
			if(str->prefix("service", x.na) && st == IQ_AGENTS_SERV){
				st = IQ_AGENTS_AGENT;
				break;
			}
			if(st == IQ_VCARD_INNER){
				st = IQ_VCARD;
				break;
			}
		END_DOCUMENT =>
			if(me.debug)
				sys->print("Documentend.\n");
			st = END;
		* =>
			sys->print("Please contact the xmlpull author about this. %x\n", b.ev);
			st = END;
		}
		tmstmp = nil;
	}
	
	id = nil;
}

ssl_suites := array [] of {
        byte 0, byte 16r03,     # RSA_EXPORT_WITH_RC4_40_MD5
        byte 0, byte 16r04,     # RSA_WITH_RC4_128_MD5
        byte 0, byte 16r05,     # RSA_WITH_RC4_128_SHA
        byte 0, byte 16r06,     # RSA_EXPORT_WITH_RC2_CBC_40_MD5
        byte 0, byte 16r07,     # RSA_WITH_IDEA_CBC_SHA
        byte 0, byte 16r08,     # RSA_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r09,     # RSA_WITH_DES_CBC_SHA
        byte 0, byte 16r0A,     # RSA_WITH_3DES_EDE_CBC_SHA

        byte 0, byte 16r0B,     # DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r0C,     # DH_DSS_WITH_DES_CBC_SHA
        byte 0, byte 16r0D,     # DH_DSS_WITH_3DES_EDE_CBC_SHA
        byte 0, byte 16r0E,     # DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r0F,     # DH_RSA_WITH_DES_CBC_SHA
        byte 0, byte 16r10,     # DH_RSA_WITH_3DES_EDE_CBC_SHA
        byte 0, byte 16r11,     # DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r12,     # DHE_DSS_WITH_DES_CBC_SHA
        byte 0, byte 16r13,     # DHE_DSS_WITH_3DES_EDE_CBC_SHA
        byte 0, byte 16r14,     # DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r15,     # DHE_RSA_WITH_DES_CBC_SHA
        byte 0, byte 16r16,     # DHE_RSA_WITH_3DES_EDE_CBC_SHA

        byte 0, byte 16r17,     # DH_anon_EXPORT_WITH_RC4_40_MD5
        byte 0, byte 16r18,     # DH_anon_WITH_RC4_128_MD5
        byte 0, byte 16r19,     # DH_anon_EXPORT_WITH_DES40_CBC_SHA
        byte 0, byte 16r1A,     # DH_anon_WITH_DES_CBC_SHA
        byte 0, byte 16r1B,     # DH_anon_WITH_3DES_EDE_CBC_SHA

        byte 0, byte 16r1C,     # FORTEZZA_KEA_WITH_NULL_SHA
        byte 0, byte 16r1D,     # FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
        byte 0, byte 16r1E,     # FORTEZZA_KEA_WITH_RC4_128_SHA
};
ssl_comprs := array [] of {byte 0};
Context: import ssl3;

pushssl(origfd: ref Sys->FD, addr: string): (string, ref Sys->FD)
{
	sslx := Context.new();
	info := ref SSL3->Authinfo(ssl_suites, ssl_comprs, nil, 0, nil, nil, nil);
	(err, vers) :=  sslx.client(origfd, addr, 3, info);
	if(err != nil)
		return (err, nil);
	say(sys->sprint("ssl connected version=%d\n", vers));

	f := sys->sprint("fcn%d.%d", sys->pctl(0, nil), 0);
	fio := sys->file2chan("#shttp", f);
	if(fio == nil)
		return (sys->sprint("file2chan: %r"), nil);
#	spawn fcssl(fio, sslx);
	spawn fcssl_read(fio, sslx);
	spawn fcssl_write(fio, sslx);
	fd := sys->open(sys->sprint("#shttp/%s", f), Sys->ORDWR);
	if(fd == nil)
		return (sys->sprint("opening ssl file: %r"), nil);
	return (nil, fd);
}

fcssl_read(fio: ref Sys->FileIO, sslx: ref SSL3->Context){
	eof := 0;
	for(;;) {
		(nil, count, nil, rc) := <-fio.read;
#		say(sys->sprint("fcssl: have read, count=%d\n", count));
		if(rc == nil) {
			#say("sslfc: rc == nil");
			return;
		}
		if(eof) {
			say("sslfc: eof reading\n");
			rc <-= (array[0] of byte, nil);
			continue;
		}
#		say("before sslx.read\n");
		n := sslx.read(d := array[count] of byte, len d);
#		say("after sslx.read\n");
		if(n < 0) {
			#say(sprint("sslfc: error: %r"));
			rc <-= (nil, sys->sprint("%r"));
			return;
		}else {
#			say(sys->sprint("sslfc: returning %d bytes\n", n));
			rc <-= (d[:n], nil);
		}
		if(n == 0)
			eof = 1;
	}
}

	
fcssl_write(fio: ref Sys->FileIO, sslx: ref SSL3->Context)
{
	#say("fcssl: new");
	for(;;) {
		(nil, d, nil, wc) := <-fio.write;  
		if(wc == nil) {
			#say("fcssl: wc == nil");
			return;
		}
		if(sslx.write(d, len d) != len d) {
			wc <-= (-1, sys->sprint("%r"));
			#say("fcssl: error writing");
			return;
		} else {
			wc <-= (len d, nil);
#			say("fcssl: written\n");
		}
	}
}

fcssl(fio: ref Sys->FileIO, sslx: ref SSL3->Context)
{
	#say("fcssl: new");
	eof := 0;
	for(;;) alt {
	(nil, count, nil, rc) := <-fio.read => {
		say(sys->sprint("fcssl: have read, count=%d\n", count));
		if(rc == nil) {
			#say("sslfc: rc == nil");
			return;
		}
		if(eof) {
			say("sslfc: eof reading\n");
			rc <-= (array[0] of byte, nil);
			continue;
		}
		say("before sslx.read\n");
		n := sslx.read(d := array[count] of byte, len d);
		say("after sslx.read\n");
		if(n < 0) {
			#say(sprint("sslfc: error: %r"));
			rc <-= (nil, sys->sprint("%r"));
			return;
		}else {
			say(sys->sprint("sslfc: returning %d bytes\n", n));
			rc <-= (d[:n], nil);
		}
		if(n == 0)
			eof = 1;

	}(nil, d, nil, wc) := <-fio.write => {
		if(wc == nil) {
			#say("fcssl: wc == nil");
			return;
		}
		if(sslx.write(d, len d) != len d) {
			wc <-= (-1, sys->sprint("%r"));
			#say("fcssl: error writing");
			return;
		} else {
			wc <-= (len d, nil);
			say("fcssl: written\n");
		}
	}
	}
}

mktmstmp(bord: int): string
{
	tm := daytime->local(daytime->now());
	return sys->sprint("%c %.2d:%.2d ", bord, tm.hour, tm.min);
}

getarg(s: string, n: int, t: int): string
{
	ret: string;

	(nargs, args) := sys->tokenize(s, " ");
	if(n >= nargs)
		return nil;
	for (i:=0; i < n; i++)
		args = tl args;
	if(t == 0)
		ret = hd args;
	else{
		for(; args != nil; args = tl args)
			ret += hd args + " ";
		ret = ret[0: len ret -1]; # drop last " "
	}
	return filterhin(ret, 2);
}

readwrite(wfd: ref Sys->FD, rfd: ref Sys->FD)
{
	b := array[2048] of byte;
	l := len b;

	while(l == len b){
		l = sys->read(rfd, b, len b);
		if(l > 0)
			sys->write(wfd, b, l);
	}
}

getmonth(m: int): string
{
	month := array[12] of { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	if(m > len month || m < 0)
		return nil;
	return month[m];
}

getday(d: int): string
{
	wdays := array[7] of { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	if(d > len wdays || d < 0)
		return nil;
	return wdays[d];
}

dayticker()
{
	daytickerpid = sys->pctl(0, nil);
	for(;;){
		tm := daytime->local(daytime->now());
		secs := 24*3600-3*60 - (tm.hour*3600+tm.min*60+tm.sec);
		if(secs > 0)
			sys->sleep(1000*secs);
		tm = daytime->local(daytime->now());
		secs = 24*3600 - (tm.hour*3600+tm.min*60+tm.sec);
		sys->sleep(secs*1000+200);
		tm = daytime->local(daytime->now());
		sys->print("! day changed, %d-%02d-%02d, %s\n", tm.year+1900, tm.mon+1, tm.mday, getday(tm.wday));
		sys->sleep(3600*1000);
	}
}

filterhin(in: string, a: int): string
{
	r, z: string;

	z = in;
	while(len in > 0 && in[0] != '\0'){
		case(in[0]){
		'<' =>
			r[len r] = '&';
			r[len r] = 'l';
			r[len r] = 't';
			r[len r] = ';';
		'&' =>
			r[len r] = '&';
			r[len r] = 'a';
			r[len r] = 'm';
			r[len r] = 'p';
			r[len r] = ';';
		'>' =>
			r[len r] = '&';
			r[len r] = 'g';
			r[len r] = 't';
			r[len r] = ';';
		'"' =>
			r[len r] = '&';
			r[len r] = 'q';
			r[len r] = 'u';
			r[len r] = 'o';
			r[len r] = 't';
			r[len r] = ';';
		* =>
			r[len r] = in[0];
		}
		in=in[1:];
	}

	if(a != 0)
		z = nil;
	return r;
}

strstr(s, t : string) : int
{
	if (t == nil)
		return 0;
        
	n := len t;
	if (n > len s)
		return -1;
	e := len s - n;
	for (p := 0; p <= e; p++)
		if (s[p:p+n] == t)
			return p;
	return -1;
}

filterzur(out: string): string
{
	a, b: int;
	changed: int;
	
	changed = 1;
	while(changed){
		changed = 0;
		if((a = strstr(out, "&lt;")) != -1){
			out[a] = '<';
			for (i:=a; i < len out-4; i++) out[i+1] = out[i+4];
			changed = 1;
		}
		if((a = strstr(out, "&gt;")) != -1){
			out[a] = '>';
			for (i:=a; i < len out-4; i++) out[i+1] = out[i+4];
			changed = 1;
		}
		if((a = strstr(out, "&quot;")) != -1){
			out[a] = '"';
			for (i:=a; i < len out-6; i++) out[i+1] = out[i+6];
			changed = 1;
		}
		if((a = strstr(out, "&amp;")) != -1){
			out[a] = '&';
			for (i:=a; i < len out-5; i++) out[i+1] = out[i+5];
			changed = 1;
		}
		if((a = strstr(out, "text/x-aolrtf;")) != -1){
			b = libc->strchr(out[a:], ':');
			if(b != 0){
				for (i:=a; i < len out-5; i++) out[i] = out[b+2+i];
				changed = 1;
			}
		}
	}
	
	return out;
}

Rostern.del(r: self ref Rostern): ref Rostern
{
	ret: ref Rostern;

	ret = nil;
	if(r.n != nil && r.p != nil){
		r.n.p = r.p;
		r.p.n = r.n;
		ret = r.p;
	}
	else if(r.n != nil){
		r.n.p = nil;
		ret = r.n;
	}
	else if(r.p != nil){
		r.p.n = nil;
		ret = r.p;
	}
	r = nil;
	return ret;
}

last(r: ref Rostern): ref Rostern
{
	while(r.n != nil)
		r = r.n;
	return r;
}

Rostern.add(r: self ref Rostern, n: ref Rostern): ref Rostern
{
	ret: ref Rostern;

	ret = last(r);
	ret.n = n;
	n.p = ret;
	n.n = nil;
	return n;
}

Rostern.status(r: self ref Rostern, name: string, jid: string, status: string, show: string): ref Rostern
{
	r = r.search(name, jid);
	if(r != nil){
		if(show != nil){
			if(str->prefix(show, r.show))
				return nil;
			r.show = show;
		}
		if(status != nil){
			if(str->prefix(status, r.stat))
				return nil;
			r.stat = status;
		}
	}
	return r;
}

Rostern.namer(r: self ref Rostern, jid: string, name: string): string
{
	r = r.search(name, jid);
	if(r != nil){
		if(jid != nil && r.name != nil)
			return r.name;
		if(name != nil && r.jid != nil)
			return r.jid;
	}
	if(jid != nil)
		return jid;
	return name;
}

Rostern.search(r: self ref Rostern, name: string, jid: string): ref Rostern
{
	while(r != nil){
		if(name != nil && str->prefix(name, r.name))
			return r;
		if(jid != nil && str->prefix(jid, r.jid))
			return r;
		r = r.n;
	}
	return nil;
}

Rostern.delname(r: self ref Rostern, name: string, jid: string): ref Rostern
{
	ret: ref Rostern;

	ret = r.search(name, jid);
	if(ret != nil){
		if(ret == r)
			return ret.del();
		ret.del();
	}
	return r;
}

Rostern.print(r: self ref Rostern, w: string, tmstmp: string)
{
	found: int;
	for(; r != nil; r = r.n){
		found = 0;
		if(w == nil)
			found = 1;
		else if(str->prefix(w, r.name) || str->prefix(w, r.jid))
			found = 1;
		else if(str->prefix(w, r.stat) || str->prefix(w, r.show))
			found = 1;
		else if(str->prefix(w, r.group))
			found = 1;

		if(found)
			sys->print("%s%s/%s on %s -> %s/%s\n", tmstmp, r.name, r.jid, r.group, r.show, r.stat);
	}
}

kill(pid: int, scope: string)
{
	fd := sys->open("/prog/"+string pid+"/ctl", sys->OWRITE);
	sys->fprint(fd, "%s", scope);
}

say(s: string)
{
	sys->print("%s", s);
}

fatal(s: string)
{
	sys->fprint(sys->fildes(2), "%s", s);
	raise s;
}
