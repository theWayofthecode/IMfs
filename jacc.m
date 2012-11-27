# 
# Copy me if you can.
# by 20h
#  

JACC: module
{
	PATH: con "/usr/inferno/code/imfs_e_1/jacc.dis";

	NONE, STREAM, AUTH, ERROR, MESSAGE, MESSAGE_INNER, MESSAGE_HTML,
	PRESENCE, PRESENCE_STATUS, PRESENCE_SHOW, PRESENCE_ERROR, PRESENCE_X, PRESENCE_SET,
	IQ, IQ_INNER, IQ_ITEM, IQ_GROUP, IQ_VCARD, IQ_VCARD_INNER, IQ_ERROR,
	IQ_DISCO, IQ_DISCO_IDENT, IQ_DISCO_FEATU, IQ_DISCO_ITEM, IQ_DISCO_EMPTY,
	IQ_VERSION, IQ_VERSION_OS, IQ_VERSION_NAME, IQ_VERSION_VER,
	IQ_TIME, IQ_TIME_UTC, IQ_TIME_TZ, IQ_TIME_DISPLAY,
	IQ_AGENTS, IQ_AGENTS_AGENT, IQ_AGENTS_NAME, IQ_AGENTS_DESC, IQ_AGENTS_SERV, IQ_LAST,
	ROSTER, ROSTER_INNER, ROSTER_GROUP, END: con iota;

	doignore: int;

	init: fn(nil: ref Draw->Context, argl: list of string);

	Jacc: adt{
	
		login:		fn(fd: ref Sys->FD, serv: string): int;
		user:		fn(fd: ref Sys->FD, user, pass, res: string): int;
		register:	fn(fd: ref Sys->FD, serv, user, pass: string): int;
		recv:		fn(fd: ref Sys->FD, me: ref jabberc, pass: string);
		prog:		fn(fd: ref Sys->FD, me: ref jabberc);
		
		version:	fn(fd: ref Sys->FD, from, tox, id: string): int;
		features:	fn(fd: ref Sys->FD, from, tox, id: string): int;
		time:		fn(fd: ref Sys->FD, from, tox, id: string): int;
		last:		fn(fd: ref Sys->FD, from, tox, id: string, d: int): int;
		vcardget:	fn(fd: ref Sys->FD, from, typex: string): int;
		vcardset:	fn(fd: ref Sys->FD, from: string, fd: ref Sys->FD): int;
		presence:	fn(fd: ref Sys->FD, stat, show, from, tox: string): int;
		presencetype:	fn(fd: ref Sys->FD, from, tox, typex: string): int;
		roster:		fn(fd: ref Sys->FD): int;
		message:	fn(fd: ref Sys->FD, from, tox, msg, typex: string): int;
		addbuddy:	fn(fd: ref Sys->FD, jid, na, typex: string): int;
		delbuddy:	fn(fd: ref Sys->FD, jid: string): int;

		xml:		fn(fd: ref Sys->FD): int;
		xmlns:		fn(fd: ref Sys->FD, who, t, id: string): int;
	};
	
	Rostern: adt{
		n: cyclic ref Rostern;
		p: cyclic ref Rostern;
		name: string;
		jid: string;
		stat: string;
		show: string;
		subsc: string;
		group: string;
		
		# fn
		del:	fn(r: self ref Rostern): ref Rostern;
		add:	fn(r: self ref Rostern, n: ref Rostern): ref Rostern;
		status:	fn(r: self ref Rostern, name, jid, status, show: string): ref Rostern;
		namer:	fn(r: self ref Rostern, jid, name: string): string;
		search:	fn(r: self ref Rostern, name, jid: string): ref Rostern;
		delname:fn(r: self ref Rostern, name, jid: string): ref Rostern;
		print:	fn(r: self ref Rostern, w: string, tmstmp: string);
	};

	jabberc: adt{
		stat: string;
		show: string;
		name: string;
		reso: string;
		serv: string;
		jid: string;

		tls: int;
		debug: int;
		reg: int;
		last: int;
		rost: ref Rostern;
	};
	
	pushssl: fn(oridfd: ref Sys->FD, addr: string): (string, ref Sys->FD);
	loadmods: fn();

	ready: int;
	pres_chan: chan of (string, string, string);
	msg_chan: chan of (string, string);
	vcard_chan: chan of string;
	killall: fn();

};
