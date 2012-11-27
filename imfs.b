implement Imfs;
include "sys.m";
include "draw.m";
include "styx.m";
include "styxservers.m";
include "string.m";
include "imfs.m";
include "jacc.m";
include "dial.m";
include "factotum.m";

styxservers: Styxservers;
str: String;
sys: Sys;
styx: Styx;
jacc: JACC;
auth: Factotum;
Styxserver, Navigator: import styxservers;
nametree: Nametree;
Tree: import nametree;
Rmsg: import styx;
Tmsg: import styx;
Fid: import styxservers;
#Jacc
jabberc: import jacc;
Jacc: import jacc;
Rostern: import jacc;

srv: ref Styxserver;
tree: ref Tree;
treeop: chan of ref Styxservers->Navop;
Qroot, Qctl, Qstat, Qgroup: con big iota;  # paths
contacts: list of ref Contact;
groups: list of ref Group;
file_num, group_num: big;
me: ref jabberc;
sock: ref Sys->FD;
debug: int;



init(nil: ref Draw->Context, args: list of string)
{
	tchan: chan of ref Tmsg;
	init_imfs();
	(tchan, srv) = Styxserver.new(sys->fildes(0), Navigator.new(treeop), Qroot);
	while ((gm := <-tchan) != nil) {
		pick m := gm {
			Read => 
				read_styx(m);
			Write => 
				write_styx(m);
			Create => 
				create_styx(m);	
			Remove => 
				remove_styx(m);
			* =>	
			srv.default(m);
		}
	}
}

init_imfs()
{
	sys = load Sys Sys->PATH;
	styx = load Styx Styx->PATH;
	str = load String String->PATH;
	auth = load Factotum Factotum->PATH;
	auth->init();
	styx->init();
	styxservers = load Styxservers Styxservers->PATH;
	styxservers->init(styx);
	nametree = load Nametree Nametree->PATH;
	nametree->init();
	debug = 0;
	sys->pctl(Sys->NEWPGRP, nil);
	(tree, treeop) = nametree->start();
	tree.create(Qroot, dir(".", 8r777|Sys->DMDIR, Qroot));
	tree.create(Qroot, dir("ctl", 8r777, Qctl));
	file_num = big 3;
	group_num = big 100000;
}

write_styx(m: ref Tmsg.Write)
{
	(f, err) := srv.canwrite(m);
	temp_con := find_contact(contacts, f.path, nil);
	if (f == nil){
		error_handler(m, err);
		return;
	}
	if (f.path == Qctl){
		i := main_ctl(string m.data);
		if (i){
			srv.reply(ref Rmsg.Write(m.tag, len m.data));
		} else {
			error_handler(m, "bad ctl command");
		}
	} else if (f.path == Qstat) {
		i := main_status(string m.data);
		if (i){
			srv.reply(ref Rmsg.Write(m.tag, len m.data));
		} else {
			error_handler(m, "bad status command");
		}
	} else if (temp_con != nil){
		if (debug == 1 && temp_con.path_stat == f.path){
			sys->print("in write = %bd\n", f.path);
			srv.default(m); #Writing in status files is not supported
		} else if (temp_con.path_conn == f.path){
			conn_handler(temp_con, string m.data);
			srv.reply(ref Rmsg.Write(m.tag, len m.data));
		}
	} else {
		srv.default(m);
	}
}

create_styx(m: ref Tmsg.Create)
{
	(f, mode, nil, err) := srv.cancreate(m); #f is the parent dir
	if (f == nil){
		error_handler(m, err);
		return;
	}
	if (f.path == Qroot && str->prefix("status", m.name)){
		d := change_status(nil, Qstat, m.name);
		if (d.name == nil){
			srv.default(m);
			return;
		} else {
			srv.reply(ref Rmsg.Create(m.tag, d.qid, srv.iounit()));
		}
	} else if (m.perm & Sys->DMDIR){ #check if mkdir
		d: Sys->Dir;
		if (f.path == Qroot){ 
			d = create_group(m.name);
		} else {
			grp := find_group(groups, f.path, nil);
			d = create_contact(m.name, grp);
			er: int;
			if (str->prefix(grp.name, "nogroup")){
				er = Jacc.addbuddy(sock, m.name, m.name, nil);
			} else {
				er = Jacc.addbuddy(sock, m.name, m.name, grp.name);
			}
			Jacc.presencetype(sock, me.jid, m.name, "subscribe");
				
		}
		f.open(mode, d.qid);
		srv.reply(ref Rmsg.Create(m.tag, d.qid, srv.iounit()));
		} else {
		srv.default(m);
	}
}

remove_styx(m: ref Tmsg.Remove)
{
	(f, path, err) := srv.canremove(m);
	if (f == nil)
		error_handler(m, err);
	tmp_con := find_contact(contacts, f.path, nil);
	if (path == Qroot){
		remove_group(find_group(groups, f.path, nil));
		srv.delfid(f);
		srv.reply(ref Rmsg.Remove(m.tag));
	} else if (tmp_con != nil){
		if (f.path == tmp_con.path_conn){
			temp_path := remove_conn(tmp_con);
			srv.delfid(f);
			srv.reply(ref Rmsg.Remove(m.tag));
		} else if (f.path == Qstat) {
			srv.reply(ref Rmsg.Remove(m.tag));
		} else if (f.path == tmp_con.path){
			remove_contact(find_contact(contacts, f.path, nil));
			er := Jacc.delbuddy(sock, tmp_con.name);
			Jacc.presencetype(sock, me.jid, tmp_con.name, "unsubscribe");
			srv.delfid(f);
			srv.reply(ref Rmsg.Remove(m.tag));
		}
	} else {
		srv.default(m);
	}
}

read_styx(m: ref Tmsg.Read)
{

	(f, err) := srv.canread(m);
	if (f == nil){
		error_handler(m, err);
		return;
	}
	tmp_con := find_contact(contacts, f.path, nil);
	if (tmp_con != nil && tmp_con.path_conn == f.path){
		if (tmp_con.pending_msgs == nil){
			tmp_con.pending_reply = m.tag;
		} else {
			srv.reply(ref Rmsg.Read(m.tag, array of byte tmp_con.pending_msgs));
			tmp_con.pending_msgs = nil;
		}
	} else if (tmp_con != nil && tmp_con.path_stat == f.path) {
		Jacc.vcardget(sock, tmp_con.name, "to");
		s :=<- jacc->vcard_chan;
		sys->print("%s\n", s);
		srv.default(m);

	} else {
		srv.default(m);
	}
}
	
		
say(s: string)
{
	sys->print("%s\n", s);
}

init_jacc(user: string)
{
	err: string;
	dial := load Dial Dial->PATH;
	jacc = load JACC JACC->PATH;
	jacc->loadmods();
        me = ref jabberc;
        me.tls = 0;
	me.reg = 0;
	me.debug = 0;
	me.show = "online";
	me.stat = "gg";
	me.reso = "Plan9";
	me.tls++;
	me.reso = "noplan";
	me.serv = "gmail.com";
	me.name = user;
	me.jid = user+"@"+me.serv+"/"+me.reso;
	server := "talk.google.com";
	port := "5223";
	addr := dial->netmkaddr(server, "tcp", port);
	(ok, c) := sys->dial(addr, nil);
	if (ok < 0)
		sys->print("dial error\n");
	(err, sock) = jacc->pushssl(c.dfd, addr);
}

main_ctl(s: string): int
{
	(ls, rs) := str->splitl(s, "!");
	if (str->prefix("login", ls)){
		do {
			(ls, rs) = auth->getuserpasswd("proto=pass service=IMFS");
		} while (ls == nil && rs == nil);
		init_jacc(ls);
		spawn Jacc.recv(sock, me, rs);
		spawn recv_handler();
		create_group("nogroup");	
		contact_list();
		tree.create(Qroot, dir("status_online", 8r777, Qstat));
		return 1;
	} else if (str->prefix("logout", ls)){
		logout();
		return 1;
	}
	return 0;
}


main_status(s: string): int
{
	sys->print("In the future you can send your vcard by writing this file\n");
	return 1;
}


conn_handler(tmp_c: ref Contact, msg: string): int
{
	return(Jacc.message(sock, me.jid, tmp_c.name, msg, "chat"));
}


contact_list()
{
	while (jacc->ready != 1);
	tmp_rost := me.rost.n;
	while (tmp_rost != nil){
		s := tmp_rost.jid; 
		s = s[ : len s - 2];
		if (tmp_rost.group == nil){
			create_contact(s, find_group(groups, big -1, "nogroup"));
			sys->print("%d\n", len tmp_rost.jid);
		} else {
			grp := tmp_rost.group;
			grp = grp[ : len grp - 2]; #discarting bad chars
			grpref := find_group(groups, big -1, grp);
			if (grpref == nil){
				create_group(grp);
				grpref = find_group(groups, big -1, grp);
			}
			create_contact(s, grpref);
		}
		tmp_rost = tmp_rost.n;
	}
}

show_contacts()
{
		tmp_list := contacts;
		say("--CONTACTS--");
	do {
		tmp_con := hd tmp_list;
		tmp_list = tl tmp_list;
		contact_print(tmp_con);
		say("---------------");
	}while (tmp_list != nil);
}


logout()
{
	temp_con: ref Contact;
	temp_grp: ref Group;
	while (contacts != nil){
		temp_con = hd contacts;
		contacts = tl contacts;
		remove_contact(temp_con);
	}
	while (groups != nil){
		temp_grp = hd groups;
		groups = tl groups;
		remove_group(temp_grp);
	}
	tree.remove(Qstat);
	sys->fprint(sock, "<presence from=\"%s\" type=\"unavailable\"/>", me.jid);
	sys->fprint(sock, "</stream:stream>");
	jacc->killall();
}

recv_handler()
{
	for(;;){
		alt {
			(from, show, status) :=<- jacc->pres_chan => {
				(name, nil) := str->splitl(from, "/");
				tmp_con := find_contact(contacts, big -10, name);
				if (debug == 1 && tmp_con == nil){
					say("recv_handler: tmp_con nil");
					continue;
				}
				d: Sys->Dir;
				if (status == nil){
					d = change_status(name, tmp_con.path_stat, "status_" + show);
				} else {
					d = change_status(name, tmp_con.path_stat, "status_" + show + "_" + status);
				}
				if (debug == 1 && d.name == nil)
					say("recv_handler: d.name nil");
			} (from, msg) :=<- jacc->msg_chan => {
				(name, nil) := str->splitl(from, "/");
				tmp_con := find_contact(contacts, big -10, name);
				if (debug == 1 && tmp_con == nil){
					say("recv_handler: tmp_con nil");
					continue;
				}
				if (tmp_con.pending_reply >= 0){
					srv.reply(ref Rmsg.Read(tmp_con.pending_reply, array of byte msg));
					tmp_con.pending_reply = -1;
				} else {
					if (tmp_con.pending_msgs == nil){
						tmp_con.pending_msgs = msg + "\n";
					} else {
						tmp_con.pending_msgs += msg + "\n";
					}
				}
			}
		}
	}
}

contact_print(c: ref Contact)
{
	sys->print("name = %s\n", c.name);
	sys->print("path = %bd\n", c.path);
	sys->print("path_stat = %bd\n", c.path_stat);
}


	

change_status(name:string , path: big, stat: string): Sys->Dir
{
	show, status: string;
	(nil, show) = str->splitl(stat, "_");
	if (show == nil){
		return Sys->zerodir;
	}
	show = show[1 : ]; #discard _
	(show, status) = str->splitl(show, "_");
	if (status != nil)
		status = status[1 : ];
	if (path == Qstat){
		me.show = show;
		me.stat = status;
		Jacc.presence(sock, status, show, nil, nil);
	} else {
		me.rost.status(nil, name, status, show);
	}	
	d := dir(stat, 8r777, path);
	tree.wstat(path, d);
	return d;
}

create_contact(name: string, grp: ref Group): Sys->Dir
{
	tmp_con: Contact;
	tmp_con.name = name;
	tmp_con.path = file_num;
	tmp_con.path_stat = file_num + big 1;
	tmp_con.path_conn = file_num + big 2;;
	tmp_con.grp = grp;
	tmp_con.pending_msgs = nil;
	tmp_con.pending_reply = -1;
	file_num = file_num + big 3;
	contacts = ref tmp_con :: contacts;
	d := dir(tmp_con.name, 8r777|sys->DMDIR, tmp_con.path);
	tree.create(grp.path, d);
	tree.create(tmp_con.path, dir("status_offline", 8r777, tmp_con.path_stat));
	tree.create(tmp_con.path, dir("conn", 8r777, tmp_con.path_conn));
	return (d);
}

create_group(name: string): Sys->Dir
{
	temp_group: Group;
	temp_group.name = name;
	temp_group.path = group_num;
	group_num = group_num + big 1;
	groups = ref temp_group :: groups;
	d := dir(temp_group.name, 8r777|sys->DMDIR, temp_group.path);
	tree.create(Qroot, d);
	return (d);
}

remove_group(grp: ref Group)
{
	group_list: list of ref Group;
	temp_grp: ref Group;
	while (groups != nil){
		temp_grp = hd groups;
		if (temp_grp != grp)
			group_list = temp_grp :: group_list;
		if (groups != nil)
			groups = tl groups;
	}
	tree.remove(grp.path);
	groups = group_list;
}

remove_contact(contact: ref Contact)
{
	temp_list: list of ref Contact;
	temp_con: ref Contact;
	while (contacts != nil){
		temp_con = hd contacts;
		if (temp_con != contact)
			temp_list = temp_con :: temp_list;
		if (contacts != nil)
			contacts = tl contacts;
	}
	tree.remove(contact.path_stat);
	if (contact.path_conn != big -1)
		tree.remove(contact.path_conn);
	tree.remove(contact.path);
	contacts = temp_list;
}

remove_conn(contact: ref Contact): big
{
	path: big;
	path = contact.path_conn;
	tree.remove(contact.path_conn);
	contact.path_conn = big -1;
	return (path);
}


Contact.has_path(c: self ref Contact, path: big): int
{
	if (c.path == path || c.path_stat == path || c.path_conn == path)
		return 1;
	return 0;
}

find_contact(l: list of ref Contact, path: big, name: string): ref Contact
{	
	if (l == nil)
		return nil;
	temp := hd l;
	if (temp.has_path(path) || (str->prefix(name, temp.name) && len name == len temp.name))
		return temp;
	return(find_contact(tl l, path, name));
}

find_group(l: list of ref Group, path: big, name: string): ref Group #find by path OR name
{	
	if (l == nil)
		return nil;
	temp := hd l;
	if (temp.path == path || (str->prefix(name, temp.name) && len name == len temp.name))
		return temp;
	return(find_group(tl l, path, name));
}


dir(name: string, perm: int, qid: big): Sys->Dir
{
	d := sys->zerodir;
	d.name = name;
	d.uid = "me";
	d.gid = "me";
	d.qid.path = qid;
	if (perm & Sys->DMDIR)
		d.qid.qtype = Sys->QTDIR;
	else
		d.qid.qtype = Sys->QTFILE;
	d.mode = perm;
	return d;
}

error_handler(m: ref Tmsg, err: string)
{
	sys->print("ERROR: %s\n", err);
	srv.reply(ref Rmsg.Error(m.tag, err));
	exit;
}
