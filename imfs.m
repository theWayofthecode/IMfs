Imfs: module
{
	init: fn(nil: ref Draw->Context, argv: list of string);
	Contact: adt{
		name: string;
		path: big;
		path_stat: big;
		path_conn: big;
		grp: ref Group;	
		pending_msgs: string;
		pending_reply: int;

		has_path: fn(me: self ref Contact, path: big): int;
	};

	Group: adt{
		name: string;
		path: big;
	};
};
