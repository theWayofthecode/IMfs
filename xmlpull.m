# 
# Copy me if you can.
# by 20h
#  

Xmlpull: module
{
	PATH: con "/dis/xmlpull.dis";

	START_DOCUMENT, START_TAG, START_END_TAG, END_TAG,
	END_TAG_S, END_TAG_N, TEXT, TEXT_C, ATTR, END_DOCUMENT: con iota;

	xmlpull: adt{
		fd: ref Sys->FD;
		
		ev: int;
		nev: int;
		lm: string;
		na: string;
		va: string;
		la: array of int;
		lv: array of int;
		ln: array of int;
	
		open:	fn(fd: ref Sys->FD, omode: int): ref xmlpull;
		next:	fn(x: self ref xmlpull): ref xmlpull;
		write:	fn(x: self ref xmlpull): ref xmlpull;
	};

	init:	fn(): string;
};
